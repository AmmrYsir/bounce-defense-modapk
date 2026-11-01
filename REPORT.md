# Bounce Defense — ad removal: analysis, patches, and device results

Target: `com.minigamelab.bouncedefense`, **1.19.8** (versionCode 26092810), Unity **6000.3.10f1**, IL2CPP,
`arm64-v8a` only, split install (base + `split_config.arm64_v8a`).
(The merged `Bounce Defense.apk` in the workspace root is the older 1.19.7; the `splits/` folder — which the
build uses — is 1.19.8.)

---

## 1. What the ad stack is

Voodoo title, so the game never talks to a network directly:

```
23 game UI call sites
  └─ AdsSelfManager.ShowAds(AdType, Action<bool>, placement)      game code (Assembly-CSharp)
       └─ StudioHelper.ShowAds ──event──> AdsSystem.OnRequestAd    game <-> SDK bridge
            └─ VoodooSauce.Show{Interstitial,RewardedVideo,Banner} Voodoo Sauce
                 └─ Voodoo.Sauce.Internal.Ads.AdsManager           mediation (MAX)
                      └─ MaxSdk → Pangle / ADN / ironSource / … (15 networks)
```

Mediation is **AppLovin MAX**. Cloud save is **Nakama** + Unity Services auth — separate from ads.

`VoodooPremium.IsPremium` / `VoodooSauce.IsPremium` have **zero call sites**, so faking the "No Ads" IAP
does nothing. The game's own forced-ad product is `bd_no_ads` ("remove forced ads, reward ads remain").

## 2. How the addresses were found

Metadata is v39, which stock Il2CppDumper rejects; the
[`lxraa` fork v6.7.46](https://github.com/lxraa/Il2CppDumper/releases/tag/v6.7.46-lxraa.1) supports v32–v39,
so `analysis/il2cpp/dump.cs` (24 MB, with RVAs) was produced offline. `analysis/xref.py` builds a function
map from it and scans `.text`/`il2cpp` for `BL`, which produced the call graph above (e.g. exactly 23 callers
of `AdsSelfManager::ShowAds`; `AdsSystem::ShowReward/ShowBanner` have 0 → dead code).

## 3. Patches

Applied by `analysis/patch.py`; each entry is RVA + exact original bytes, so a mismatch aborts the build.
All are 4-byte AArch64 edits that keep the file size identical.

| # | RVA | Method | Change | Variant |
|---|-----|--------|--------|---------|
| P1 | `0x176A6B0` | `AdsSelfManager::ShowAds` | `b.ne` → `nop` | instant |
| P2 | `0x176A7C8` | `AdsSelfManager::IsVipNoAdMonthlyProActive` | `mov w0,#1; ret` | instant |
| P7 | `0x176A6F8` | `AdsSelfManager::ShowAds` | `bl CloudStatsData::AddStatInt` → `nop` | instant |
| P3 | `0x3003300` | `VoodooSauce::ShowBanner` | `ret` | both |
| P4 | `0x30D3830` | `AppOpenRewardedInterstitialWrapper::TryShowing` | `ret` | both |
| P5 | `0x3042628` | `AudioAdsManager::IsEnabled` | `mov w0,#0; ret` | both |
| P6 | `0x176B55C` | `AdInterstitialConfig::CanShowAdInterstitial` | `mov w0,#0; ret` | both |

### Variants

- **`instant`** (P1,P2,P7,P3–P6) — every ad request lands on the game's own VIP "instant reward" path:
  reward granted immediately, nothing reaches `StudioHelper`/`VoodooSauce`/MAX.
- **`safe`** (P3–P6) — forced ads (interstitial/app-open/banner/audio) removed, opt-in rewarded ads still
  play normally. This is the game's own `bd_no_ads` semantics and carries no behaviour risk.

### Why P7 exists (important)

`ShowAds`'s VIP path calls `CloudStatsData::AddStatInt(stats, 3, 1, 1.0f)` **after** invoking the success
callback. On an account whose stats dictionary has no key `3`, that call throws
`KeyNotFoundException` — observed on device as

```
DOTWEEN ► An error inside a tween callback was taken care of
(System.Collections.Generic.KeyNotFoundException ...) ► The given key '3' was not present in the dictionary.
```

DOTween swallows it, so the caller's remaining flow (enable FIGHT, award coins/gems) never runs and the
level locks up — exactly the "coins not collected, can't continue" symptom. P7 nops that single `bl`, so the
VIP path grants the reward and returns cleanly.

## 4. Device results (SM-A326B, Android 13, arm64)

Installed with `adb install-multiple -i com.android.vending` — **the game exits itself
(`System.exit(0)`) at Voodoo bootstrap if `installerPackageName` is not the Play Store**, which is why a
plain `adb install` gives a 3-second black screen.

- Stock build, rewarded chest button → `io.adn.sdk.internal.ui.fullscreen.FullscreenAdActivity` opens, a
  real video ad plays (captured in `shots/stock-05-rv.png`). Baseline confirmed.
- Patched `libil2cpp.so` verified byte-for-byte **on the device** by pulling the installed split.
- Aggressive build without P7 → reproduced the `KeyNotFound '3'` loop, FIGHT non-interactable.
- `safe` and `instant` (with P7) both boot and run; no `KeyNot` errors since.

## 5. Build + install

```
pwsh -File build.ps1 -Variant instant   # or -Variant safe
adb uninstall com.minigamelab.bouncedefense
adb install-multiple -i com.android.vending build\instant\base.apk build\instant\split_config.arm64_v8a.apk
```

Signed with a local key (`build/mod.keystore`, alias `modkey`, store/key pass `modstore`), v2+v3, minSdk 26.
Re-signing means the Play Store build must be uninstalled first, and **Play will try to overwrite the mod**
when it updates the app — disable auto-update or keep the phone offline for that app.

## 6. Running from any installer — PairIP

The game is protected by **PairIP** (`com.pairip.licensecheck`, Google Play's automatic integrity
protection, injected at signing time and living entirely in `classes2.dex`). A sideloaded copy *silently*
calls `System.exit(0)` ~0.3 s after Unity starts — no dialog, no log line:

```
Voodoo.Sauce.Core.CorePackage:Bootstrap()   <- last log
b.bouncedefense: System.exit called, status: 0
```

Installed with `adb install-multiple -i com.android.vending` it runs; installed with no installer, or with
`-i com.android.shell`, it dies. So `Application.installMode` is *not* the gate — PairIP queries the package
installer directly.

`analysis/pairip_patch.py` neutralises it in `classes2.dex`:

| class | method | change |
|---|---|---|
| `LicenseClient$1` | `run` | return-void (error-path runnable that calls `System.exit`) |
| `LicenseActivity` | `exitApp`, `closeApp`, `closeAllTasks` | return-void |
| `LicenseClient` | `handleError`, `startErrorDialogActivity`, `startPaywallActivity`, `scheduleAppShutdown` | return-void |
| `LicenseClient` | `isLocalCheckPassed` | `return true` |

Verified on device: the same APK now runs with **no installer identity at all**.

Two gotchas worth remembering:

* DEX instructions are variable-length. Replacing a 3-unit `invoke` with a 1-unit `return-void` leaves a
  fragment behind and ART rejects the class with `VerifyError` — each patch overwrites exactly the first
  instruction and pads with `nop`, then repairs the Adler32 checksum and SHA-1 signature.
* `const/4 v0, #1` encodes as `0x1012`, not `0x0112` (`0x0112` is `const/4 v1, #0`), which the verifier
  reports as *"register v0 has type Undefined but expected Boolean"*.

## 7. Sharing / installing on another phone

`share/` holds the two APKs to send. The app is a bundle, so **both** are required — a lone base APK fails
with `INSTALL_FAILED_MISSING_SPLIT`. Merging them into one file was attempted (`analysis/merge_apk.py`
injects the native libs and nulls `requiredSplitTypes`) but Android still enforces the split requirement, so
the split pair is the supported route.

* On the phone: SAI / APKPure Installer / APKMirror Installer → select both files.
* With a PC: `adb install-multiple <base> <arm64>`. No `-i` flag needed any more, thanks to the PairIP patch.
* Uninstall the Play Store build first (different key). Turn off Play auto-update or the mod gets replaced.

## 8. Caveats

1. Signature change → uninstall/reinstall; local save is lost (cloud save on Nakama is separate).
2. The ad SDKs are still packaged and still initialise, so MAX may still perform auction/config requests even
   though no ad can appear. Deleting them is a further step (manifest components, adapter dex, mraid/omsdk
   assets) that needs its own test cycle.
3. Analytics/attribution (Adjust, Firebase, GameAnalytics) untouched.
4. `instant` grants rewarded-ad payouts for free (revives, 2× rewards) — that is a gameplay change by design.
5. PairIP can also be updated server-side by Google for newer builds; a rebuild from a future version may
   need the same treatment again.
