# Bounce Defense — ad removal toolkit

A small, documented pipeline that removes ads from the Unity/IL2CPP game
**Bounce Defense** (`com.minigamelab.bouncedefense`) by patching `libil2cpp.so`
and the PairIP-protected dex, then rebuilding and re-signing the split APK pair.

This repository contains **tooling and documentation only**. It ships no game
binaries, no assets, and no patched APKs — you bring your own copy of the game.

> **Status:** verified on 1.19.8 (versionCode 26092810), Unity 6000.3.10f1,
> arm64-v8a, on a Samsung A32 (Android 13). Stock build plays a real ad from the
> rewarded chest button; patched build plays none.

---

## What it actually does

The game is a Voodoo title, so ads never come from the game directly:

```
23 game UI call sites
  └─ AdsSelfManager.ShowAds(AdType, Action<bool>, placement)     game code
       └─ StudioHelper.ShowAds ──event──> AdsSystem.OnRequestAd   game <-> SDK bridge
            └─ VoodooSauce.Show{Interstitial,RewardedVideo,Banner}
                 └─ Voodoo.Sauce.Internal.Ads.AdsManager          mediation (AppLovin MAX)
                      └─ MaxSdk → Pangle / ADN / ironSource / … (15 networks)
```

Rather than deleting SDKs (which breaks the asynchronous callback contract the game
relies on), the patches neutralise the *decisions*:

| # | Target | Change | Variant |
|---|--------|--------|---------|
| P1 | `AdsSelfManager::ShowAds` | `b.ne` after `cmp w8,#1` → `nop` | instant |
| P2 | `AdsSelfManager::IsVipNoAdMonthlyProActive` | `return true` | instant |
| P7 | `AdsSelfManager::ShowAds` | `bl CloudStatsData::AddStatInt` → `nop` | instant |
| P3 | `VoodooSauce::ShowBanner` | `ret` | both |
| P4 | `AppOpenRewardedInterstitialWrapper::TryShowing` | `ret` | both |
| P5 | `AudioAdsManager::IsEnabled` | `return false` | both |
| P6 | `AdInterstitialConfig::CanShowAdInterstitial` | `return false` | both |
| P8 | `Application::get_installMode` | `return Store` | both |
| D1 | PairIP `LicenseClient`, `LicenseActivity` (9 methods) | `return` / `return true` | both |

### Variants

- **`safe`** — removes forced ads (interstitial, app-open, banner, audio) and leaves
  opt-in rewarded ads functioning. This is what the game's own `bd_no_ads` IAP does.
- **`instant`** — additionally routes every ad request through the game's built-in
  VIP "instant reward" path: no ad, reward granted immediately. This changes gameplay
  (free revives, free ×2 rewards).

### Three findings worth knowing

1. **P7 exists because P2 alone locks the game up.** `ShowAds`'s VIP path calls
   `CloudStatsData::AddStatInt(stats, 3, 1, 1.0f)` *after* invoking the reward
   callback. On accounts without stat `3` that throws `KeyNotFoundException`; DOTween
   swallows it, so the caller's remaining work (enable FIGHT, award coins) never runs.
2. **PairIP kills sideloaded installs.** The game silently calls `System.exit(0)`
   ~0.3 s after boot unless `installerPackageName` is the Play Store. `Application.installMode`
   is a decoy — patching it changes nothing; the check reads the package installer directly.
3. **The ad SDKs are not removed.** They are still packaged and still initialise, so MAX
   may still perform auction requests. They simply can never display an ad.

---

## Repository layout

```
analysis/
  patch.py         known-build patch table (byte-asserted, fails safe)
  retarget.py      version-independent: re-derives addresses from a new APK pair
  pairip_patch.py  neutralises PairIP in classes2.dex (+ checksum/signature repair)
  rebuild.py       repacks base + ABI split with the patched artifacts
  merge_apk.py     experimental single-APK merge (see "Limits")
  xref.py          call-graph helper (BL scanner over the dumped function map)
  dexscan.py       minimal DEX parser (finds Java callers of a given API)
  verify.js        Frida harness to confirm the ad path is dead on a device
build.ps1          patch → PairIP → repack → align → sign
share/INSTALL.txt  end-user install instructions (for whoever you send the APKs to)
REPORT.md          full analysis: architecture, evidence, device results
AGENTS.md          invariants and gotchas for AI agents working on this repo
```

Everything large is gitignored and lives locally: `splits/` (game APKs + decoded tree),
`build/` (outputs + keystore), `local/` (staging), `Tools/` (dumper, frida, AssetRipper).

---

## Requirements

| Need | Why |
|---|---|
| Python 3.12 | all scripts are stdlib-only |
| [Il2CppDumper fork](https://github.com/lxraa/Il2CppDumper) (Unity 6, metadata v32–v39) | stock Il2CppDumper rejects metadata v39 |
| .NET 8 runtime | runs the dumper |
| Android SDK build-tools (`zipalign`, `apksigner`) | align + sign |
| JDK (`keytool`) | generate the mod keystore |
| PowerShell 7 | `build.ps1` |
| arm64 Android device, Android 8+ | the game is arm64-only |

Paths to these tools are at the top of `build.ps1` — edit them for your machine.

## Getting the game files

You need the **bundle**, not a single APK: `base.apk` + `split_config.arm64_v8a.apk`.
Extract them from your own installed copy (`adb shell pm path …`, then `adb pull`), or
from an APK mirror you trust. Put them in `splits/` (or anywhere, and pass paths).

## Build

Known version (uses the byte-asserted table):

```powershell
pwsh -File build.ps1 -Variant instant
```

A **new game version** (re-derives every address from the binaries):

```powershell
pwsh -File build.ps1 -Variant instant `
     -Base splits\base.apk -Split splits\split_config.arm64_v8a.apk
```

Output: `build/<variant>/base.apk` + `build/<variant>/split_config.arm64_v8a.apk`.

`merge_apk.py` is validated to produce byte-identical output to `patch.py` on 1.19.8 —
if you change a patch, run both and diff.

## Install

```powershell
adb uninstall com.minigamelab.bouncedefense
adb install-multiple build\instant\base.apk build\instant\split_config.arm64_v8a.apk
```

The split pair is mandatory — a lone base APK fails with `INSTALL_FAILED_MISSING_SPLIT`.
On-device, use a split installer (SAI, APKPure Installer). See `share/INSTALL.txt`.

## Verify

Static: `patch.py` refuses to write unless the original bytes match, and `rebuild.py`
reads the patched library back out of the signed APK.

Dynamic (needs a rooted device or a Frida gadget):

```
frida -U -f com.minigamelab.bouncedefense -l analysis/verify.js --no-pause
```

Expect `ShowAds` calls with `adType=REWARDED`, `IsVipNoAdMonthlyProActive` → `1`,
`CanShowAdInterstitial` → `0`, and **no** calls into `StudioHelper.ShowAds` /
`VoodooSauce.Show*`. On a non-rooted phone, watch for ad activities instead:
`dumpsys activity activities | grep -i ad` should never show
`io.adn.sdk.internal.ui.fullscreen.FullscreenAdActivity`.

---

## Limits

- **Version-pinned.** Play's copy can never be patched in place (signature), so the mod
  is a parallel install that must be rebuilt per release. Rebuilding is scripted
  (~10–15 min); the game has no forced-update gate, so an older build keeps working.
- **Play auto-update must be off**, or the mod is silently replaced.
- **Single-APK merge does not work**: Android enforces `requiredSplitTypes` even after
  the attribute is nulled in the binary manifest.
- The app is re-signed with a local test key, so uninstalling the store build is
  required and local saves are lost (cloud save is Nakama, separate).

---

## Legal

This is a reverse-engineering study of software you own, published as tooling so the
technique can be inspected and reused. **Do not redistribute the game, its assets, or
patched APKs** — that is copyright infringement. `instant` also bypasses the game's
monetisation, and the PairIP patch circumvents a technical protection measure, which in
some jurisdictions (e.g. DMCA §1201, EUCD Art. 6) is separately actionable regardless of
copyright ownership. Nothing here is affiliated with or endorsed by MiniGameLab, Voodoo,
Google, or AppLovin. Provided as-is, no warranty; you are responsible for how you use it.

*Educational / personal-modding use only, on copies you are licensed to modify.*
