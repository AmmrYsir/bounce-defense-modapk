# AGENTS.md

Instructions for AI agents (and humans) working on this repository.

## Mission

Keep a reproducible pipeline that removes ads from **Bounce Defense** (Unity
6000.3 IL2CPP, arm64, split APK) by binary-patching, and keep it working across
game releases. The repository ships **tooling only**.

## Hard rules — do not violate these

1. **Never commit, or add to git, any of:** the game APKs, `splits/`, `build/`,
   `local/`, `Tools/`, signed APKs, keystores. `.gitignore` covers all of them; if
   you add a new artifact directory, ignore it too. Publishing game binaries is
   copyright infringement and the repo is designed around not doing it.
2. **Never weaken a patch assertion.** `patch.py` compares the exact original
   bytes before writing and aborts on mismatch. That is the safety net that makes a
   wrong version fail loudly instead of producing a bricked APK. Keep it.
3. **Do not "clean up" the async contract.** The game's ad callbacks are
   asynchronous; making `ShowAds` return success synchronously has already broken
   the wave/coin flow once. See `REPORT.md` §3 (P7).
4. **Do not remove the ad SDKs / dex entries** as a "simplification". It is
   untested, and MAX is still expected to initialise even though no ad can display.
5. **Do not commit machine-specific absolute paths** into scripts. `build.ps1` has
   a tool-path block at the top; keep changes there and document them in the README.

## Entry points

| File | Role |
|---|---|
| `build.ps1` | orchestrates: patch → PairIP → repack → align → sign |
| `analysis/patch.py` | known-build table: RVA + expected bytes + replacement, per variant |
| `analysis/retarget.py` | version-independent: extract → Il2CppDumper → resolve by name → patch |
| `analysis/pairip_patch.py` | dex surgery for `com.pairip.*` + checksum/SHA-1 repair |
| `analysis/rebuild.py` | writes base/split APKs with patched artifacts |
| `analysis/verify.js` | Frida harness; asserts the ad path is never reached |
| `REPORT.md` | the analysis: architecture, evidence, device results |

Variants: `safe` = forced ads only (P3–P6, P8, D1); `instant` = adds P1, P2, P7.

## Supporting a new game release

1. Get the new `base.apk` + `split_config.arm64_v8a.apk`.
2. `pwsh -File build.ps1 -Variant instant -Base <base> -Split <split>`
   `retarget.py` re-derives every address from the binary; nothing is hard-coded.
3. If `retarget.py` reports a missing method or cannot find the two in-body sites,
   the code was refactored — re-analyse with `analysis/xref.py` against
   `local/work/retarget/dump/dump.cs` and adjust `STUBS` / the scan.
4. Sanity check: on a known version, `retarget.py` output must be **byte-identical**
   to `patch.py` output (`cmp` the two `libil2cpp.patched.so` files).
5. Re-verify on device. PairIP is injected at signing time, so a newer build may ship
   a changed `com.pairip` layout; `pairip_patch.py` prints any method it cannot find.

## Pitfalls already paid for — read before touching anything

- **DEX instructions are variable-length.** Overwriting only the first code unit of a
  2–3 unit instruction leaves a fragment and ART throws `VerifyError`. `pairip_patch.py`
  computes the instruction length and pads the remainder with `nop`.
- **`const/4 v0, #1` is `0x1012`**, not `0x0112` (`0x0112` is `const/4 v1, #0`). Getting
  the nibbles backwards yields *"register v0 has type Undefined but expected Boolean"*.
- **PairIP is the reason a sideloaded build dies silently** (`System.exit(0)` ~0.3 s
  after boot, no log). `Application.installMode` looks like the culprit but is a decoy.
- **`ShowAds` VIP path throws** via `CloudStatsData::AddStatInt(.., 3, ..)`; DOTween
  swallows the exception, so the caller's remaining work silently never runs.
- **`INSTALL_FAILED_MISSING_SPLIT`** is expected if you try to install the base alone;
  the split pair is mandatory. Merging was attempted in `merge_apk.py` and does not
  work — Android enforces `requiredSplitTypes` even after the attribute is nulled.
- **PowerShell mangles hex literals** when passing numbers to Python (`0x100` becomes
  decimal). Pass addresses as quoted strings.

## Verification checklist

Static:

```powershell
python analysis\patch.py --variant instant     # must echo all 7 rows, no mismatch
python analysis\rebuild.py --variant instant
```

Device (non-rooted is fine):

```powershell
adb install-multiple -i com.android.vending build\instant\*.apk   # -i not needed after D1
adb shell am start -n com.minigamelab.bouncedefense/com.google.firebase.MessagingUnityPlayerActivity
adb shell pidof com.minigamelab.bouncedefense                     # must stay alive
adb logcat -d | Select-String 'System.exit'                       # must be empty
adb shell dumpsys activity activities | Select-String 'FullscreenAdActivity'  # must be empty
```

With root + `frida-server`, use `analysis/verify.js` for method-level proof.

## Style

- Python: stdlib only, no new dependencies, 3.12, `pathlib`, explicit failure over
  silent fallback.
- PowerShell: 7+, `$ErrorActionPreference = 'Stop'`, throw on non-zero exit codes.
- Comments explain *why* a patch exists (the failure it prevents), not what the opcode is.
- Any new patch needs: target, RVA or name-resolution strategy, original bytes,
  replacement, and one line in `REPORT.md`'s table.
