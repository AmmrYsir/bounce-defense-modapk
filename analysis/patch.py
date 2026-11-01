#!/usr/bin/env python3
"""Apply ad-removal patches to libil2cpp.so (Unity 6000.3.10f1 / metadata v39, game 1.19.8).

Two variants:

  safe  (default) - remove every *forced* ad surface, leave opt-in rewarded ads working.
                    This mirrors the game's own "remove forced ads" product and keeps the
                    original asynchronous ad callback ordering, so no gameplay state machine
                    is re-entered synchronously.

  aggressive      - additionally force every ad request onto the game's built-in VIP
                    "instant reward" path (no ad at all, reward granted immediately).
                    WARNING: that path also runs a cloud-stats update keyed '3' which throws
                    KeyNotFoundException on accounts without the VIP stat entry, aborting the
                    caller and locking the wave/reward UI.

Every patch is expressed as RVA + exact original bytes, so a mismatch aborts the build.
"""
import argparse
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SO_IN = ROOT / "splits" / "arm64" / "lib" / "arm64-v8a" / "libil2cpp.so"

NOP = bytes.fromhex("1f2003d5")
RET = bytes.fromhex("c0035fd6")
MOV_W0_1 = bytes.fromhex("20008052")
MOV_W0_0 = bytes.fromhex("00008052")

# (key, rva, original, replacement, label, variants)
PATCHES = [
    ("P1", 0x176A6B0, bytes.fromhex("01030054"), NOP,
     "AdsSelfManager::ShowAds - drop ad-type branch", {"instant"}),
    ("P2", 0x176A7C8, bytes.fromhex("fe57bea9f44f01a9"), MOV_W0_1 + RET,
     "AdsSelfManager::IsVipNoAdMonthlyProActive -> true", {"instant"}),
    ("P7", 0x176A6F8, bytes.fromhex("de320494"), NOP,
     "AdsSelfManager::ShowAds - skip CloudStatsData::AddStatInt(3,..) that throws KeyNotFound", {"instant"}),
    ("P3", 0x3003300, bytes.fromhex("fe57bea9"), RET,
     "VoodooSauce::ShowBanner -> no-op", {"safe", "instant"}),
    ("P4", 0x30D3830, bytes.fromhex("ff4301d1"), RET,
     "AppOpenRewardedInterstitialWrapper::TryShowing -> no-op", {"safe", "instant"}),
    ("P8", 0x2BD65B8, bytes.fromhex("fe4fbfa9735a00b0"), MOV_W0_1 + RET,
     "Application::get_installMode -> Store (runs when sideloaded, not only Play install)",
     {"safe", "instant"}),
    ("P5", 0x3042628, bytes.fromhex("00a04039c0035fd6"), MOV_W0_0 + RET,
     "AudioAdsManager::IsEnabled -> false", {"safe", "instant"}),
    ("P6", 0x176B55C, bytes.fromhex("fe57bea9f44f01a9"), MOV_W0_0 + RET,
     "AdInterstitialConfig::CanShowAdInterstitial -> false", {"safe", "instant"}),
]


def load_segments(d):
    phoff = struct.unpack_from("<Q", d, 0x20)[0]
    phentsize = struct.unpack_from("<H", d, 0x36)[0]
    phnum = struct.unpack_from("<H", d, 0x38)[0]
    segs = []
    for i in range(phnum):
        p_type, flags, off, vaddr, paddr, filesz = struct.unpack_from("<IIQQQQ", d, phoff + i * phentsize)
        if p_type == 1:  # PT_LOAD
            segs.append((vaddr, filesz, off))
    return segs


def rva_to_offset(segs, rva):
    for vaddr, filesz, off in segs:
        if vaddr <= rva < vaddr + filesz:
            return off + (rva - vaddr)
    raise ValueError(f"RVA 0x{rva:X} not mapped by any PT_LOAD")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", default="safe", choices=["safe", "instant"])
    ap.add_argument("--src", default=str(SO_IN))
    ap.add_argument("--dst", default=None)
    a = ap.parse_args()

    dst = Path(a.dst) if a.dst else ROOT / "build" / a.variant / "libil2cpp.patched.so"
    data = bytearray(Path(a.src).read_bytes())
    original = bytes(data)
    segs = load_segments(data)

    applied = 0
    for key, rva, orig, new, label, variants in PATCHES:
        if a.variant not in variants:
            print(f"  skip    {key}  {label}")
            continue
        off = rva_to_offset(segs, rva)
        cur = bytes(data[off:off + len(orig)])
        if cur != orig:
            raise SystemExit(f"REFUSING TO PATCH: {label}\n  RVA 0x{rva:X} (file 0x{off:X})"
                             f" expected {orig.hex()} found {cur.hex()}")
        data[off:off + len(new)] = new
        applied += 1
        print(f"  patched {key}  RVA 0x{rva:X} (file 0x{off:X})  {new.hex():<20} {label}")

    assert len(data) == len(original), "patch changed file size"
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)
    print(f"\nvariant '{a.variant}': {applied} patches -> {dst} ({len(data)} bytes)")


if __name__ == "__main__":
    main()

