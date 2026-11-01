#!/usr/bin/env python3
"""Version-independent patcher.

`patch.py` is the fast path for a known build: it asserts exact original bytes at
hard-coded RVAs. This script instead re-derives everything from a given APK pair,
so a new Play release can be patched without hand-editing addresses:

  1. pull libil2cpp.so + global-metadata.dat out of the APKs
  2. run Il2CppDumper to get a function map
  3. resolve each target method *by name*
  4. stub the simple ones (overwrite the method entry)
  5. scan AdsSelfManager::ShowAds for the two in-body edits
  6. write the patched library

  python retarget.py --base local/game/base.apk --split local/game/split_config.arm64_v8a.apk \
                     --variant instant --out local/build/instant
"""
import argparse
import re
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from patch import NOP, RET, MOV_W0_0, MOV_W0_1, load_segments, rva_to_offset  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DUMPER = ROOT / "Tools" / "dumpers" / "Il2CppDumper" / "Il2CppDumper.exe"
SO_ENTRY = "lib/arm64-v8a/libil2cpp.so"
META_ENTRY = "assets/bin/Data/Managed/Metadata/global-metadata.dat"

# method entry stubs: (class, method, bytes, note, variants)
STUBS = [
    ("AdsSelfManager", "IsVipNoAdMonthlyProActive", MOV_W0_1 + RET, "VIP no-ad -> true", {"instant"}),
    ("VoodooSauce", "ShowBanner", RET, "banner -> no-op", {"safe", "instant"}),
    ("AppOpenRewardedInterstitialWrapper", "TryShowing", RET, "app-open ad -> no-op", {"safe", "instant"}),
    ("AudioAdsManager", "IsEnabled", MOV_W0_0 + RET, "audio ads -> false", {"safe", "instant"}),
    ("AdInterstitialConfig", "CanShowAdInterstitial", MOV_W0_0 + RET, "interstitial gate -> false", {"safe", "instant"}),
    ("Application", "get_installMode", MOV_W0_1 + RET, "install mode -> Store", {"safe", "instant"}),
]

IN_BODY_CLASS, IN_BODY_METHOD = "AdsSelfManager", "ShowAds"
STAT_INT = ("CloudStatsData", "AddStatInt")
CMP_W8_1 = 0x7100051F          # cmp w8, #1
B_COND_NE = 0x54000001         # b.ne (imm19 filled in per site)


def parse_functions(dump_cs: Path):
    """RVA -> 'Class::Method' in file order (mirrors analysis/xref.py)."""
    rva_re = re.compile(r"^\s*// RVA: (0x[0-9A-Fa-f]+) Offset: (0x[0-9A-Fa-f]+)")
    cls = ""
    pending = None
    out = []
    with open(dump_cs, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith(("public ", "internal ", "private ", "protected ")) and (
                    " class " in line or " struct " in line):
                m = re.search(r"\b(?:class|struct)\s+([A-Za-z0-9_.<>`]+)", line)
                if m:
                    cls = m.group(1)
                continue
            m = rva_re.match(line)
            if m:
                pending = int(m.group(1), 16)
                continue
            if pending is not None and line[:1] in ("\t", " "):
                sig = line.strip()
                if sig.startswith("["):
                    continue
                nm = re.match(r".*?([A-Za-z0-9_~.<>]+)\s*\(", sig)
                if nm:
                    out.append((pending, f"{cls}::{nm.group(1)}"))
                pending = None
    out.sort()
    return out


def exact(funcs, cls, method):
    hits = [f for f in funcs if f[1] == f"{cls}::{method}"]
    if len(hits) > 1:
        raise SystemExit(f"ambiguous: {cls}::{method} has {len(hits)} definitions at "
                         + ", ".join(hex(r) for r, _ in hits))
    return hits[0][0] if hits else None


def extract(apk: Path, entry: str, dest: Path):
    with zipfile.ZipFile(apk) as z:
        if entry not in z.namelist():
            raise SystemExit(f"{entry} not in {apk}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(z.read(entry))
    return dest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--split", required=True)
    ap.add_argument("--variant", default="instant", choices=["safe", "instant"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--dumper", default=str(DEFAULT_DUMPER))
    ap.add_argument("--dump-dir", default=None, help="reuse an existing Il2CppDumper output")
    ap.add_argument("--work", default=None, help="staging dir (default local/work/retarget)")
    a = ap.parse_args()

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    work = Path(a.work) if a.work else ROOT / "local" / "work" / "retarget"
    work.mkdir(parents=True, exist_ok=True)
    print(f"work dir: {work}")

    so_src = extract(Path(a.split), SO_ENTRY, work / "libil2cpp.so")
    meta = extract(Path(a.base), META_ENTRY, work / "global-metadata.dat")

    dump_dir = Path(a.dump_dir) if a.dump_dir else work / "dump"
    dump_cs = dump_dir / "dump.cs"
    if not dump_cs.exists():
        dumper = Path(a.dumper)
        if not dumper.exists():
            raise SystemExit(f"Il2CppDumper not found at {dumper} (see README: external dependency)")
        dump_dir.mkdir(parents=True, exist_ok=True)
        print(f"running {dumper.name} ...")
        subprocess.run([str(dumper), str(so_src), str(meta), str(dump_dir)],
                       stdin=subprocess.DEVNULL, capture_output=True)
        if not dump_cs.exists():
            raise SystemExit("Il2CppDumper produced no dump.cs (unsupported metadata version?)")

    funcs = parse_functions(dump_cs)
    print(f"{len(funcs)} functions in map")

    data = bytearray(so_src.read_bytes())
    segs = load_segments(data)
    applied = []

    for cls, meth, blob, note, variants in STUBS:
        if a.variant not in variants:
            continue
        rva = exact(funcs, cls, meth)
        if rva is None:
            print(f"  ! {cls}::{meth} not found — skipped")
            continue
        off = rva_to_offset(segs, rva)
        struct.pack_into("<%dB" % len(blob), data, off, *blob)
        applied.append(f"{cls}::{meth} @0x{rva:X} ({note})")
        print(f"  stub    {cls}::{meth:<32} RVA 0x{rva:X}  {note}")

    if a.variant == "instant":
        show_rva = exact(funcs, IN_BODY_CLASS, IN_BODY_METHOD)
        stat_rva = exact(funcs, *STAT_INT)
        if show_rva is None:
            raise SystemExit("AdsSelfManager::ShowAds not found")
        start = rva_to_offset(segs, show_rva)
        # scan the first ~120 instructions of ShowAds
        patched_branch = patched_call = False
        for i in range(120):
            o = start + i * 4
            w = struct.unpack_from("<I", data, o)[0]
            if w == CMP_W8_1:
                nxt = struct.unpack_from("<I", data, o + 4)[0]
                if (nxt & 0xFF00000F) == B_COND_NE:
                    struct.pack_into("<I", data, o + 4, struct.unpack_from("<I", NOP)[0])
                    patched_branch = True
                    print(f"  branch  ShowAds+0x{i*4:X} cmp w8,#1 ; b.ne -> nop")
            if stat_rva is not None:
                op = w >> 26
                if op == 0b100101:                                  # BL
                    imm = w & 0x03FFFFFF
                    if imm & 0x02000000:
                        imm -= 0x04000000
                    if show_rva + i * 4 + imm * 4 == stat_rva:
                        struct.pack_into("<I", data, o, struct.unpack_from("<I", NOP)[0])
                        patched_call = True
                        print(f"  call    ShowAds+0x{i*4:X} bl AddStatInt -> nop")
        if not patched_branch:
            print("  ! could not locate the adType branch in ShowAds")
        if not patched_call:
            print("  ! could not locate the AddStatInt call in ShowAds")
        if patched_branch:
            applied.append("ShowAds branch -> nop")
        if patched_call:
            applied.append("ShowAds AddStatInt -> nop")

    dst = out / "libil2cpp.patched.so"
    dst.write_bytes(data)
    print(f"\n{len(applied)} patches -> {dst}")
    if len(applied) < 6:
        print("WARNING: fewer patches than expected — check the dump for renamed methods")


if __name__ == "__main__":
    main()

