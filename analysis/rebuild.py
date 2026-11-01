#!/usr/bin/env python3
"""Rebuild the install set with a patched libil2cpp.so (per variant)."""
import argparse
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE_SRC = ROOT / "splits" / "base.apk"
SPLIT_SRC = ROOT / "splits" / "split_config.arm64_v8a.apk"
LIB_ENTRY = "lib/arm64-v8a/libil2cpp.so"


def strip_signature(infos):
    return [i for i in infos
            if not (i.filename.startswith("META-INF/")
                    and i.filename.upper().endswith((".SF", ".RSA", ".DSA", ".EC", ".MF")))]


def rewrite(src, dst, replace=None):
    replace = replace or {}
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in strip_signature(zin.infolist()):
            data = zin.read(info.filename)
            if info.filename in replace:
                data = replace[info.filename]
            out = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            out.compress_type = info.compress_type
            out.external_attr = info.external_attr
            out.internal_attr = info.internal_attr
            out.create_system = info.create_system
            zout.writestr(out, data)
    print(f"  {Path(src).name} -> {Path(dst).name} ({Path(dst).stat().st_size:,} bytes)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", default="safe", choices=["safe", "instant"])
    a = ap.parse_args()

    build = ROOT / "build" / a.variant
    patched_so = build / "libil2cpp.patched.so"
    if not patched_so.exists():
        raise SystemExit(f"missing {patched_so}; run patch.py --variant {a.variant} first")

    print(f"rebuilding install set ({a.variant}):")
    dex_patch = ROOT / "build" / "dex" / "classes2.patched.dex"
    base_replace = {}
    if dex_patch.exists():
        base_replace["classes2.dex"] = dex_patch.read_bytes()
        print(f"  applying PairIP dex patch ({dex_patch.name})")
    rewrite(BASE_SRC, build / "base.unsigned.apk", replace=base_replace)
    rewrite(SPLIT_SRC, build / "split_config.arm64_v8a.unsigned.apk",
            replace={LIB_ENTRY: patched_so.read_bytes()})

    with zipfile.ZipFile(build / "split_config.arm64_v8a.unsigned.apk") as z:
        so = z.read(LIB_ENTRY)
        print(f"  verify: patched libil2cpp.so {len(so):,} bytes inside split")


if __name__ == "__main__":
    main()

