#!/usr/bin/env python3
"""Merge the ABI split into the base APK so the mod is a single installable file.

The split only carries lib/arm64-v8a/*.so, and the base declares
android:requiredSplitTypes="base__abi", so the merged APK has to drop those two
manifest attributes (aapt2/PackageManager read them by resource id). We zero the
resource-id map entries instead of touching the string pool, which keeps the
binary XML byte-identical in size.

  python merge_apk.py --variant instant
"""
import argparse
import re
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "splits" / "base.apk"
SPLIT = ROOT / "splits" / "split_config.arm64_v8a.apk"
LIB_ENTRY = "lib/arm64-v8a/libil2cpp.so"

# android:requiredSplitTypes (0x0101064e) and android:splitTypes (0x0101064f)
DROP_ATTRS = {0x0101064E, 0x0101064F}
ATTR_RES_IDS = ({0x0101064E: "requiredSplitTypes", 0x0101064F: "splitTypes"})


def strip_split_attrs(axml: bytes) -> tuple[bytes, int]:
    """Strip the split-type declarations from a binary AndroidManifest.

    PackageManager honours these by *value*, so zeroing the resource-map ids is not
    enough: every attribute whose value is the ABI split type gets its typed value
    turned into TYPE_NULL, which the parser treats as "attribute not present".
    """
    d = bytearray(axml)
    if d[:2] != b"\x03\x00":
        raise SystemExit("AndroidManifest.xml is not binary AXML")
    total = struct.unpack_from("<I", d, 4)[0]

    pos = 8
    chunks = []
    while pos + 8 <= min(total, len(d)):
        ctype, hsize, csize = struct.unpack_from("<HHI", d, pos)
        if csize == 0:
            break
        chunks.append((ctype, pos, hsize, csize))
        pos += csize

    # string pool -> index of the split type value
    pool = next((c for c in chunks if c[0] == 0x0001), None)
    if pool is None:
        raise SystemExit("no string pool in manifest")
    _, ppos, phsize, _ = pool
    n_strings, _, flags, strings_start = struct.unpack_from("<IIII", d, ppos + 8)
    utf8 = bool(flags & 0x100)
    offs = [struct.unpack_from("<I", d, ppos + phsize + i * 4)[0] for i in range(n_strings)]
    base = ppos + strings_start

    def get(i):
        o = base + offs[i]
        if utf8:
            o += 2 if d[o] & 0x80 else 1          # utf16 length (skip)
            n = d[o]
            if n & 0x80:
                n = ((n & 0x7F) << 8) | d[o + 1]
                o += 1
            o += 1
            return bytes(d[o:o + n]).decode("utf8", "replace")
        n = struct.unpack_from("<H", d, o)[0]
        return bytes(d[o + 2:o + 2 + n * 2]).decode("utf-16-le", "replace")

    split_vals = {i for i in range(n_strings) if get(i) in ("base__abi", "base__lang", "config.arm64_v8a")}

    # zero the resource ids too (belt and braces)
    dropped = 0
    for ctype, cpos, chsize, csize in chunks:
        if ctype == 0x0180:
            for i in range((csize - chsize) // 4):
                off = cpos + chsize + i * 4
                if struct.unpack_from("<I", d, off)[0] in DROP_ATTRS:
                    struct.pack_into("<I", d, off, 0)
                    dropped += 1

    # null out every attribute whose value is one of those strings
    for ctype, cpos, chsize, csize in chunks:
        if ctype != 0x0102:          # RES_XML_START_ELEMENT
            continue
        attr_start = struct.unpack_from("<H", d, cpos + 24)[0]
        attr_size = struct.unpack_from("<H", d, cpos + 26)[0]
        attr_count = struct.unpack_from("<H", d, cpos + 28)[0]
        for i in range(attr_count):
            off = cpos + 16 + attr_start + i * attr_size
            raw = struct.unpack_from("<I", d, off + 8)[0]
            if raw in split_vals:
                struct.pack_into("<IBB", d, off + 12, 8, 0, 0x00)   # size, res0, TYPE_NULL
                struct.pack_into("<I", d, off + 16, 0)              # data
                dropped += 1
    return bytes(d), dropped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", default="instant", choices=["safe", "instant"])
    a = ap.parse_args()

    build = ROOT / "build" / a.variant
    patched_so = (build / "libil2cpp.patched.so")
    if not patched_so.exists():
        raise SystemExit(f"missing {patched_so}")
    dex_patch = ROOT / "build" / "dex" / "classes2.patched.dex"
    out = build / "merged.unsigned.apk"

    libs = {}
    with zipfile.ZipFile(SPLIT) as zs:
        for info in zs.infolist():
            if info.filename.startswith("lib/"):
                libs[info.filename] = zs.read(info.filename)
    libs[LIB_ENTRY] = patched_so.read_bytes()

    with zipfile.ZipFile(BASE) as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            if info.filename.startswith("META-INF/") and info.filename.upper().endswith(
                    (".SF", ".RSA", ".DSA", ".EC", ".MF")):
                continue
            data = zin.read(info.filename)
            if info.filename == "AndroidManifest.xml":
                data, dropped = strip_split_attrs(data)
                print(f"  cleared {dropped} split-type resource ids from the manifest")
            elif info.filename == "classes2.dex" and dex_patch.exists():
                data = dex_patch.read_bytes()
            o = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            o.compress_type = info.compress_type
            o.external_attr = info.external_attr
            o.internal_attr = info.internal_attr
            o.create_system = info.create_system
            zout.writestr(o, data)
        for name, data in libs.items():
            o = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            o.compress_type = zipfile.ZIP_DEFLATED
            o.external_attr = 0o644 << 16
            zout.writestr(o, data)

    print(f"  merged {len(libs)} native libraries into {out.name}")
    print(f"  -> {out} ({out.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()


