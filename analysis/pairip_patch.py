#!/usr/bin/env python3
"""Neutralise PairIP (com.pairip.licensecheck) so the game also runs when it is
not installed by the Play Store.

PairIP fails closed: on a sideloaded install it shows its license activity and
calls System.exit(0) a fraction of a second after startup. We rewrite the
offending method bodies in classes2.dex and repair the DEX checksum + SHA-1
signature so ART still loads the file.

DEX instruction lengths matter: replacing a 3-unit `invoke` with a 1-unit
`return-void` leaves the second unit behind as a bogus opcode, which ART rejects
with a VerifyError. Every patch therefore overwrites exactly the first
instruction and pads the remainder with `nop`.

  python pairip_patch.py
"""
import hashlib
import re
import struct
import sys
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dexscan import Dex  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APK = ROOT / "splits" / "base.apk"
OUT = ROOT / "build" / "dex" / "classes2.patched.dex"

LC = "Lcom/pairip/licensecheck/LicenseClient;"
LA = "Lcom/pairip/licensecheck/LicenseActivity;"

TARGETS = [
    ("Lcom/pairip/licensecheck/LicenseClient$1;", "run", "void"),
    (LA, "exitApp", "void"),
    (LA, "closeApp", "void"),
    (LA, "closeAllTasks", "void"),
    (LC, "handleError", "void"),
    (LC, "startErrorDialogActivity", "void"),
    (LC, "startPaywallActivity", "void"),
    (LC, "scheduleAppShutdown", "void"),
    (LC, "isLocalCheckPassed", "true"),
]


def insn_len(op):
    """Length in 16-bit code units of a Dalvik instruction with this opcode."""
    if op == 0x18:
        return 5
    if (op in (0x03, 0x06, 0x09, 0x14, 0x17, 0x1B, 0x24, 0x25, 0x26, 0x2A, 0x2B, 0x2C)
            or 0x6E <= op <= 0x72 or 0x74 <= op <= 0x78 or 0xFC <= op <= 0xFD):
        return 3
    if op in (0xFA, 0xFB):
        return 4
    if (op in (0x00, 0x01, 0x04, 0x05, 0x07, 0x08, 0x0E, 0x0F, 0x10, 0x11, 0x12,
               0x1D, 0x1E, 0x21, 0x27, 0x28, 0x73, 0x79, 0x7A)
            or 0x7B <= op <= 0x8F or 0xB0 <= op <= 0xCF or 0x0A <= op <= 0x0D):
        return 1
    return 2


def find_method_code(dx, wanted_class, wanted_method):
    for cls, data_off in dx.classes():
        if cls != wanted_class or not data_off:
            continue
        for midx, code in dx.methods_in_class(data_off):
            _, name, _ = dx.method(midx)
            if name == wanted_method:
                return code
    return None


def fix_header(d):
    d[12:32] = hashlib.sha1(bytes(d[32:])).digest()
    d[8:12] = struct.pack("<I", zlib.adler32(bytes(d[12:])) & 0xFFFFFFFF)


def main():
    src = zipfile.ZipFile(APK)
    entry = next(n for n in src.namelist() if re.match(r"classes2\.dex$", n))
    data = bytearray(src.read(entry))
    dx = Dex(bytes(data), entry)

    patched = 0
    for cls, meth, kind in TARGETS:
        code = find_method_code(dx, cls, meth)
        if code is None:
            print(f"  ! {cls}->{meth} not found")
            continue
        insns = code + 16
        op = struct.unpack_from("<H", data, insns)[0] & 0xFF
        n = insn_len(op)
        if kind == "true":
            if n < 2:
                raise SystemExit(f"cannot return-true: {cls}->{meth} first insn is {n} unit(s)")
            words = [0x1012, 0x000F] + [0x0000] * (n - 2)
            note = "return true"
        else:
            words = [0x000E] + [0x0000] * (n - 1)
            note = "return-void"
        struct.pack_into("<%dH" % n, data, insns, *words)
        patched += 1
        print(f"  {cls.split('/')[-1]:<22} {meth:<26} op 0x{op:02X} ({n}u) -> {note}")

    if not patched:
        raise SystemExit("nothing patched")

    fix_header(data)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(data)
    print(f"\n{patched} methods patched -> {OUT}")


if __name__ == "__main__":
    main()

