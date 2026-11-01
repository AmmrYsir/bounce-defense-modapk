#!/usr/bin/env python3
"""Minimal DEX scanner: find which Java methods invoke a given API, and which
string constants appear in those classes.

Used to locate the install-source check that calls System.exit on sideloaded installs.

  python dexscan.py --apk splits/base.apk --invoke System.exit
  python dexscan.py --apk splits/base.apk --invoke PackageManager.getInstallerPackageName
  python dexscan.py --apk splits/base.apk --string com.android.vending
"""
import argparse
import re
import struct
import zipfile
from collections import defaultdict


def uleb(d, o):
    r = s = 0
    while True:
        b = d[o]
        o += 1
        r |= (b & 0x7F) << s
        if not b & 0x80:
            return r, o
        s += 7


class Dex:
    def __init__(self, data, name=""):
        self.d = data
        self.name = name
        h = self.d
        self.strings_size = struct.unpack_from("<I", h, 0x38)[0]
        self.strings_off = struct.unpack_from("<I", h, 0x3C)[0]
        self.types_size = struct.unpack_from("<I", h, 0x40)[0]
        self.types_off = struct.unpack_from("<I", h, 0x44)[0]
        self.methods_size = struct.unpack_from("<I", h, 0x58)[0]
        self.methods_off = struct.unpack_from("<I", h, 0x5C)[0]
        self.classes_size = struct.unpack_from("<I", h, 0x60)[0]
        self.classes_off = struct.unpack_from("<I", h, 0x64)[0]
        self._str_cache = {}

    def string(self, i):
        if i in self._str_cache:
            return self._str_cache[i]
        off = struct.unpack_from("<I", self.d, self.strings_off + i * 4)[0]
        n, p = uleb(self.d, off)
        end = self.d.index(b"\0", p)
        s = self.d[p:end].decode("utf8", "replace")
        self._str_cache[i] = s
        return s

    def type(self, i):
        return self.string(struct.unpack_from("<I", self.d, self.types_off + i * 4)[0])

    def method(self, i):
        o = self.methods_off + i * 8
        cls, proto, name = struct.unpack_from("<HHI", self.d, o)
        return self.type(cls), self.string(name), proto

    def methods_in_class(self, class_data_off):
        """Yield (method_idx, code_off) for every method defined in a class."""
        d = self.d
        p = class_data_off
        sf, p = uleb(d, p)
        inf, p = uleb(d, p)
        dm, p = uleb(d, p)
        vm, p = uleb(d, p)
        for _ in range(sf + inf):  # fields (skip)
            _, p = uleb(d, p)
            _, p = uleb(d, p)
        out = []
        for count in (dm, vm):
            idx = 0
            for _ in range(count):
                diff, p = uleb(d, p)
                acc, p = uleb(d, p)
                code, p = uleb(d, p)
                idx += diff
                out.append((idx, code))
        return out

    def invokes(self, code_off):
        """Return method indexes invoked in a code_item."""
        d = self.d
        regs, ins, outs, tries, dbg = struct.unpack_from("<HHHHI", d, code_off)
        insns_size = struct.unpack_from("<I", d, code_off + 12)[0]
        base = code_off + 16
        found = []
        for i in range(insns_size):
            w = struct.unpack_from("<H", d, base + i * 2)[0]
            op = w & 0xFF
            if op in (0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78):
                if i + 1 < insns_size:
                    mi = struct.unpack_from("<H", d, base + (i + 1) * 2)[0]
                    if mi < self.methods_size:
                        found.append(mi)
        return found

    def string_literals(self, code_off):
        """Return string indexes referenced by const-string in a code_item."""
        d = self.d
        insns_size = struct.unpack_from("<I", d, code_off + 12)[0]
        base = code_off + 16
        out = []
        for i in range(insns_size):
            w = struct.unpack_from("<H", d, base + i * 2)[0]
            op = w & 0xFF
            if op in (0x1A, 0x1B):  # const-string / jumbo (jumbo uses 2 words + idx)
                if op == 0x1A and i + 1 < insns_size:
                    si = struct.unpack_from("<H", d, base + (i + 1) * 2)[0]
                    if si < self.strings_size:
                        out.append(si)
        return out

    def classes(self):
        for i in range(self.classes_size):
            o = self.classes_off + i * 32
            class_idx, access, super_idx, ifaces, src, ann, data_off, static_values = struct.unpack_from("<IIIIIIII", self.d, o)
            yield self.type(class_idx), data_off


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True)
    ap.add_argument("--invoke", help="e.g. System.exit or PackageManager.getInstallerPackageName")
    ap.add_argument("--string", help="string constant that must also appear in the class")
    ap.add_argument("--dex", default=None, help="only this dex entry")
    a = ap.parse_args()

    want = a.invoke.split(".")[-1] if a.invoke else None
    z = zipfile.ZipFile(a.apk)
    dexes = sorted([n for n in z.namelist() if re.match(r"classes\d*\.dex$", n)])
    if a.dex:
        dexes = [d for d in dexes if d == a.dex]

    results = []
    for name in dexes:
        dx = Dex(z.read(name), name)
        for cls, data_off in dx.classes():
            if not data_off:
                continue
            methods = dx.methods_in_class(data_off)
            hit_methods = []
            class_strings = set()
            for midx, code in methods:
                if not code:
                    continue
                for si in dx.string_literals(code):
                    class_strings.add(dx.string(si))
                if want:
                    for m in dx.invokes(code):
                        c, n, _ = dx.method(m)
                        if want == "exit" and c == "Ljava/lang/System;" and n == "exit":
                            hit_methods.append(dx.method(midx)[1])
                        elif want in n and ("PackageManager" in c or c.endswith("InstallSourceInfo;")):
                            hit_methods.append(dx.method(midx)[1])
            if hit_methods and (not a.string or any(a.string in s for s in class_strings)):
                results.append((name, cls, sorted(set(hit_methods)), a.string in class_strings if a.string else None))

    print(f"{len(results)} matching classes")
    for name, cls, ms, has in results[:60]:
        print(f"  {name:14} {cls:60} methods={ms}")


if __name__ == "__main__":
    main()


