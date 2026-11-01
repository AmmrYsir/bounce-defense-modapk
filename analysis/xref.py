#!/usr/bin/env python3
"""Static cross-reference helper for Unity IL2CPP libil2cpp.so (AArch64).

Reads the function map produced by Il2CppDumper (dump.cs) and scans the code
sections of libil2cpp.so for BL/B instructions, so we can see exactly which
managed methods call a given target method.

Usage:
  python xref.py --callers 0x305C70C [--limit 40]
  python xref.py --callees AdsSelfManager.ShowAds
  python xref.py --find symbol VoodooPremium
  python xref.py --string "ShowInterstitial"
"""
import argparse
import bisect
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SO = ROOT / "splits" / "arm64" / "lib" / "arm64-v8a" / "libil2cpp.so"
RUN_WORK = ROOT / "local" / "work"
DUMP = RUN_WORK / "retarget" / "dump" / "dump.cs"


def parse_functions():
    """Map RVA -> fully qualified method name, in file order."""
    rva_re = re.compile(r"^\s*// RVA: (0x[0-9A-Fa-f]+) Offset: (0x[0-9A-Fa-f]+)")
    cur_class = ""
    pending_rva = None
    funcs = []
    with open(DUMP, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith(("public ", "internal ", "private ", "protected ")) and (
                " class " in line or " struct " in line or " interface " in line
            ):
                m = re.search(r"\b(?:class|struct|interface)\s+([A-Za-z0-9_.<>`]+)", line)
                cur_class = m.group(1) if m else cur_class
                continue
            m = rva_re.match(line)
            if m:
                pending_rva = int(m.group(1), 16)
                continue
            if pending_rva is not None and line.strip() and line.startswith(("\t", " ")):
                sig = line.strip()
                if sig.startswith("["):
                    continue
                nm = re.match(r".*?([A-Za-z0-9_~.<>]+)\s*\(", sig)
                name = nm.group(1) if nm else sig[:40]
                if name in ("get", "set"):
                    name = "?"
                funcs.append((pending_rva, f"{cur_class}::{name}"))
                pending_rva = None
    funcs.sort()
    return funcs


def load_code(path):
    d = Path(path).read_bytes()
    shoff = struct.unpack_from("<Q", d, 0x28)[0]
    shentsize = struct.unpack_from("<H", d, 0x3A)[0]
    shnum = struct.unpack_from("<H", d, 0x3C)[0]
    shstrndx = struct.unpack_from("<H", d, 0x3E)[0]
    secs = []
    for i in range(shnum):
        o = shoff + i * shentsize
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", d, o)
        secs.append(dict(name_off=name, typ=typ, addr=addr, off=off, size=size, flags=flags))
    hdr = secs[shstrndx]
    strtab = d[hdr["off"]:hdr["off"] + hdr["size"]]

    def nm(x):
        e = strtab.find(b"\0", x)
        return strtab[x:e].decode("utf8", "replace")

    for s in secs:
        s["name"] = nm(s["name_off"])
    # sections that hold AArch64 code, i.e. SHF_EXECINSTR (0x4)
    code = [s for s in secs if s["size"] and (s["flags"] & 0x4) and s["name"] in (".text", "il2cpp")]
    return d, code


def scan_bl(d, code):
    """Yield (site_rva, target_rva) for every BL/B instruction in code sections."""
    out = []
    for s in code:
        base = s["addr"]
        blob = d[s["off"]:s["off"] + s["size"]]
        n = len(blob) // 4
        words = struct.unpack_from("<%dI" % n, blob, 0)
        for i, w in enumerate(words):
            op = w >> 26
            if op in (0b100101, 0b000101):  # BL, B
                imm = w & 0x03FFFFFF
                if imm & 0x02000000:
                    imm -= 0x04000000
                out.append((base + i * 4, base + i * 4 + imm * 4))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--callers", help="target RVA in hex")
    ap.add_argument("--callees", help="function name substring")
    ap.add_argument("--find", help="substring to search in function names")
    ap.add_argument("--string", help="search .rodata string literal and report xref sites")
    ap.add_argument("--limit", type=int, default=40)
    args = ap.parse_args()

    funcs = parse_functions()
    rvas = [f[0] for f in funcs]
    d, code = load_code(SO)

    def owner(rva):
        i = bisect.bisect_right(rvas, rva) - 1
        return funcs[i] if i >= 0 else ("0x0", "?")

    if args.find:
        hits = [f for f in funcs if args.find.lower() in f[1].lower()]
        print(f"{len(hits)} matches for {args.find!r}")
        for rva, name in hits[: args.limit]:
            print(f"  0x{rva:X}  {name}")
        return

    xrefs = scan_bl(d, code)

    if args.callers:
        tgt = int(args.callers, 16)
        hits = [(site, o) for site, t in xrefs if t == tgt for o in [owner(site)]]
        print(f"{len(hits)} call sites -> 0x{tgt:X} ({owner(tgt)[1]})")
        for site, (frva, fname) in hits[: args.limit]:
            print(f"  call @0x{site:X} in {fname}")
        return

    if args.callees:
        idx = [i for i, f in enumerate(funcs) if args.callees.lower() in f[1].lower()]
        if not idx:
            print("no such function")
            return
        for i in idx:
            rva, name = funcs[i]
            end = funcs[i + 1][0] if i + 1 < len(funcs) else rva + 0x4000
            callees = sorted({(t, owner(t)[1]) for site, t in xrefs if rva <= site < end and t}
                             , key=lambda x: x[1])
            print(f"{name} @0x{rva:X}..0x{end:X} calls {len(callees)} targets")
            for t, nm in callees[: args.limit]:
                print(f"   -> 0x{t:X} {nm}")
        return

    if args.string:
        needle = args.string.encode()
        ro = next(s for s in [dict(name=".rodata")] if False) if False else None
        # locate the literal in the whole file, then map file offset -> vaddr using PT_LOAD
        off = d.find(needle)
        if off < 0:
            print("string not found")
            return
        phoff = struct.unpack_from("<Q", d, 0x20)[0]
        phentsize = struct.unpack_from("<H", d, 0x36)[0]
        phnum = struct.unpack_from("<H", d, 0x38)[0]
        vaddr = None
        for i in range(phnum):
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack_from("<IIQQQQ", d, phoff + i * phentsize)
            if p_type == 1 and p_offset <= off < p_offset + p_filesz:
                vaddr = p_vaddr + (off - p_offset)
        print(f"string @file 0x{off:X} vaddr 0x{vaddr:X}" if vaddr else "no segment")
        return

    print("nothing to do")


if __name__ == "__main__":
    main()

