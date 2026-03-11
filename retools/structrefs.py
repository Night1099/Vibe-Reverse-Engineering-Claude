#!/usr/bin/env python3
"""Find all instructions that access [register + offset] for a given offset.

Useful for mapping struct field usage across a binary -- e.g. finding every
piece of code that touches ``obj+0x54`` to understand a struct layout.
Classifies each hit as read (r), write (w), or both (rw).

Output:  N refs to [reg+0xOFFSET]
           0xVA  base  [rw]  mnemonic  operand

Usage:
    python retools/structrefs.py <binary> <offset> [--base REG] [--fn VA]

Examples:
    python retools/structrefs.py binary.exe 0x54
    python retools/structrefs.py binary.exe 0x54 --base esi
    python retools/structrefs.py binary.exe 0x54 --fn 0x401000 --fn-size 0x200
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary

CHUNK = 0x10000


def scan(b: Binary, offset: int, base_filter: str | None,
         fn_start: int | None, fn_size: int):
    """Yield (va, base_reg, access, mnemonic, op_str) for matching accesses."""
    if fn_start is not None:
        ranges = [(fn_start, b.va_to_offset(fn_start) or 0, fn_size)]
    else:
        ranges = b.exec_ranges()

    for sec_va, sec_off, sec_size in ranges:
        for chunk_start in range(0, sec_size, CHUNK):
            chunk_end = min(chunk_start + CHUNK + 32, sec_size)
            code = b.raw[sec_off + chunk_start : sec_off + chunk_end]
            va = sec_va + chunk_start
            for insn in b._cs.disasm(code, va):
                for mop in b.mem_operands(insn):
                    if mop.disp != offset:
                        continue
                    if not mop.base or mop.index:
                        continue
                    if base_filter and mop.base != base_filter:
                        continue
                    yield (insn.address, mop.base, mop.access,
                           insn.mnemonic, insn.op_str)


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("offset",
                   help="Struct field offset in hex (e.g. 0x54)")
    p.add_argument("--base",
                   help="Only show accesses with this base register "
                        "(e.g. esi, edi, ecx)")
    p.add_argument("--fn",
                   help="Restrict scan to a single function at this VA (hex)")
    p.add_argument("--fn-size", type=lambda x: int(x, 0), default=0x2000,
                   help="Max function size when using --fn (default: 0x2000)")
    args = p.parse_args()

    b = Binary(args.binary)
    offset = int(args.offset, 16)
    fn_start = int(args.fn, 16) if args.fn else None

    hits = list(scan(b, offset, args.base, fn_start, args.fn_size))
    print(f"{len(hits)} refs to [reg+0x{offset:X}]\n")
    for va, base, acc, mnemonic, op_str in hits:
        print(f"  0x{va:08X}  {base:5s} [{acc:2s}]  {mnemonic:8s} {op_str}")


if __name__ == "__main__":
    main()
