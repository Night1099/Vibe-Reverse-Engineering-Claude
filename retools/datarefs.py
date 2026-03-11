#!/usr/bin/env python3
"""Find all instructions that reference a global memory address.

Scans executable sections for instructions whose operands encode an
absolute address (no base/index register), e.g. ``fsub [0x7A0000]``
or ``mov [0x7A0000], eax``.  Classifies each hit as read (r), write (w),
or read-write (rw).

Output:  N data refs to 0xADDR..0xADDR+RANGE
           0xVA  [r ]  mnemonic  operand

Usage:
    python retools/datarefs.py <binary> <address> [--range N] [--access r|w|rw]

Examples:
    python retools/datarefs.py binary.exe 0x7A0000
    python retools/datarefs.py binary.exe 0x7A0000 --range 12
    python retools/datarefs.py binary.exe 0x7A0000 --access w
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary

CHUNK = 0x10000


def _access_for(b, insn, addr_lo, addr_hi):
    """Determine read/write access for operands matching the target range."""
    acc = set()
    for mop in b.mem_operands(insn):
        if mop.base or mop.index:
            continue
        ea = mop.disp & 0xFFFFFFFF
        if addr_lo <= ea < addr_hi:
            acc.update(mop.access)
    return "rw" if {"r", "w"} <= acc else ("w" if "w" in acc else "r")


def scan(b: Binary, addr: int, size: int, access_filter: str | None):
    """Yield (va, mnemonic, op_str, access) for matching instructions."""
    addr_hi = addr + size
    for sec_va, sec_off, sec_size in b.exec_ranges():
        for chunk_start in range(0, sec_size, CHUNK):
            chunk_end = min(chunk_start + CHUNK + 32, sec_size)
            code = b.raw[sec_off + chunk_start : sec_off + chunk_end]
            va = sec_va + chunk_start
            for insn in b._cs.disasm(code, va):
                refs = b.abs_mem_refs(insn)
                if not any(addr <= r < addr_hi for r in refs):
                    continue
                acc = _access_for(b, insn, addr, addr_hi)
                if access_filter and acc != access_filter:
                    continue
                yield insn.address, insn.mnemonic, insn.op_str, acc


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("address",
                   help="Target global address in hex (e.g. 0x7A0000)")
    p.add_argument("--range", type=int, default=4,
                   help="Byte range: match refs to "
                        "[address, address+range) (default: 4)")
    p.add_argument("--access", choices=["r", "w", "rw"],
                   help="Only show reads (r), writes (w), or both (rw)")
    args = p.parse_args()

    b = Binary(args.binary)
    addr = int(args.address, 16)
    hits = list(scan(b, addr, args.range, args.access))

    print(f"{len(hits)} data refs to 0x{addr:X}..0x{addr + args.range - 1:X}\n")
    for va, mnemonic, op_str, acc in hits:
        print(f"  0x{va:08X}  [{acc:2s}]  {mnemonic:8s} {op_str}")


if __name__ == "__main__":
    main()
