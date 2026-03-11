#!/usr/bin/env python3
"""Analyze a function: find start, all return instructions, and callees.

Given any address inside a function, walks backward to find the prologue,
then forward-scans to collect every RET (with stack cleanup size and
inferred calling convention) and every direct CALL target.

Output:
    Function: 0xSTART .. 0xEND  (N bytes)
    Returns (N):  address, ret imm, calling convention guess
    Callees (N):  unique direct call targets with call count

Usage:
    python retools/funcinfo.py <binary> <va> [--max-size BYTES]

Examples:
    python retools/funcinfo.py binary.exe 0x401000
    python retools/funcinfo.py binary.exe 0x401000 --max-size 0x4000
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary

_PROLOGUES = [b"\x55\x8B\xEC", b"\x55\x89\xE5"]
_PADDING = {0x90, 0xCC}


def find_start(b: Binary, va: int, max_search: int = 0x2000) -> int | None:
    """Walk backwards from *va* to find the function entry point.

    Recognises standard prologues (push ebp; mov ebp,esp) and
    sub esp preceded by padding.  Also detects inter-function padding
    runs (>= 2 NOP/INT3 bytes) as hard boundaries -- the function
    must start immediately after such a run.
    """
    padding_run = 0
    for off in range(0, max_search):
        addr = va - off
        cur = b.read_va(addr, 1)
        if not cur:
            continue

        if cur[0] in _PADDING:
            padding_run += 1
            continue

        if padding_run >= 2:
            return addr + padding_run + 1

        padding_run = 0

        head = b.read_va(addr, 3)
        if head in _PROLOGUES:
            return addr
        if len(head) >= 2 and head[0] in (0x83, 0x81) and head[1] == 0xEC:
            prev = b.read_va(addr - 1, 1)
            if prev and prev[0] in _PADDING:
                return addr
    return None


def analyze(b: Binary, start: int, max_size: int):
    """Return (rets, callees, end_va) for the function at *start*."""
    insns = b.disasm(start, count=5000, max_bytes=max_size)
    rets: list[tuple[int, int]] = []
    calls: list[tuple[int, int | str]] = []
    end_va = start
    nop_run = 0

    for insn in insns:
        if insn.mnemonic in ("ret", "retn"):
            cleanup = int(insn.op_str, 0) if insn.op_str else 0
            rets.append((insn.address, cleanup))
            end_va = insn.address + insn.size
        elif insn.mnemonic == "call":
            try:
                target: int | str = int(insn.op_str, 16)
            except ValueError:
                target = insn.op_str
            calls.append((insn.address, target))

        nop_run = nop_run + 1 if insn.mnemonic == "nop" else 0
        if (nop_run >= 3 and rets) or insn.mnemonic == "int3":
            break

    return rets, calls, end_va


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("va", help="Any address inside the target function (hex, "
                   "e.g. 0x401000)")
    p.add_argument(
        "--max-size", type=lambda x: int(x, 0), default=0x2000,
        help="Max forward-scan window in bytes (default: 0x2000)",
    )
    args = p.parse_args()

    b = Binary(args.binary)
    va = int(args.va, 16)
    start = find_start(b, va) or va
    rets, calls, end_va = analyze(b, start, args.max_size)

    print(f"Function: 0x{start:08X} .. 0x{end_va:08X}  ({end_va - start} bytes)\n")

    print(f"Returns ({len(rets)}):")
    for addr, cleanup in rets:
        if cleanup:
            desc = f"stdcall/thiscall  {cleanup} bytes = {cleanup // 4} stack args"
        else:
            desc = "cdecl/thiscall  0 stack args"
        print(f"  0x{addr:08X}: ret {f'0x{cleanup:X}':6s}  {desc}")

    print(f"\nCallees ({len(set(t for _, t in calls))}):")
    seen: set = set()
    for _, target in calls:
        if target in seen:
            continue
        seen.add(target)
        n = sum(1 for _, t in calls if t == target)
        label = target if isinstance(target, str) else f"0x{target:08X}"
        print(f"  {label}{f'  ({n}x)' if n > 1 else ''}")


if __name__ == "__main__":
    main()
