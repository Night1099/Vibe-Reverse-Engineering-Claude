#!/usr/bin/env python3
"""Decompose a function into basic blocks and show control flow edges.

Finds the function prologue from a given VA, splits it into basic blocks
(leader = branch target or fall-through after branch), and shows edges
(conditional, unconditional, fall-through).

Output (text mode):
    === Block 0xADDR (N insns)  -> 0xTARGET (label), ... ===
      disassembly lines

Output (mermaid mode):
    Mermaid graph TD suitable for rendering in Markdown.

Usage:
    python retools/cfg.py <binary> <va> [--format text|mermaid] [--max-size N]

Examples:
    python retools/cfg.py binary.exe 0x401000
    python retools/cfg.py binary.exe 0x401000 --format mermaid
    python retools/cfg.py binary.exe 0x401000 --max-size 0x8000
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary
from funcinfo import find_start

_UNCOND_JUMPS = {"jmp", "ret", "retn"}
_COND_JUMPS = {
    "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns", "jp", "jnp",
}


def _resolve_target(insn) -> int | None:
    try:
        return int(insn.op_str, 16)
    except ValueError:
        return None


def _find_func_end(insns):
    """Detect function boundary: stop after ret + NOP padding or int3."""
    last_ret = None
    nop_run = 0
    for i, insn in enumerate(insns):
        if insn.mnemonic in ("ret", "retn"):
            last_ret = i
            nop_run = 0
        elif last_ret is not None:
            if insn.mnemonic == "nop":
                nop_run += 1
                if nop_run >= 2:
                    return last_ret + 1
            elif insn.mnemonic == "int3":
                return last_ret + 1
            else:
                last_ret = None
                nop_run = 0
    return len(insns)


def build_cfg(b: Binary, start: int, max_size: int = 0x4000):
    """Return (blocks, edges) where blocks maps block_va -> [insns]."""
    raw_insns = b.disasm(start, count=5000, max_bytes=max_size)
    if not raw_insns:
        return {}, []
    insns = raw_insns[:_find_func_end(raw_insns)]
    if not insns:
        return {}, []

    # Collect block-start addresses
    leaders = {start}
    for insn in insns:
        mn = insn.mnemonic
        if mn in _UNCOND_JUMPS | _COND_JUMPS:
            target = _resolve_target(insn)
            if target is not None:
                leaders.add(target)
            if mn in _COND_JUMPS:
                leaders.add(insn.address + insn.size)
            if mn in _UNCOND_JUMPS and mn not in ("ret", "retn"):
                leaders.add(insn.address + insn.size)

    leaders = sorted(leaders)
    leader_set = set(leaders)

    # Partition instructions into blocks
    blocks: dict[int, list] = {}
    current_leader = None
    for insn in insns:
        if insn.address in leader_set:
            current_leader = insn.address
            blocks[current_leader] = []
        if current_leader is not None:
            blocks[current_leader].append(insn)
            mn = insn.mnemonic
            if mn in _UNCOND_JUMPS or mn in _COND_JUMPS:
                current_leader = None

    # Build edges
    edges = []
    for block_va, block_insns in blocks.items():
        if not block_insns:
            continue
        last = block_insns[-1]
        mn = last.mnemonic
        if mn in ("ret", "retn"):
            continue
        target = _resolve_target(last)
        fallthrough = last.address + last.size
        if mn in _COND_JUMPS:
            if target and target in blocks:
                edges.append((block_va, target, mn))
            if fallthrough in blocks:
                edges.append((block_va, fallthrough, "fall"))
        elif mn in _UNCOND_JUMPS:
            if target and target in blocks:
                edges.append((block_va, target, "jmp"))
        else:
            if fallthrough in blocks:
                edges.append((block_va, fallthrough, "fall"))

    return blocks, edges


def _fmt_text(blocks, edges, b):
    sorted_blocks = sorted(blocks.items())
    for block_va, insns in sorted_blocks:
        out_edges = [(dst, label) for src, dst, label in edges if src == block_va]
        edge_str = "  -> " + ", ".join(
            f"0x{dst:08X} ({label})" for dst, label in out_edges
        ) if out_edges else ""
        print(f"\n=== Block 0x{block_va:08X} ({len(insns)} insns){edge_str} ===")
        for insn in insns:
            print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")


def _fmt_mermaid(blocks, edges, start):
    print("```mermaid")
    print("graph TD")
    for block_va, insns in sorted(blocks.items()):
        first = insns[0] if insns else None
        last = insns[-1] if insns else None
        label = f"0x{block_va:08X}"
        if last:
            label += f"..0x{last.address:08X}"
        label += f" ({len(insns)} insns)"
        node_id = f"B_{block_va:08X}"
        print(f'    {node_id}["{label}"]')
    for src, dst, label in edges:
        src_id = f"B_{src:08X}"
        dst_id = f"B_{dst:08X}"
        print(f'    {src_id} -->|"{label}"| {dst_id}')
    print("```")


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("va", help="Any address inside the target function (hex, "
                   "e.g. 0x401000)")
    p.add_argument("--format", choices=["text", "mermaid"], default="text",
                   help="Output format (default: text)")
    p.add_argument("--max-size", type=lambda x: int(x, 0), default=0x4000,
                   help="Max forward-scan window in bytes (default: 0x4000)")
    args = p.parse_args()

    b = Binary(args.binary)
    va = int(args.va, 16)
    start = find_start(b, va) or va
    blocks, edges = build_cfg(b, start, args.max_size)

    print(f"Function 0x{start:08X}: {len(blocks)} blocks, {len(edges)} edges\n")
    if args.format == "mermaid":
        _fmt_mermaid(blocks, edges, start)
    else:
        _fmt_text(blocks, edges, b)


if __name__ == "__main__":
    main()
