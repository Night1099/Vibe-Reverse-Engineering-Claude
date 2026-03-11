#!/usr/bin/env python3
"""Search a PE binary for strings, byte patterns, or imports.

Three sub-commands:

  strings   Extract printable ASCII strings (min length filter, keyword filter)
  pattern   Find exact byte sequences (hex, spaces optional)
  imports   List PE import table entries (optional DLL name filter)

Usage:
    python retools/search.py <binary> strings [-f KEYWORDS] [-m MIN_LEN]
    python retools/search.py <binary> pattern <hex_bytes>
    python retools/search.py <binary> imports [-d DLL_NAME]

Examples:
    python retools/search.py binary.exe strings -f render,draw,visible
    python retools/search.py binary.exe pattern "D9 56 54 D8 1D"
    python retools/search.py binary.exe imports -d kernel32
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary


def cmd_strings(b: Binary, args):
    filters = [f.strip() for f in args.filter.split(",")] if args.filter else None
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % args.min_len, b.raw):
        s = m.group().decode("ascii", errors="ignore")
        if filters and not any(f.lower() in s.lower() for f in filters):
            continue
        va = b.offset_to_va(m.start())
        loc = f"0x{va:08X}" if va else f"off:{m.start():08X}"
        print(f"{loc}: {s}")


def cmd_pattern(b: Binary, args):
    needle = bytes.fromhex(args.hex.replace(" ", ""))
    pos = 0
    while True:
        idx = b.raw.find(needle, pos)
        if idx == -1:
            break
        va = b.offset_to_va(idx)
        loc = f"0x{va:08X}" if va else f"off:{idx:08X}"
        print(loc)
        pos = idx + 1


def cmd_imports(b: Binary, args):
    if not hasattr(b.pe, "DIRECTORY_ENTRY_IMPORT"):
        return
    for entry in b.pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode("ascii", errors="ignore")
        if args.dll and args.dll.lower() not in dll.lower():
            continue
        for imp in entry.imports:
            name = (
                imp.name.decode("ascii", errors="ignore")
                if imp.name
                else f"ordinal_{imp.ordinal}"
            )
            print(f"{dll:30s} {name}")


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("strings", help="Extract printable ASCII strings")
    s.add_argument("-f", "--filter",
                   help="Comma-separated keywords to match (case-insensitive)")
    s.add_argument("-m", "--min-len", type=int, default=4,
                   help="Minimum string length (default: 4)")

    s = sub.add_parser("pattern", help="Find exact byte pattern in the binary")
    s.add_argument("hex",
                   help="Hex bytes to search for, e.g. 'D9 56 54 D8 1D'")

    s = sub.add_parser("imports", help="List PE import table entries")
    s.add_argument("-d", "--dll",
                   help="Show only imports from DLLs matching this substring")

    args = p.parse_args()
    b = Binary(args.binary)
    {"strings": cmd_strings, "pattern": cmd_pattern, "imports": cmd_imports}[
        args.command
    ](b, args)


if __name__ == "__main__":
    main()
