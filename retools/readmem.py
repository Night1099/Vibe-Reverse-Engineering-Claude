#!/usr/bin/env python3
"""Read typed data from a PE binary at a virtual address.

Reads memory from a PE file at the given VA and displays it as the
requested type.  Supports numeric types, raw bytes, and pointer reads.

Usage:
    python retools/readmem.py <binary> <va> <type> [-n COUNT]

Types: float, double, int32, uint32, int16, uint16, int8, uint8, ptr, bytes

Examples:
    python retools/readmem.py binary.exe 0x401000 float
    python retools/readmem.py binary.exe 0x401000 uint32 -n 3
    python retools/readmem.py binary.exe 0x401000 bytes -n 64
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary

_TYPES = {
    "float": ("<f", 4),
    "double": ("<d", 8),
    "int32": ("<i", 4),
    "uint32": ("<I", 4),
    "int16": ("<h", 2),
    "uint16": ("<H", 2),
    "int8": ("<b", 1),
    "uint8": ("<B", 1),
    "ptr": ("<I", 4),
}


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("va", help="Virtual address in hex (e.g. 0x401000)")
    p.add_argument("type", choices=list(_TYPES) + ["bytes"],
                   help="Data type to interpret as")
    p.add_argument("-n", "--count", type=int, default=1,
                   help="Number of elements to read (bytes mode: byte count; "
                        "other types: element count) (default: 1)")
    args = p.parse_args()

    b = Binary(args.binary)
    va = int(args.va, 16)

    if args.type == "bytes":
        data = b.read_va(va, args.count)
        print(f"0x{va:08X}: {' '.join(f'{x:02X}' for x in data)}")
        return

    fmt, size = _TYPES[args.type]
    if b.is_64 and args.type == "ptr":
        fmt, size = "<Q", 8

    for i in range(args.count):
        addr = va + i * size
        data = b.read_va(addr, size)
        if len(data) < size:
            break
        (val,) = struct.unpack(fmt, data)
        if args.type == "ptr":
            print(f"0x{addr:08X}: 0x{val:0{b.ptr_size * 2}X}")
        elif args.type in ("float", "double"):
            raw_int = struct.unpack("<I" if size == 4 else "<Q", data)[0]
            print(f"0x{addr:08X}: {val:14.6f}  (0x{raw_int:0{size * 2}X})")
        else:
            print(f"0x{addr:08X}: {val}")


if __name__ == "__main__":
    main()
