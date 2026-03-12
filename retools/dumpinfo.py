#!/usr/bin/env python3
"""Analyze Windows minidump files (.dmp).

Sub-commands:

  info       Modules loaded at crash time + exception summary
  threads    All threads with registers resolved to module+offset
  stack      Stack walk for a single thread (return addresses, annotated values)
  exception  Exception record with MSVC C++ type decoding
  read       Read typed data from dump memory

Usage:
    python retools/dumpinfo.py <dumpfile> info
    python retools/dumpinfo.py <dumpfile> threads
    python retools/dumpinfo.py <dumpfile> stack <thread_id>
    python retools/dumpinfo.py <dumpfile> exception
    python retools/dumpinfo.py <dumpfile> read <address> <type>

Examples:
    python retools/dumpinfo.py crash.dmp info
    python retools/dumpinfo.py crash.dmp threads
    python retools/dumpinfo.py crash.dmp stack 12340
    python retools/dumpinfo.py crash.dmp exception
    python retools/dumpinfo.py crash.dmp read 0x7FFE0030 uint64

Requires: pip install minidump pefile
"""

import argparse
import struct
import sys
from pathlib import Path

try:
    from minidump.minidumpfile import MinidumpFile
except ImportError:
    sys.exit("minidump not installed. Run: pip install minidump")

import pefile


def _load_dump(path: str) -> MinidumpFile:
    import logging
    logging.disable(logging.CRITICAL)
    try:
        return MinidumpFile.parse(path)
    finally:
        logging.disable(logging.NOTSET)


def _build_module_map(dump: MinidumpFile):
    """Return sorted list of (base, size, name) for address resolution."""
    modules = []
    if dump.modules:
        for m in dump.modules.modules:
            modules.append((m.baseaddress, m.size, m.name))
    return sorted(modules, key=lambda x: x[0])


def _resolve_addr(modules, addr: int) -> str:
    """Resolve an address to module+offset, or return hex string."""
    for base, size, name in modules:
        if base <= addr < base + size:
            mod_name = name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            return f"{mod_name}+0x{addr - base:X}"
    return f"0x{addr:X}"


def _read_dump_memory(dump: MinidumpFile, addr: int, size: int) -> bytes:
    """Read bytes from the dump's memory image."""
    reader = dump.get_reader()
    try:
        return reader.read(addr, size)
    except Exception:
        return b""


def _get_exception_info(dump: MinidumpFile):
    """Extract exception record fields from the first exception record."""
    if not dump.exception or not dump.exception.exception_records:
        return None
    stream = dump.exception.exception_records[0]
    rec = stream.ExceptionRecord
    code_raw = rec.ExceptionCode_raw if hasattr(rec, "ExceptionCode_raw") else int(rec.ExceptionCode)
    return {
        "thread_id": stream.ThreadId,
        "code": code_raw,
        "address": rec.ExceptionAddress,
        "num_params": rec.NumberParameters,
        "params": list(rec.ExceptionInformation[:rec.NumberParameters]),
    }


def _resolve_msvc_exception(modules, dump, exc_info) -> str | None:
    """Try to decode MSVC C++ exception type from _ThrowInfo."""
    if exc_info["code"] != 0xE06D7363:
        return None
    params = exc_info["params"]
    if len(params) < 4:
        return None

    throw_info_param = params[2]
    image_base_param = params[3] if len(params) > 3 else 0

    target_base = image_base_param if image_base_param else exc_info["address"]
    for base, size, mod_path in _build_module_map(dump):
        if base <= target_base < base + size:
            try:
                pe = pefile.PE(mod_path, fast_load=False)
            except Exception:
                continue
            pe_base = pe.OPTIONAL_HEADER.ImageBase
            is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B

            if is_64:
                runtime_base = image_base_param if image_base_param else base
                ti_rva = throw_info_param - runtime_base
                if ti_rva <= 0:
                    continue
                try:
                    data = pe.get_data(ti_rva, 24)
                except Exception:
                    continue
                cta_rva = struct.unpack_from("<I", data, 12)[0]
                if cta_rva == 0:
                    continue
                cta_data = pe.get_data(cta_rva, 8)
                n_types = struct.unpack_from("<I", cta_data, 0)[0]
                types = []
                for i in range(n_types):
                    ct_rva = struct.unpack_from(
                        "<I", pe.get_data(cta_rva + 4 + i * 4, 4), 0)[0]
                    ct_data = pe.get_data(ct_rva, 28)
                    td_rva = struct.unpack_from("<I", ct_data, 4)[0]
                    td_data = pe.get_data(td_rva, 64)
                    name_bytes = td_data[16:]
                    name = name_bytes.split(b"\x00", 1)[0].decode(
                        "ascii", errors="replace")
                    types.append(name)
                return "; ".join(types) if types else None
            else:
                ti_va = throw_info_param
                ti_rva = ti_va - pe_base
                try:
                    data = pe.get_data(ti_rva, 16)
                except Exception:
                    continue
                cta_va = struct.unpack_from("<I", data, 12)[0]
                cta_rva = cta_va - pe_base
                try:
                    cta_data = pe.get_data(cta_rva, 8)
                except Exception:
                    continue
                n_types = struct.unpack_from("<I", cta_data, 0)[0]
                types = []
                for i in range(n_types):
                    ct_va = struct.unpack_from(
                        "<I", pe.get_data(cta_rva + 4 + i * 4, 4), 0)[0]
                    ct_rva = ct_va - pe_base
                    ct_data = pe.get_data(ct_rva, 20)
                    td_va = struct.unpack_from("<I", ct_data, 4)[0]
                    td_rva = td_va - pe_base
                    td_data = pe.get_data(td_rva, 64)
                    name_bytes = td_data[12:]
                    name = name_bytes.split(b"\x00", 1)[0].decode(
                        "ascii", errors="replace")
                    types.append(name)
                return "; ".join(types) if types else None
    return None


def cmd_info(dump: MinidumpFile, _args):
    modules = _build_module_map(dump)
    print(f"Modules ({len(modules)}):\n")
    for base, size, name in modules:
        short = name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        print(f"  0x{base:016X}  {size:10d}  {short}")

    exc = _get_exception_info(dump)
    if exc:
        print(f"\nException: code=0x{exc['code']:08X} "
              f"at {_resolve_addr(modules, exc['address'])} "
              f"(thread {exc['thread_id']})")


def cmd_threads(dump: MinidumpFile, _args):
    modules = _build_module_map(dump)
    if not dump.threads:
        print("No thread information.")
        return
    for t in dump.threads.threads:
        tid = t.ThreadId
        ctx = t.ContextObject
        if ctx is None:
            print(f"\nThread {tid}: no context")
            continue
        print(f"\nThread {tid}:")
        if hasattr(ctx, "Rip"):
            rip = ctx.Rip
            print(f"  RIP = 0x{rip:016X}  ({_resolve_addr(modules, rip)})")
            print(f"  RSP = 0x{ctx.Rsp:016X}  RBP = 0x{ctx.Rbp:016X}")
            print(f"  RAX = 0x{ctx.Rax:016X}  RBX = 0x{ctx.Rbx:016X}  "
                  f"RCX = 0x{ctx.Rcx:016X}  RDX = 0x{ctx.Rdx:016X}")
            print(f"  RSI = 0x{ctx.Rsi:016X}  RDI = 0x{ctx.Rdi:016X}  "
                  f"R8  = 0x{ctx.R8:016X}  R9  = 0x{ctx.R9:016X}")
        elif hasattr(ctx, "Eip"):
            eip = ctx.Eip
            print(f"  EIP = 0x{eip:08X}  ({_resolve_addr(modules, eip)})")
            print(f"  ESP = 0x{ctx.Esp:08X}  EBP = 0x{ctx.Ebp:08X}")
            print(f"  EAX = 0x{ctx.Eax:08X}  EBX = 0x{ctx.Ebx:08X}  "
                  f"ECX = 0x{ctx.Ecx:08X}  EDX = 0x{ctx.Edx:08X}")


def cmd_stack(dump: MinidumpFile, args):
    modules = _build_module_map(dump)
    tid = int(args.thread_id)
    thread = None
    if dump.threads:
        for t in dump.threads.threads:
            if t.ThreadId == tid:
                thread = t
                break
    if thread is None:
        print(f"Thread {tid} not found.")
        return

    ctx = thread.ContextObject
    if ctx is None:
        print("No context for this thread.")
        return

    is_64 = hasattr(ctx, "Rip")
    sp = ctx.Rsp if is_64 else ctx.Esp
    ptr_size = 8 if is_64 else 4
    ptr_fmt = "<Q" if is_64 else "<I"
    w = 16 if is_64 else 8
    depth = int(args.depth) if hasattr(args, "depth") and args.depth else 64

    exec_ranges = set()
    for base, size, name in modules:
        try:
            pe = pefile.PE(name, fast_load=True)
            for s in pe.sections:
                if s.Characteristics & 0x20000000:
                    sec_va = base + s.VirtualAddress
                    exec_ranges.add((sec_va, sec_va + s.Misc_VirtualSize))
        except Exception:
            exec_ranges.add((base, base + size))

    def _in_code(addr):
        return any(lo <= addr < hi for lo, hi in exec_ranges)

    print(f"Stack walk for thread {tid} (SP=0x{sp:0{w}X}):\n")
    stack_data = _read_dump_memory(dump, sp, depth * ptr_size)
    if not stack_data:
        print("  (stack memory not available in dump)")
        return

    for i in range(0, len(stack_data) - ptr_size + 1, ptr_size):
        val = struct.unpack_from(ptr_fmt, stack_data, i)[0]
        addr = sp + i
        resolved = _resolve_addr(modules, val) if _in_code(val) else ""
        tag = " <-- RET" if resolved and "+" in resolved else ""
        if resolved:
            print(f"  0x{addr:0{w}X}: 0x{val:0{w}X}  {resolved}{tag}")
        else:
            print(f"  0x{addr:0{w}X}: 0x{val:0{w}X}")


def cmd_exception(dump: MinidumpFile, _args):
    modules = _build_module_map(dump)
    exc = _get_exception_info(dump)
    if not exc:
        print("No exception record in dump.")
        return

    print(f"Exception code:    0x{exc['code']:08X}")
    print(f"Exception address: 0x{exc['address']:016X}  "
          f"({_resolve_addr(modules, exc['address'])})")
    print(f"Thread ID:         {exc['thread_id']}")
    print(f"Parameters ({exc['num_params']}):")
    for i, p in enumerate(exc["params"][:exc["num_params"]]):
        print(f"  [{i}] 0x{p:016X}")

    if exc["code"] == 0xE06D7363:
        print("\nMSVC C++ exception (_CxxThrowException)")
        type_name = _resolve_msvc_exception(modules, dump, exc)
        if type_name:
            print(f"  Type: {type_name}")
        else:
            print("  (could not resolve type -- module/PE not accessible)")


def cmd_read(dump: MinidumpFile, args):
    addr = int(args.address, 16)
    type_map = {
        "uint8": ("<B", 1), "int8": ("<b", 1),
        "uint16": ("<H", 2), "int16": ("<h", 2),
        "uint32": ("<I", 4), "int32": ("<i", 4),
        "uint64": ("<Q", 8), "int64": ("<q", 8),
        "float": ("<f", 4), "double": ("<d", 8),
        "ptr32": ("<I", 4), "ptr64": ("<Q", 8),
    }
    if args.type == "bytes":
        size = int(args.count) if args.count else 64
        data = _read_dump_memory(dump, addr, size)
        if not data:
            print(f"Cannot read {size} bytes at 0x{addr:X}")
            return
        for off in range(0, len(data), 16):
            chunk = data[off : off + 16]
            hex_str = " ".join(f"{b:02X}" for b in chunk)
            ascii_str = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            print(f"  0x{addr + off:016X}: {hex_str:<48s} {ascii_str}")
        return

    if args.type not in type_map:
        print(f"Unknown type '{args.type}'. "
              f"Valid: {', '.join(sorted(type_map))} bytes")
        return
    fmt, size = type_map[args.type]
    data = _read_dump_memory(dump, addr, size)
    if len(data) < size:
        print(f"Cannot read {size} bytes at 0x{addr:X}")
        return
    val = struct.unpack(fmt, data)[0]
    if isinstance(val, float):
        print(f"0x{addr:016X}: {val}")
    else:
        print(f"0x{addr:016X}: {val}  (0x{val:X})")


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("dumpfile", help="Path to minidump (.dmp) file")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="Modules and exception summary")

    sub.add_parser("threads", help="All threads with registers")

    s = sub.add_parser("stack", help="Stack walk for a thread")
    s.add_argument("thread_id", help="Thread ID (decimal)")
    s.add_argument("--depth", type=int, default=64,
                   help="Number of stack slots to scan (default: 64)")

    sub.add_parser("exception", help="Exception record with C++ type decoding")

    s = sub.add_parser("read", help="Read typed data from dump memory")
    s.add_argument("address", help="Virtual address in hex")
    s.add_argument("type",
                   help="Data type: uint8/16/32/64, int8/16/32/64, "
                        "float, double, ptr32, ptr64, bytes")
    s.add_argument("--count", help="Byte count (for 'bytes' type, default: 64)")

    args = p.parse_args()
    dump = _load_dump(args.dumpfile)
    {"info": cmd_info, "threads": cmd_threads, "stack": cmd_stack,
     "exception": cmd_exception, "read": cmd_read}[args.command](dump, args)


if __name__ == "__main__":
    main()
