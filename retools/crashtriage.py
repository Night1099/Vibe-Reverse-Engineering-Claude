#!/usr/bin/env python3
"""Batch crash triage for fuzzer output.

Processes a directory of minidump (.dmp) files, deduplicates crashes by
exception address and type, classifies exploitability, and produces a
prioritized report. Designed for Acrobat Reader and similar PDF parser
fuzzing campaigns.

Sub-commands:

  triage     Process crash directory, deduplicate, classify, rank
  watch      Monitor directory for new crashes and triage on arrival
  report     Re-read a saved triage JSON and print summary

Usage:
    python -m retools.crashtriage triage <crash_dir> [--binary path] [--output report.json]
    python -m retools.crashtriage watch <crash_dir> [--binary path] [--interval 10]
    python -m retools.crashtriage report <report.json>

Examples:
    python -m retools.crashtriage triage ./crashes --binary AcroRd32.exe
    python -m retools.crashtriage triage ./crashes --binary AcroRd32.exe --output results.json
    python -m retools.crashtriage watch ./crashes --binary AcroRd32.exe --interval 5
    python -m retools.crashtriage report results.json
"""

import argparse
import hashlib
import json
import struct
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

try:
    from minidump.minidumpfile import MinidumpFile
except ImportError:
    sys.exit("minidump not installed. Run: pip install minidump")

import pefile


# ── Exception code classification ────────────────────────────────────

_EXCEPTION_NAMES: dict[int, str] = {
    0xC0000005: "ACCESS_VIOLATION",
    0xC0000006: "IN_PAGE_ERROR",
    0xC0000008: "INVALID_HANDLE",
    0xC000000D: "INVALID_PARAMETER",
    0xC0000017: "NO_MEMORY",
    0xC000001D: "ILLEGAL_INSTRUCTION",
    0xC0000025: "NONCONTINUABLE_EXCEPTION",
    0xC0000026: "INVALID_DISPOSITION",
    0xC000005E: "UNWIND_CONSOLIDATE",
    0xC00000FD: "STACK_OVERFLOW",
    0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
    0xC0000095: "INTEGER_OVERFLOW",
    0xC0000096: "PRIVILEGED_INSTRUCTION",
    0xC000008C: "ARRAY_BOUNDS_EXCEEDED",
    0xC000008D: "FLOAT_DENORMAL_OPERAND",
    0xC000008E: "FLOAT_DIVIDE_BY_ZERO",
    0xC000008F: "FLOAT_INEXACT_RESULT",
    0xC0000090: "FLOAT_INVALID_OPERATION",
    0xC0000091: "FLOAT_OVERFLOW",
    0xC0000092: "FLOAT_STACK_CHECK",
    0xC0000093: "FLOAT_UNDERFLOW",
    0x80000003: "BREAKPOINT",
    0x80000004: "SINGLE_STEP",
    0xE06D7363: "CPP_EXCEPTION",
    0x40010006: "DBG_PRINTEXCEPTION_C",
    0x4001000A: "DBG_PRINTEXCEPTION_WIDE_C",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",   # /GS cookie violation
    0xC0000374: "STATUS_HEAP_CORRUPTION",
}

# Exploitability classification
_EXPLOITABILITY: dict[str, str] = {
    "write_av_controlled":       "EXPLOITABLE",
    "write_av_near_null":        "PROBABLY_EXPLOITABLE",
    "write_av":                  "PROBABLY_EXPLOITABLE",
    "read_av_controlled":        "PROBABLY_EXPLOITABLE",
    "read_av_near_null":         "NOT_LIKELY_EXPLOITABLE",
    "read_av":                   "UNKNOWN",
    "heap_corruption":           "EXPLOITABLE",
    "stack_buffer_overrun":      "EXPLOITABLE",
    "illegal_instruction":       "PROBABLY_EXPLOITABLE",
    "stack_overflow":            "NOT_LIKELY_EXPLOITABLE",
    "integer_divide_by_zero":    "NOT_LIKELY_EXPLOITABLE",
    "cpp_exception":             "NOT_LIKELY_EXPLOITABLE",
    "breakpoint":                "NOT_LIKELY_EXPLOITABLE",
    "unknown":                   "UNKNOWN",
}

_EXPLOIT_RANK = {
    "EXPLOITABLE": 0,
    "PROBABLY_EXPLOITABLE": 1,
    "UNKNOWN": 2,
    "NOT_LIKELY_EXPLOITABLE": 3,
}


@dataclass
class CrashInfo:
    """Parsed crash information from a single minidump."""
    path: str
    exception_code: int
    exception_name: str
    exception_address: int
    faulting_module: str
    faulting_offset: int
    access_type: str       # "read", "write", "execute", "none"
    access_address: int    # for AV: target address
    exploitability: str
    exploit_reason: str
    crash_hash: str        # dedup key
    thread_id: int
    stack_trace: list[str] = field(default_factory=list)
    cpp_type: str = ""


@dataclass
class CrashBucket:
    """Group of deduplicated crashes."""
    crash_hash: str
    exploitability: str
    exploit_reason: str
    exception_name: str
    faulting_module: str
    faulting_offset: int
    count: int
    samples: list[str] = field(default_factory=list)


@dataclass
class TriageReport:
    """Full batch triage results."""
    crash_dir: str
    total_dumps: int
    total_parsed: int
    total_errors: int
    buckets: list[CrashBucket] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _load_dump(path: str) -> MinidumpFile:
    import logging
    logging.disable(logging.CRITICAL)
    try:
        return MinidumpFile.parse(path)
    finally:
        logging.disable(logging.NOTSET)


def _build_module_map(dump: MinidumpFile) -> list[tuple[int, int, str]]:
    modules = []
    if dump.modules:
        for m in dump.modules.modules:
            modules.append((m.baseaddress, m.size, m.name))
    return sorted(modules, key=lambda x: x[0])


def _resolve_addr(modules: list, addr: int) -> tuple[str, int]:
    """Resolve address to (module_name, offset). Returns ("unknown", addr) if unresolved."""
    for base, size, name in modules:
        if base <= addr < base + size:
            short = name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            return short, addr - base
    return "unknown", addr


def _classify_access_violation(exc_info: dict) -> tuple[str, int, str, str]:
    """Classify an access violation.

    Returns:
        (access_type, access_address, exploitability, reason)
    """
    params = exc_info.get("params", [])
    if len(params) < 2:
        return "unknown", 0, "UNKNOWN", "unknown"

    rw_flag = params[0]  # 0=read, 1=write, 8=execute
    target_addr = params[1]

    if rw_flag == 0:
        access_type = "read"
    elif rw_flag == 1:
        access_type = "write"
    elif rw_flag == 8:
        access_type = "execute"
    else:
        access_type = f"unknown({rw_flag})"

    near_null = target_addr < 0x10000

    if access_type == "write":
        if near_null:
            return access_type, target_addr, "PROBABLY_EXPLOITABLE", "write_av_near_null"
        return access_type, target_addr, "PROBABLY_EXPLOITABLE", "write_av"
    elif access_type == "execute":
        return access_type, target_addr, "EXPLOITABLE", "execute_av"
    elif access_type == "read":
        if near_null:
            return access_type, target_addr, "NOT_LIKELY_EXPLOITABLE", "read_av_near_null"
        return access_type, target_addr, "UNKNOWN", "read_av"
    return access_type, target_addr, "UNKNOWN", "unknown_av"


def _get_stack_trace(dump: MinidumpFile, thread_id: int,
                     modules: list, depth: int = 10) -> list[str]:
    """Extract a short stack trace for hashing and display."""
    frames = []
    if not dump.threads:
        return frames

    thread = None
    for t in dump.threads.threads:
        if t.ThreadId == thread_id:
            thread = t
            break
    if not thread or not thread.ContextObject:
        return frames

    ctx = thread.ContextObject
    is_64 = hasattr(ctx, "Rip")
    sp = ctx.Rsp if is_64 else ctx.Esp
    ptr_size = 8 if is_64 else 4
    ptr_fmt = "<Q" if is_64 else "<I"

    reader = dump.get_reader()
    for chunk_off in range(0, depth * ptr_size * 32, 4096):
        try:
            chunk = reader.read(sp + chunk_off, 4096)
        except Exception:
            continue
        for i in range(0, len(chunk) - ptr_size + 1, ptr_size):
            val = struct.unpack_from(ptr_fmt, chunk, i)[0]
            for base, size, name in modules:
                if base <= val < base + size:
                    short = name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                    frames.append(f"{short}+0x{val - base:X}")
                    break
            if len(frames) >= depth:
                return frames
    return frames


def analyze_crash(dump_path: str) -> CrashInfo:
    """Analyze a single minidump file.

    Args:
        dump_path: Path to .dmp file.

    Returns:
        CrashInfo with classification.
    """
    dump = _load_dump(dump_path)
    modules = _build_module_map(dump)

    # Extract exception
    exc_info = None
    if dump.exception and dump.exception.exception_records:
        stream = dump.exception.exception_records[0]
        rec = stream.ExceptionRecord
        code_raw = (rec.ExceptionCode_raw
                    if hasattr(rec, "ExceptionCode_raw")
                    else int(rec.ExceptionCode))
        exc_info = {
            "thread_id": stream.ThreadId,
            "code": code_raw,
            "address": rec.ExceptionAddress,
            "num_params": rec.NumberParameters,
            "params": list(rec.ExceptionInformation[:rec.NumberParameters]),
        }

    if not exc_info:
        return CrashInfo(
            path=dump_path, exception_code=0,
            exception_name="NO_EXCEPTION", exception_address=0,
            faulting_module="unknown", faulting_offset=0,
            access_type="none", access_address=0,
            exploitability="UNKNOWN", exploit_reason="no_exception",
            crash_hash="no_exception", thread_id=0,
        )

    code = exc_info["code"]
    exc_name = _EXCEPTION_NAMES.get(code, f"UNKNOWN_0x{code:08X}")
    exc_addr = exc_info["address"]
    mod_name, mod_off = _resolve_addr(modules, exc_addr)
    thread_id = exc_info["thread_id"]

    # Classify exploitability
    access_type = "none"
    access_addr = 0
    exploitability = "UNKNOWN"
    reason = "unknown"

    if code == 0xC0000005:  # ACCESS_VIOLATION
        access_type, access_addr, exploitability, reason = \
            _classify_access_violation(exc_info)
    elif code == 0xC0000374:  # HEAP_CORRUPTION
        exploitability = "EXPLOITABLE"
        reason = "heap_corruption"
    elif code == 0xC0000409:  # STACK_BUFFER_OVERRUN (/GS)
        exploitability = "EXPLOITABLE"
        reason = "stack_buffer_overrun"
    elif code == 0xC000001D:  # ILLEGAL_INSTRUCTION
        exploitability = "PROBABLY_EXPLOITABLE"
        reason = "illegal_instruction"
    elif code == 0xC00000FD:  # STACK_OVERFLOW
        exploitability = "NOT_LIKELY_EXPLOITABLE"
        reason = "stack_overflow"
    elif code == 0xC0000094:  # INTEGER_DIVIDE_BY_ZERO
        exploitability = "NOT_LIKELY_EXPLOITABLE"
        reason = "integer_divide_by_zero"
    elif code == 0xE06D7363:  # C++ EXCEPTION
        exploitability = "NOT_LIKELY_EXPLOITABLE"
        reason = "cpp_exception"

    # Stack trace for dedup
    stack = _get_stack_trace(dump, thread_id, modules, depth=5)

    # Crash hash: module + offset + exception type + top 3 frames
    hash_input = f"{mod_name}+0x{mod_off:X}:{code:08X}:" + ":".join(stack[:3])
    crash_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    return CrashInfo(
        path=dump_path,
        exception_code=code,
        exception_name=exc_name,
        exception_address=exc_addr,
        faulting_module=mod_name,
        faulting_offset=mod_off,
        access_type=access_type,
        access_address=access_addr,
        exploitability=exploitability,
        exploit_reason=reason,
        crash_hash=crash_hash,
        thread_id=thread_id,
        stack_trace=stack,
    )


def triage_directory(crash_dir: str, binary: str | None = None) -> TriageReport:
    """Process all .dmp files in a directory.

    Args:
        crash_dir: Directory containing minidump files.
        binary: Optional PE binary path for throw-site matching.

    Returns:
        TriageReport with deduplicated, ranked crash buckets.
    """
    crash_path = Path(crash_dir)
    dumps = sorted(crash_path.glob("**/*.dmp"))

    report = TriageReport(
        crash_dir=str(crash_dir),
        total_dumps=len(dumps),
        total_parsed=0,
        total_errors=0,
    )

    # Analyze each dump
    crashes: list[CrashInfo] = []
    for dump_path in dumps:
        try:
            info = analyze_crash(str(dump_path))
            crashes.append(info)
            report.total_parsed += 1
        except Exception as e:
            report.total_errors += 1
            report.errors.append(f"{dump_path.name}: {e}")

    # Deduplicate into buckets
    buckets: dict[str, list[CrashInfo]] = {}
    for crash in crashes:
        buckets.setdefault(crash.crash_hash, []).append(crash)

    for crash_hash, group in buckets.items():
        representative = group[0]
        report.buckets.append(CrashBucket(
            crash_hash=crash_hash,
            exploitability=representative.exploitability,
            exploit_reason=representative.exploit_reason,
            exception_name=representative.exception_name,
            faulting_module=representative.faulting_module,
            faulting_offset=representative.faulting_offset,
            count=len(group),
            samples=[c.path for c in group[:5]],
        ))

    # Sort by exploitability (most exploitable first), then by count
    report.buckets.sort(
        key=lambda b: (_EXPLOIT_RANK.get(b.exploitability, 99), -b.count)
    )

    return report


def format_report(report: TriageReport) -> str:
    """Format TriageReport as human-readable output."""
    lines = [
        f"  Crash Directory: {report.crash_dir}",
        f"  Total dumps:     {report.total_dumps}",
        f"  Parsed:          {report.total_parsed}",
        f"  Errors:          {report.total_errors}",
        f"  Unique crashes:  {len(report.buckets)}",
        "",
    ]

    if report.errors:
        lines.append("  Parse errors:")
        for e in report.errors[:10]:
            lines.append(f"    {e}")
        if len(report.errors) > 10:
            lines.append(f"    ... and {len(report.errors) - 10} more")
        lines.append("")

    # Color-coded exploitability
    colors = {
        "EXPLOITABLE": "\033[91m",
        "PROBABLY_EXPLOITABLE": "\033[93m",
        "UNKNOWN": "\033[90m",
        "NOT_LIKELY_EXPLOITABLE": "\033[90m",
    }
    reset = "\033[0m"

    lines.append(f"  {'#':<4s} {'Exploit':<25s} {'Exception':<28s} "
                 f"{'Module+Offset':<30s} {'Count':<6s} Hash")
    lines.append("  " + "-" * 105)

    for i, bucket in enumerate(report.buckets):
        color = colors.get(bucket.exploitability, "")
        mod_off = f"{bucket.faulting_module}+0x{bucket.faulting_offset:X}"
        lines.append(
            f"  {i + 1:<4d} {color}{bucket.exploitability:<25s}{reset} "
            f"{bucket.exception_name:<28s} {mod_off:<30s} "
            f"{bucket.count:<6d} {bucket.crash_hash}"
        )

    # Summary by exploitability
    lines.append("")
    exploit_counts: dict[str, int] = {}
    for b in report.buckets:
        exploit_counts[b.exploitability] = exploit_counts.get(b.exploitability, 0) + 1
    lines.append("  Summary:")
    for label in ["EXPLOITABLE", "PROBABLY_EXPLOITABLE", "UNKNOWN", "NOT_LIKELY_EXPLOITABLE"]:
        count = exploit_counts.get(label, 0)
        if count:
            color = colors.get(label, "")
            lines.append(f"    {color}{label}: {count} unique crashes{reset}")

    return "\n".join(lines)


def cmd_triage(args):
    report = triage_directory(args.crash_dir, binary=args.binary)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(asdict(report), f, indent=2)
        print(f"  Report saved to {args.output}")
        print()

    print(format_report(report))


def cmd_watch(args):
    """Monitor a directory for new crash dumps and triage on arrival."""
    crash_dir = Path(args.crash_dir)
    seen: set[str] = set()
    interval = args.interval

    # Initial scan
    for p in crash_dir.glob("**/*.dmp"):
        seen.add(str(p))

    print(f"  Watching {crash_dir} for new .dmp files (interval: {interval}s)")
    print(f"  {len(seen)} existing dumps skipped. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(interval)
            for p in crash_dir.glob("**/*.dmp"):
                sp = str(p)
                if sp in seen:
                    continue
                seen.add(sp)

                try:
                    info = analyze_crash(sp)
                    color = {
                        "EXPLOITABLE": "\033[91m",
                        "PROBABLY_EXPLOITABLE": "\033[93m",
                    }.get(info.exploitability, "\033[90m")
                    reset = "\033[0m"

                    print(f"  NEW: {p.name}")
                    print(f"    {color}{info.exploitability}{reset} | "
                          f"{info.exception_name} | "
                          f"{info.faulting_module}+0x{info.faulting_offset:X} | "
                          f"{info.exploit_reason}")
                    if info.stack_trace:
                        print(f"    Stack: {' -> '.join(info.stack_trace[:3])}")
                    print()
                except Exception as e:
                    print(f"  ERROR: {p.name}: {e}\n")
    except KeyboardInterrupt:
        print("\n  Stopped watching.")


def cmd_report(args):
    """Re-read a saved triage JSON and print summary."""
    with open(args.report_file) as f:
        data = json.load(f)

    report = TriageReport(
        crash_dir=data["crash_dir"],
        total_dumps=data["total_dumps"],
        total_parsed=data["total_parsed"],
        total_errors=data["total_errors"],
        errors=data.get("errors", []),
    )
    for b in data.get("buckets", []):
        report.buckets.append(CrashBucket(**b))

    print(format_report(report))


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("triage", help="Batch triage crash directory")
    s.add_argument("crash_dir", help="Directory containing .dmp files")
    s.add_argument("--binary", help="PE binary for throw-site matching")
    s.add_argument("--output", "-o", help="Save report as JSON")

    s = sub.add_parser("watch", help="Monitor directory for new crashes")
    s.add_argument("crash_dir", help="Directory to monitor")
    s.add_argument("--binary", help="PE binary for throw-site matching")
    s.add_argument("--interval", type=int, default=10,
                   help="Poll interval in seconds (default: 10)")

    s = sub.add_parser("report", help="Display a saved triage report")
    s.add_argument("report_file", help="JSON report file from triage --output")

    args = p.parse_args()
    {"triage": cmd_triage, "watch": cmd_watch, "report": cmd_report}[args.command](args)


if __name__ == "__main__":
    main()
