#!/usr/bin/env python3
"""Scan PE binaries for dangerous API usage patterns and potential vulnerabilities.

Finds calls to known-dangerous functions (memcpy, strcpy, sprintf, etc.),
shows disassembly context around each call site, and classifies risk level.
Tuned for Adobe Acrobat Reader and similar C/C++ desktop software.

Sub-commands:

  scan       Full vulnerability pattern scan
  imports    Quick check: list dangerous imports present
  callers    Find all call sites to a specific dangerous function

Usage:
    python -m retools.vulnscan <binary> scan [--risk high|medium|all] [--limit N]
    python -m retools.vulnscan <binary> imports
    python -m retools.vulnscan <binary> callers <function_name>

Examples:
    python -m retools.vulnscan AcroRd32.exe scan
    python -m retools.vulnscan AcroRd32.exe scan --risk high --limit 50
    python -m retools.vulnscan Acrobat.dll imports
    python -m retools.vulnscan AcroRd32.exe callers memcpy
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary
from search import find_imports

CHUNK = 0x10000


# ── Dangerous function database ─────────────────────────────────────
# Each entry: (name, risk, vuln_class, description)
# Risk: "high" = commonly exploitable, "medium" = exploitable with effort

DANGEROUS_FUNCTIONS: list[tuple[str, str, str, str]] = [
    # Memory copy — buffer overflow
    ("memcpy",       "high",   "buffer-overflow",  "Unbounded memory copy"),
    ("memmove",      "medium", "buffer-overflow",  "Memory move — check size source"),
    ("RtlCopyMemory","high",   "buffer-overflow",  "Kernel-style unbounded copy"),
    ("RtlMoveMemory","medium", "buffer-overflow",  "Kernel-style memory move"),
    ("CopyMemory",   "high",   "buffer-overflow",  "Unbounded memory copy (macro)"),

    # String copy — buffer overflow
    ("strcpy",       "high",   "buffer-overflow",  "Unbounded string copy"),
    ("strncpy",      "medium", "buffer-overflow",  "May not null-terminate"),
    ("wcscpy",       "high",   "buffer-overflow",  "Wide-char unbounded copy"),
    ("wcsncpy",      "medium", "buffer-overflow",  "Wide-char copy — check bounds"),
    ("lstrcpyA",     "high",   "buffer-overflow",  "Win32 unbounded string copy"),
    ("lstrcpyW",     "high",   "buffer-overflow",  "Win32 unbounded wide copy"),
    ("_mbscpy",      "high",   "buffer-overflow",  "MBCS unbounded copy"),

    # String concatenation — buffer overflow
    ("strcat",       "high",   "buffer-overflow",  "Unbounded concatenation"),
    ("strncat",      "medium", "buffer-overflow",  "Check remaining buffer space"),
    ("wcscat",       "high",   "buffer-overflow",  "Wide-char unbounded concat"),
    ("lstrcatA",     "high",   "buffer-overflow",  "Win32 unbounded concat"),
    ("lstrcatW",     "high",   "buffer-overflow",  "Win32 wide unbounded concat"),

    # Format strings — format string injection / overflow
    ("sprintf",      "high",   "format-string",    "Unbounded format + no length limit"),
    ("vsprintf",     "high",   "format-string",    "Unbounded variadic format"),
    ("swprintf",     "medium", "format-string",    "Wide format — check buffer size"),
    ("_snprintf",    "medium", "format-string",    "Returns -1 on truncation (MSVC)"),
    ("_vsnprintf",   "medium", "format-string",    "Variadic — returns -1 on truncation"),
    ("wvsprintfA",   "high",   "format-string",    "Win32 format — no length param"),
    ("wvsprintfW",   "high",   "format-string",    "Win32 wide format — no length param"),
    ("wsprintfA",    "high",   "format-string",    "Win32 format — no length param"),
    ("wsprintfW",    "high",   "format-string",    "Win32 wide format — no length param"),
    ("printf",       "medium", "format-string",    "Format string if user-controlled"),
    ("fprintf",      "medium", "format-string",    "File format string"),
    ("wprintf",      "medium", "format-string",    "Wide format string"),

    # Dangerous input — buffer overflow / injection
    ("gets",         "high",   "buffer-overflow",  "No bounds checking at all"),
    ("scanf",        "medium", "buffer-overflow",  "Unbounded %s reads"),
    ("sscanf",       "medium", "buffer-overflow",  "Unbounded %s from string"),
    ("fscanf",       "medium", "buffer-overflow",  "Unbounded %s from file"),
    ("wscanf",       "medium", "buffer-overflow",  "Wide unbounded scan"),

    # Integer overflow in allocation
    ("malloc",       "medium", "integer-overflow", "Check for integer overflow in size calc"),
    ("calloc",       "medium", "integer-overflow", "n*size may overflow"),
    ("realloc",      "medium", "integer-overflow", "New size from untrusted source"),
    ("HeapAlloc",    "medium", "integer-overflow", "Heap alloc — check size"),
    ("VirtualAlloc", "medium", "integer-overflow", "Large alloc — check size param"),
    ("LocalAlloc",   "medium", "integer-overflow", "Local alloc — check size"),
    ("GlobalAlloc",  "medium", "integer-overflow", "Global alloc — check size"),
    ("CoTaskMemAlloc","medium","integer-overflow", "COM alloc — check size"),

    # Use-after-free / double-free indicators
    ("free",         "medium", "use-after-free",   "Potential double-free or UAF"),
    ("HeapFree",     "medium", "use-after-free",   "Heap free — check double-free"),
    ("CoTaskMemFree","medium", "use-after-free",   "COM free — check double-free"),

    # Command / code execution
    ("system",       "high",   "command-injection","Shell command execution"),
    ("_popen",       "high",   "command-injection","Piped command execution"),
    ("WinExec",      "high",   "command-injection","Legacy process creation"),
    ("ShellExecuteA","high",   "command-injection","Shell execute — check params"),
    ("ShellExecuteW","high",   "command-injection","Shell execute — check params"),
    ("CreateProcessA","medium","command-injection","Process creation"),
    ("CreateProcessW","medium","command-injection","Process creation"),

    # File operations — path traversal
    ("CreateFileA",  "medium", "path-traversal",   "File open — check path sanitization"),
    ("CreateFileW",  "medium", "path-traversal",   "File open — check path sanitization"),
    ("DeleteFileA",  "medium", "path-traversal",   "File delete — check path"),
    ("DeleteFileW",  "medium", "path-traversal",   "File delete — check path"),
    ("MoveFileA",    "medium", "path-traversal",   "File move — check both paths"),
    ("MoveFileW",    "medium", "path-traversal",   "File move — check both paths"),

    # Crypto — weak primitives
    ("CryptEncrypt", "medium", "weak-crypto",      "Check algorithm selection"),
    ("MD5Init",      "high",   "weak-crypto",      "MD5 is broken for security use"),
    ("MD5Update",    "high",   "weak-crypto",      "MD5 is broken for security use"),
    ("SHA1Init",     "medium", "weak-crypto",      "SHA1 collision attacks practical"),

    # Deserialization / parsing — Acrobat-relevant
    ("MultiByteToWideChar", "medium", "buffer-overflow",
     "Output buffer size from untrusted length"),
    ("WideCharToMultiByte", "medium", "buffer-overflow",
     "Output buffer size from untrusted length"),

    # Registry — privilege escalation
    ("RegSetValueExA",  "medium", "privilege-escalation", "Registry write"),
    ("RegSetValueExW",  "medium", "privilege-escalation", "Registry write"),

    # Network — remote attack surface (Acrobat has network features)
    ("recv",         "medium", "remote-input",     "Network input — trace to parsers"),
    ("recvfrom",     "medium", "remote-input",     "Network input — trace to parsers"),
    ("InternetReadFile", "medium", "remote-input",  "HTTP input — trace to parsers"),
    ("URLDownloadToFileA","medium","remote-input",  "Download — check URL source"),
    ("URLDownloadToFileW","medium","remote-input",  "Download — check URL source"),
    ("InternetOpenUrlA", "medium", "remote-input",  "URL open — check URL source"),
    ("InternetOpenUrlW", "medium", "remote-input",  "URL open — check URL source"),
]

# Build lookup by function name
_FUNC_DB: dict[str, tuple[str, str, str]] = {
    name: (risk, vuln_class, desc)
    for name, risk, vuln_class, desc in DANGEROUS_FUNCTIONS
}


@dataclass
class VulnHit:
    """A single dangerous function call site."""
    va: int
    func_name: str
    risk: str
    vuln_class: str
    description: str
    context: list[str] = field(default_factory=list)


@dataclass
class VulnReport:
    """Full scan results for a binary."""
    path: str
    arch: str
    dangerous_imports: list[str] = field(default_factory=list)
    hits: list[VulnHit] = field(default_factory=list)

    @property
    def high_count(self) -> int:
        return sum(1 for h in self.hits if h.risk == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for h in self.hits if h.risk == "medium")


def _resolve_import_thunks(b: Binary) -> dict[int, str]:
    """Map IAT entry addresses to function names for call [addr] resolution."""
    thunks: dict[int, str] = {}
    if not hasattr(b.pe, "DIRECTORY_ENTRY_IMPORT"):
        return thunks
    for entry in b.pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            name = (imp.name.decode("ascii", errors="ignore")
                    if imp.name else f"ordinal_{imp.ordinal}")
            if name in _FUNC_DB:
                thunks[imp.address] = name
    return thunks


def _find_call_targets(b: Binary) -> dict[int, str]:
    """Build a map of VA -> function name for dangerous functions.

    Finds both IAT thunk calls and direct call targets that jump to IAT.
    """
    thunks = _resolve_import_thunks(b)
    targets: dict[int, str] = {}

    # IAT entries
    for addr, name in thunks.items():
        targets[addr] = name

    # Find jmp [IAT] trampolines (common in MSVC-compiled code)
    for sec_va, sec_off, sec_size in b.exec_ranges():
        data = b.raw[sec_off:sec_off + sec_size]
        for i in range(len(data) - 5):
            # FF 25 xx xx xx xx = jmp [addr] (32-bit absolute)
            if data[i] == 0xFF and data[i + 1] == 0x25:
                if b.is_64:
                    # RIP-relative
                    rip = sec_va + i + 6
                    disp = int.from_bytes(data[i + 2:i + 6], "little", signed=True)
                    iat_addr = rip + disp
                else:
                    iat_addr = int.from_bytes(data[i + 2:i + 6], "little")
                if iat_addr in thunks:
                    trampoline_va = sec_va + i
                    targets[trampoline_va] = thunks[iat_addr]

    return targets


def _disasm_context(b: Binary, call_va: int, before: int = 5, after: int = 2) -> list[str]:
    """Get disassembly context around a call site."""
    w = 16 if b.is_64 else 8
    # Start a bit before the call to show arg setup
    start = max(call_va - before * 6, 0)
    insns = b.disasm(start, count=before + after + 5)
    lines = []
    for insn in insns:
        marker = " >>>" if insn.address == call_va else "    "
        lines.append(f"{marker} 0x{insn.address:0{w}X}  {insn.mnemonic:8s} {insn.op_str}")
        if insn.address > call_va and len(lines) > before + after + 1:
            break
    return lines


def scan_dangerous_calls(b: Binary, risk_filter: str = "all",
                         limit: int = 0) -> VulnReport:
    """Scan for all calls to dangerous functions with context.

    Args:
        b: Loaded PE binary.
        risk_filter: "high", "medium", or "all".
        limit: Max hits to return (0 = unlimited).

    Returns:
        VulnReport with all findings.
    """
    report = VulnReport(
        path=str(b.pe.filename if hasattr(b.pe, 'filename') else ''),
        arch="x64" if b.is_64 else "x86",
    )

    # Check which dangerous functions are imported
    for imp in find_imports(b):
        if imp.name in _FUNC_DB:
            report.dangerous_imports.append(imp.name)

    # Build target map
    targets = _find_call_targets(b)
    iat_thunks = _resolve_import_thunks(b)

    # Scan all executable sections for calls
    hit_count = 0
    for sec_va, sec_off, sec_size in b.exec_ranges():
        data = b.raw[sec_off:sec_off + sec_size]
        for i in range(sec_size - 5):
            va = sec_va + i

            func_name = None

            # E8 rel32 = direct call
            if data[i] == 0xE8:
                rel = int.from_bytes(data[i + 1:i + 5], "little", signed=True)
                dest = va + 5 + rel
                if dest in targets:
                    func_name = targets[dest]

            # FF 15 = call [addr] (IAT call)
            elif data[i] == 0xFF and data[i + 1] == 0x15:
                if b.is_64:
                    rip = va + 6
                    disp = int.from_bytes(data[i + 2:i + 6], "little", signed=True)
                    iat_addr = rip + disp
                else:
                    iat_addr = int.from_bytes(data[i + 2:i + 6], "little")
                if iat_addr in iat_thunks:
                    func_name = iat_thunks[iat_addr]

            if func_name is None:
                continue

            risk, vuln_class, desc = _FUNC_DB[func_name]
            if risk_filter != "all" and risk != risk_filter:
                continue

            hit = VulnHit(
                va=va,
                func_name=func_name,
                risk=risk,
                vuln_class=vuln_class,
                description=desc,
                context=_disasm_context(b, va),
            )
            report.hits.append(hit)
            hit_count += 1
            if limit and hit_count >= limit:
                return report

    return report


def format_report(report: VulnReport) -> str:
    """Format VulnReport as human-readable output."""
    w = 16 if report.arch == "x64" else 8
    lines = [
        f"  Binary: {report.path}",
        f"  Arch:   {report.arch}",
        f"  Dangerous imports: {len(report.dangerous_imports)}",
        f"  Call sites found:  {len(report.hits)} "
        f"(\033[91m{report.high_count} high\033[0m, "
        f"\033[93m{report.medium_count} medium\033[0m)",
        "",
    ]

    if report.dangerous_imports:
        lines.append("  Dangerous imports present:")
        for name in sorted(set(report.dangerous_imports)):
            risk, vuln_class, _ = _FUNC_DB[name]
            color = "\033[91m" if risk == "high" else "\033[93m"
            lines.append(f"    {color}{risk:6s}\033[0m  {name:30s}  [{vuln_class}]")
        lines.append("")

    # Group hits by vulnerability class
    by_class: dict[str, list[VulnHit]] = {}
    for hit in report.hits:
        by_class.setdefault(hit.vuln_class, []).append(hit)

    for vuln_class, hits in sorted(by_class.items()):
        lines.append(f"  ── {vuln_class} ({len(hits)} sites) ──")
        for hit in hits[:20]:  # Cap display per class
            color = "\033[91m" if hit.risk == "high" else "\033[93m"
            lines.append(
                f"  {color}[{hit.risk:6s}]\033[0m 0x{hit.va:0{w}X}  "
                f"{hit.func_name:20s}  {hit.description}"
            )
            for ctx_line in hit.context:
                lines.append(f"          {ctx_line}")
            lines.append("")
        if len(hits) > 20:
            lines.append(f"  ... and {len(hits) - 20} more {vuln_class} sites")
            lines.append("")

    return "\n".join(lines)


def cmd_scan(b: Binary, args):
    report = scan_dangerous_calls(b, risk_filter=args.risk, limit=args.limit)
    if args.json:
        import dataclasses
        print(json.dumps(dataclasses.asdict(report), indent=2, default=str))
    else:
        print(format_report(report))


def cmd_imports(b: Binary, args):
    dangerous = []
    for imp in find_imports(b):
        if imp.name in _FUNC_DB:
            risk, vuln_class, desc = _FUNC_DB[imp.name]
            dangerous.append((imp.dll, imp.name, risk, vuln_class, desc))

    if not dangerous:
        print("  No dangerous function imports found.")
        return

    print(f"  {len(dangerous)} dangerous imports:\n")
    for dll, name, risk, vuln_class, desc in sorted(dangerous, key=lambda x: (x[2], x[1])):
        color = "\033[91m" if risk == "high" else "\033[93m"
        print(f"  {color}{risk:6s}\033[0m  {dll:25s}  {name:30s}  [{vuln_class}] {desc}")


def cmd_callers(b: Binary, args):
    func_name = args.function
    if func_name not in _FUNC_DB:
        print(f"  Warning: '{func_name}' not in dangerous function database. Scanning anyway.")
        # Add a temporary entry
        _FUNC_DB[func_name] = ("unknown", "unknown", "User-specified function")

    # Find all call sites to this specific function
    targets = _find_call_targets(b)
    iat_thunks = _resolve_import_thunks(b)

    w = 16 if b.is_64 else 8
    hits = []

    for sec_va, sec_off, sec_size in b.exec_ranges():
        data = b.raw[sec_off:sec_off + sec_size]
        for i in range(sec_size - 5):
            va = sec_va + i
            found_name = None

            if data[i] == 0xE8:
                rel = int.from_bytes(data[i + 1:i + 5], "little", signed=True)
                dest = va + 5 + rel
                if dest in targets and targets[dest] == func_name:
                    found_name = func_name

            elif data[i] == 0xFF and data[i + 1] == 0x15:
                if b.is_64:
                    rip = va + 6
                    disp = int.from_bytes(data[i + 2:i + 6], "little", signed=True)
                    iat_addr = rip + disp
                else:
                    iat_addr = int.from_bytes(data[i + 2:i + 6], "little")
                if iat_addr in iat_thunks and iat_thunks[iat_addr] == func_name:
                    found_name = func_name

            if found_name:
                hits.append((va, _disasm_context(b, va)))

    print(f"  {len(hits)} call sites to {func_name}:\n")
    for va, ctx in hits:
        print(f"  0x{va:0{w}X}:")
        for line in ctx:
            print(f"    {line}")
        print()


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Full vulnerability pattern scan")
    s.add_argument("--risk", choices=["high", "medium", "all"], default="all",
                   help="Filter by risk level (default: all)")
    s.add_argument("--limit", type=int, default=0,
                   help="Max results (0 = unlimited)")
    s.add_argument("--json", action="store_true", help="Output as JSON")

    sub.add_parser("imports", help="List dangerous imports present")

    s = sub.add_parser("callers", help="Find call sites to a dangerous function")
    s.add_argument("function", help="Function name (e.g., memcpy, sprintf)")

    args = p.parse_args()
    b = Binary(args.binary)
    {"scan": cmd_scan, "imports": cmd_imports, "callers": cmd_callers}[args.command](b, args)


if __name__ == "__main__":
    main()
