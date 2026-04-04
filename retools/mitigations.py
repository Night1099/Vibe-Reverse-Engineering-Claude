#!/usr/bin/env python3
"""Check PE binary security mitigations.

Reports the presence or absence of exploit mitigations: ASLR, DEP/NX,
CFG (Control Flow Guard), SafeSEH, stack cookies (/GS), high-entropy
ASLR, and Authenticode signatures. Designed for bounty triage — quickly
assess how hard exploitation will be after finding a bug.

Usage:
    python -m retools.mitigations <binary>
    python -m retools.mitigations <binary> --json
    python -m retools.mitigations <dir> --recursive

Examples:
    python -m retools.mitigations AcroRd32.exe
    python -m retools.mitigations "C:/Program Files/Adobe/Acrobat Reader/" --recursive
    python -m retools.mitigations Acrobat.dll --json
"""

import argparse
import json
import struct
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

import pefile


# ── PE flag constants ────────────────────────────────────────────────

# DllCharacteristics flags
_DYNAMIC_BASE = 0x0040          # ASLR
_HIGH_ENTROPY_VA = 0x0020       # High-entropy 64-bit ASLR
_NX_COMPAT = 0x0100             # DEP/NX
_NO_SEH = 0x0400                # No structured exception handling
_GUARD_CF = 0x4000              # Control Flow Guard
_NO_ISOLATION = 0x0200          # No isolation
_NO_BIND = 0x0800               # No binding
_APPCONTAINER = 0x1000          # AppContainer
_FORCE_INTEGRITY = 0x0080       # Force code integrity

# IMAGE_LOAD_CONFIG guard flags
_GUARD_CF_INSTRUMENTED = 0x00000100
_GUARD_CFW_INSTRUMENTED = 0x00000200
_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x00000400
_GUARD_SECURITY_COOKIE_UNUSED = 0x00000800
_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 0x00002000
_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT = 0x00004000
_GUARD_CF_ENABLE_EXPORT_SUPPRESSION = 0x00008000
_GUARD_CF_LONGJUMP_TABLE_PRESENT = 0x00010000
_GUARD_RF_INSTRUMENTED = 0x00020000          # Return Flow Guard
_GUARD_RF_ENABLE = 0x00040000
_GUARD_RF_STRICT = 0x00080000
_GUARD_RETPOLINE_PRESENT = 0x00100000
_GUARD_EH_CONTINUATION_TABLE_PRESENT = 0x00400000
_GUARD_XFG_ENABLED = 0x00800000              # eXtended Flow Guard


@dataclass
class Mitigation:
    """Single mitigation check result."""
    name: str
    enabled: bool
    detail: str = ""


@dataclass
class MitigationReport:
    """Full mitigation report for a PE binary."""
    path: str
    arch: str
    mitigations: list[Mitigation] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Number of enabled mitigations (higher = harder to exploit)."""
        return sum(1 for m in self.mitigations if m.enabled)

    @property
    def max_score(self) -> int:
        return len(self.mitigations)


def _has_load_config(pe: pefile.PE) -> bool:
    return (hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG")
            and pe.DIRECTORY_ENTRY_LOAD_CONFIG is not None)


def _guard_flags(pe: pefile.PE) -> int:
    if not _has_load_config(pe):
        return 0
    lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
    if hasattr(lc, "GuardFlags"):
        return lc.GuardFlags
    return 0


def _security_cookie_va(pe: pefile.PE) -> int:
    if not _has_load_config(pe):
        return 0
    lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
    if hasattr(lc, "SecurityCookie"):
        return lc.SecurityCookie
    return 0


def _check_safeseh(pe: pefile.PE) -> Mitigation:
    """Check SafeSEH (32-bit only, via IMAGE_LOAD_CONFIG_DIRECTORY)."""
    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    if is_64:
        return Mitigation("SafeSEH", True, "N/A (64-bit uses table-based SEH)")

    dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
    if dll_chars & _NO_SEH:
        return Mitigation("SafeSEH", True, "NO_SEH flag set (SEH disabled entirely)")

    if not _has_load_config(pe):
        return Mitigation("SafeSEH", False, "No IMAGE_LOAD_CONFIG — no SEH handler table")

    lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
    if hasattr(lc, "SEHandlerTable") and hasattr(lc, "SEHandlerCount"):
        if lc.SEHandlerTable != 0 and lc.SEHandlerCount > 0:
            return Mitigation("SafeSEH", True,
                              f"{lc.SEHandlerCount} registered handlers")
    return Mitigation("SafeSEH", False, "SEH handler table missing or empty")


def _check_authenticode(pe: pefile.PE) -> Mitigation:
    """Check for Authenticode signature (IMAGE_DIRECTORY_ENTRY_SECURITY)."""
    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # SECURITY
    if sec_dir.VirtualAddress != 0 and sec_dir.Size != 0:
        return Mitigation("Authenticode", True,
                          f"Signature at offset 0x{sec_dir.VirtualAddress:X}, "
                          f"size {sec_dir.Size} bytes")
    return Mitigation("Authenticode", False, "No embedded signature")


def check_mitigations(path: str) -> MitigationReport:
    """Analyze a PE binary for security mitigations.

    Args:
        path: Filesystem path to a PE (.exe / .dll) file.

    Returns:
        MitigationReport with all check results.
    """
    pe = pefile.PE(path, fast_load=False)
    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    arch = "x64" if is_64 else "x86"
    dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
    gflags = _guard_flags(pe)

    report = MitigationReport(path=str(path), arch=arch)
    m = report.mitigations

    # ASLR
    aslr = bool(dll_chars & _DYNAMIC_BASE)
    m.append(Mitigation("ASLR", aslr,
                         "DYNAMIC_BASE set" if aslr else "Fixed base address"))

    # High-entropy ASLR (64-bit)
    if is_64:
        he = bool(dll_chars & _HIGH_ENTROPY_VA)
        m.append(Mitigation("HighEntropyASLR", he,
                             "HIGH_ENTROPY_VA set" if he else "Standard ASLR entropy"))

    # DEP / NX
    dep = bool(dll_chars & _NX_COMPAT)
    m.append(Mitigation("DEP", dep,
                         "NX_COMPAT set" if dep else "No NX_COMPAT — DEP opt-in only"))

    # CFG (Control Flow Guard)
    cfg_flag = bool(dll_chars & _GUARD_CF)
    cfg_instrumented = bool(gflags & _GUARD_CF_INSTRUMENTED)
    cfg_table = bool(gflags & _GUARD_CF_FUNCTION_TABLE_PRESENT)
    cfg_ok = cfg_flag and cfg_instrumented and cfg_table
    detail_parts = []
    if cfg_flag:
        detail_parts.append("GUARD_CF")
    if cfg_instrumented:
        detail_parts.append("instrumented")
    if cfg_table:
        detail_parts.append("function table present")
    m.append(Mitigation("CFG", cfg_ok,
                         ", ".join(detail_parts) if detail_parts else "Not present"))

    # XFG (eXtended Flow Guard)
    xfg = bool(gflags & _GUARD_XFG_ENABLED)
    m.append(Mitigation("XFG", xfg,
                         "XFG enabled" if xfg else "Not present"))

    # Return Flow Guard
    rfg = bool(gflags & _GUARD_RF_INSTRUMENTED) and bool(gflags & _GUARD_RF_ENABLE)
    m.append(Mitigation("RFG", rfg,
                         "Return Flow Guard enabled" if rfg else "Not present"))

    # Stack cookies (/GS)
    cookie_va = _security_cookie_va(pe)
    cookie_unused = bool(gflags & _GUARD_SECURITY_COOKIE_UNUSED)
    gs_ok = cookie_va != 0 and not cookie_unused
    if gs_ok:
        detail = f"Security cookie at 0x{cookie_va:X}"
    elif cookie_unused:
        detail = "Cookie present but marked unused"
    else:
        detail = "No security cookie in LOAD_CONFIG"
    m.append(Mitigation("StackCookies", gs_ok, detail))

    # SafeSEH
    m.append(_check_safeseh(pe))

    # Authenticode
    m.append(_check_authenticode(pe))

    # Force integrity
    fi = bool(dll_chars & _FORCE_INTEGRITY)
    m.append(Mitigation("ForceIntegrity", fi,
                         "Mandatory code integrity" if fi else "Not enforced"))

    # AppContainer
    ac = bool(dll_chars & _APPCONTAINER)
    m.append(Mitigation("AppContainer", ac,
                         "Runs in AppContainer" if ac else "Not containerized"))

    # CET Shadow Stack (via EH continuation table as proxy)
    cet = bool(gflags & _GUARD_EH_CONTINUATION_TABLE_PRESENT)
    m.append(Mitigation("CET_ShadowStack", cet,
                         "EH continuation table present (CET-compatible)"
                         if cet else "No CET support indicators"))

    # Retpoline (Spectre v2 mitigation)
    retpoline = bool(gflags & _GUARD_RETPOLINE_PRESENT)
    m.append(Mitigation("Retpoline", retpoline,
                         "Retpoline thunks present" if retpoline else "Not present"))

    return report


def format_report(report: MitigationReport) -> str:
    """Format a MitigationReport as a human-readable table."""
    lines = [
        f"  Binary: {report.path}",
        f"  Arch:   {report.arch}",
        f"  Score:  {report.score}/{report.max_score}",
        "",
    ]
    for m in report.mitigations:
        status = "\033[92m ON\033[0m" if m.enabled else "\033[91mOFF\033[0m"
        lines.append(f"  [{status}] {m.name:20s} {m.detail}")
    return "\n".join(lines)


def format_json(report: MitigationReport) -> str:
    d = asdict(report)
    d["score"] = report.score
    d["max_score"] = report.max_score
    return json.dumps(d, indent=2)


def scan_directory(dirpath: str, recursive: bool = True) -> list[MitigationReport]:
    """Scan a directory for PE files and check mitigations on each."""
    results = []
    pattern = "**/*" if recursive else "*"
    for p in sorted(Path(dirpath).glob(pattern)):
        if p.suffix.lower() not in (".exe", ".dll", ".ocx", ".sys", ".drv"):
            continue
        if not p.is_file():
            continue
        try:
            results.append(check_mitigations(str(p)))
        except pefile.PEFormatError:
            continue
    return results


def format_summary(reports: list[MitigationReport]) -> str:
    """Format a multi-binary summary sorted by weakest mitigation score."""
    reports_sorted = sorted(reports, key=lambda r: r.score)
    lines = [f"  {'Binary':<50s} {'Arch':<5s} {'Score':<7s} ASLR  DEP   CFG   /GS   SEH"]
    lines.append("  " + "-" * 95)
    for r in reports_sorted:
        mmap = {m.name: m.enabled for m in r.mitigations}
        name = Path(r.path).name
        if len(name) > 48:
            name = name[:45] + "..."
        def flag(key):
            if key not in mmap:
                return " -  "
            return " \033[92mY\033[0m  " if mmap[key] else " \033[91mN\033[0m  "
        lines.append(
            f"  {name:<50s} {r.arch:<5s} {r.score}/{r.max_score:<5s}"
            f"{flag('ASLR')}{flag('DEP')}{flag('CFG')}{flag('StackCookies')}{flag('SafeSEH')}"
        )
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("target", help="PE binary or directory of binaries")
    p.add_argument("--json", action="store_true", help="Output as JSON")
    p.add_argument("--recursive", action="store_true",
                   help="Scan directory recursively for PE files")
    args = p.parse_args()

    target = Path(args.target)

    if target.is_dir() or args.recursive:
        reports = scan_directory(str(target), recursive=args.recursive)
        if not reports:
            print("No PE files found.")
            sys.exit(1)
        if args.json:
            out = [asdict(r) | {"score": r.score, "max_score": r.max_score}
                   for r in reports]
            print(json.dumps(out, indent=2))
        else:
            print(format_summary(reports))
            # Also show weakest binary in detail
            weakest = min(reports, key=lambda r: r.score)
            print(f"\n  Weakest: {Path(weakest.path).name} ({weakest.score}/{weakest.max_score})")
            print(format_report(weakest))
    else:
        report = check_mitigations(str(target))
        if args.json:
            print(format_json(report))
        else:
            print(format_report(report))


if __name__ == "__main__":
    main()
