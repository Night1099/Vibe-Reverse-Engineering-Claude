#!/usr/bin/env python3
"""Auto-KB seeding pipeline for PE binary reverse engineering.

Runs on first contact with a binary to seed a knowledge base with
compiler fingerprints, signature matches, RTTI classes, imports,
interesting strings, and propagated function labels.

Usage:
    python -m retools.bootstrap <binary> --project <dir> [--db path]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary


# ---------------------------------------------------------------------------
# classify_function -- propagation rules
# ---------------------------------------------------------------------------

def classify_function(
    callees: list[int],
    callee_names: dict[int, str],
    is_vtable_call: bool,
) -> dict | None:
    """Classify a function by its callee pattern.

    Args:
        callees: List of direct call target VAs.
        callee_names: Map of VA -> known name for resolved callees.
        is_vtable_call: Whether the function contains an indirect vtable call.

    Returns:
        {"label": str, "confidence": float} or None if no rule matches.
    """
    names = {callee_names.get(c, "") for c in callees}
    name_lower = {n.lower() for n in names}

    # Rule 1: exactly one callee with a known name -> thunk
    if len(callees) == 1:
        target = callees[0]
        target_name = callee_names.get(target)
        if target_name:
            return {"label": f"_thunk_{target_name}", "confidence": 0.80}

    # Rule 2: calls operator_new + has vtable call -> constructor
    if is_vtable_call and any("operator_new" in n for n in name_lower):
        return {"label": "constructor", "confidence": 0.75}

    # Rule 3: calls CxxThrowException -> throws
    if any("cxxthrowexception" in n for n in name_lower):
        return {"label": "throws", "confidence": 0.85}

    # Rule 4: calls operator_delete -> destructor
    if any("operator_delete" in n for n in name_lower):
        return {"label": "destructor", "confidence": 0.70}

    # Rule 5: calls malloc with <=3 callees -> init_global
    if len(callees) <= 3 and any("malloc" in n for n in name_lower):
        return {"label": "init_global", "confidence": 0.55}

    return None


# ---------------------------------------------------------------------------
# Packed binary detection
# ---------------------------------------------------------------------------

def _is_packed(pe: pefile.PE) -> bool:
    """True if any executable section has raw_size < 10% of virtual_size.

    Only triggers when virtual_size > 0x1000 to avoid false positives
    on tiny sections.
    """
    for sec in pe.sections:
        if not (sec.Characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
            continue
        vsize = sec.Misc_VirtualSize
        rsize = sec.SizeOfRawData
        if vsize > 0x1000 and rsize < vsize * 0.10:
            return True
    return False


# ---------------------------------------------------------------------------
# KB file I/O
# ---------------------------------------------------------------------------

def _read_existing_addresses(kb_path: str) -> set[int]:
    """Parse existing kb.h and return the set of known addresses."""
    addresses: set[int] = set()
    if not os.path.isfile(kb_path):
        return addresses
    with open(kb_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("@ 0x"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        addresses.add(int(parts[1], 16))
                    except ValueError:
                        pass
    return addresses


def _write_kb_entries(kb_path: str, entries: list[str], known: set[int]) -> int:
    """Append new entries to kb.h, skipping addresses already present.

    Returns the number of entries written.
    """
    written = 0
    with open(kb_path, "a") as f:
        for entry in entries:
            # Extract address from "@ 0xADDR ..." lines
            for line in entry.splitlines():
                if line.startswith("@ 0x"):
                    parts = line.split()
                    try:
                        addr = int(parts[1], 16)
                    except (ValueError, IndexError):
                        continue
                    if addr in known:
                        break
            else:
                # No address line found or no duplicate -- write
                f.write(entry + "\n\n")
                written += 1
                continue
            # Duplicate found -- skip this entry
            continue
    return written


# ---------------------------------------------------------------------------
# bootstrap -- full pipeline
# ---------------------------------------------------------------------------

def bootstrap(
    binary_path: str,
    project_dir: str,
    db_path: str | None = None,
) -> dict:
    """Full auto-KB seeding pipeline.

    Args:
        binary_path: Path to the PE binary.
        project_dir: Directory for output (kb.h, bootstrap_report.txt).
        db_path: Optional path to a SignatureDB database file.

    Returns:
        Dict with pipeline statistics.
    """
    os.makedirs(project_dir, exist_ok=True)
    kb_path = os.path.join(project_dir, "kb.h")
    report_path = os.path.join(project_dir, "bootstrap_report.txt")

    pe = pefile.PE(binary_path, fast_load=False)

    # -- Packed binary detection -------------------------------------------
    if _is_packed(pe):
        report = (
            "Bootstrap Report\n"
            "================\n\n"
            "WARNING: Binary appears to be packed.\n"
            "Executable section has raw_size < 10% of virtual_size.\n"
            "Skipping analysis -- unpack the binary first.\n\n"
            "Compiler: unknown (packed)\n"
            "Functions identified: 0\n"
        )
        Path(report_path).write_text(report)
        # Create empty kb.h if it doesn't exist
        if not os.path.isfile(kb_path):
            Path(kb_path).write_text("// Auto-generated KB -- packed binary, no data\n")
        return {"packed": True, "functions_identified": 0}

    # -- Load binary -------------------------------------------------------
    b = Binary(binary_path)
    known_addresses = _read_existing_addresses(kb_path)
    kb_entries: list[str] = []
    stats: dict = {
        "packed": False,
        "compiler": "unknown",
        "compiler_confidence": 0.0,
        "sigdb_matches": 0,
        "rtti_classes": 0,
        "imports": 0,
        "strings_seeded": 0,
        "propagated": 0,
        "functions_identified": 0,
    }

    # -- Step 1: Compiler fingerprint --------------------------------------
    compiler_id = "unknown"
    try:
        if db_path and os.path.isfile(db_path):
            from sigdb import SignatureDB
            db = SignatureDB(db_path)
            fp = db.fingerprint(b)
            compiler_id = fp.get("compiler", "unknown")
            stats["compiler"] = compiler_id
            stats["compiler_confidence"] = fp.get("confidence", 0.0)
        else:
            # Lightweight fingerprint without sigdb marker patterns
            from sigdb import detect_crt_import
            crt = detect_crt_import(b)
            if crt:
                compiler_id = crt
                stats["compiler"] = crt
                stats["compiler_confidence"] = 0.3
    except Exception as exc:
        stats["_fingerprint_error"] = type(exc).__name__

    # -- Step 2: Bulk signature scan ---------------------------------------
    sig_results: dict = {}
    try:
        if db_path and os.path.isfile(db_path):
            from sigdb import SignatureDB
            db = SignatureDB(db_path)
            sig_results = db.scan(b, preferred_compiler=compiler_id)
            db.close()
            for va, match in sig_results.items():
                comment = f"// [sigdb: {match.tier}, {match.confidence:.2f}] {match.category}"
                kb_entries.append(f"{comment}\n@ 0x{va:X} {match.name};")
            stats["sigdb_matches"] = len(sig_results)
    except Exception as exc:
        stats["_sigdb_error"] = type(exc).__name__

    # -- Step 3: RTTI scan -------------------------------------------------
    try:
        from rtti import scan_all_rtti
        rtti_classes = scan_all_rtti(pe)
        for cls in rtti_classes:
            hierarchy_str = " -> ".join(cls.hierarchy) if cls.hierarchy else cls.name
            clean_name = re.sub(r"[^A-Za-z0-9_]", "_", cls.name.lstrip(".?AV").rstrip("@@"))
            comment = f"// [rtti] {cls.name}\n// hierarchy: {hierarchy_str}"
            kb_entries.append(f"{comment}\n@ 0x{cls.vtable_va:X} {clean_name}_vtable;")
        stats["rtti_classes"] = len(rtti_classes)
    except Exception as exc:
        stats["_rtti_error"] = type(exc).__name__

    # -- Step 4: Import analysis -------------------------------------------
    try:
        from search import find_imports
        imports = find_imports(b)
        stats["imports"] = len(imports)
    except Exception as exc:
        stats["_imports_error"] = type(exc).__name__
        imports = []

    # Build a name lookup from imports + sigdb for propagation
    import_names: dict[str, str] = {}
    for imp in imports:
        import_names[imp.name.lower()] = imp.name

    # -- Step 5: String xref seeding ---------------------------------------
    error_keywords = ["error", "fail", "assert", "fatal", "exception",
                      "invalid", "corrupt", "abort", "panic", "warning"]
    try:
        from search import find_strings
        strings = find_strings(b, filter_keywords=error_keywords, min_len=6)
        for sref in strings:
            if sref.va is not None:
                # Sanitize the string for a C comment
                safe_str = sref.value[:80].replace("*/", "* /")
                comment = f'// [string] "{safe_str}"'
                label = re.sub(r"[^A-Za-z0-9_]", "_", sref.value[:40]).strip("_")
                if label:
                    kb_entries.append(f"{comment}\n@ 0x{sref.va:X} str_{label};")
        stats["strings_seeded"] = len(strings)
    except Exception as exc:
        stats["_strings_error"] = type(exc).__name__

    # -- Step 6: Cross-function propagation --------------------------------
    # Build name map from sigdb matches + imports
    known_names: dict[int, str] = {}
    for va, match in sig_results.items():
        known_names[va] = match.name
    # Add import thunk targets if available via PE IAT
    try:
        if hasattr(b.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in b.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.address:
                        name = imp.name.decode("ascii", errors="ignore")
                        known_names[imp.address] = name
    except Exception:
        pass

    propagated = 0
    try:
        from funcinfo import analyze
        for func_va in b.func_table:
            if func_va in known_addresses or func_va in {
                va for e in kb_entries
                for line in e.splitlines()
                if line.startswith("@ 0x")
                for va in [int(line.split()[1], 16)]
            }:
                continue

            try:
                rets, calls, end_va = analyze(b, func_va, max_size=0x1000)
            except Exception:
                continue

            direct_callees = []
            has_vtable_call = False
            for _, target in calls:
                if isinstance(target, int):
                    direct_callees.append(target)
                elif isinstance(target, str) and "[" in target:
                    # Indirect call through register+offset -> vtable call
                    has_vtable_call = True

            if not direct_callees:
                continue

            result = classify_function(direct_callees, known_names, has_vtable_call)
            if result:
                comment = f"// [propagated: {result['label']}, {result['confidence']:.2f}]"
                kb_entries.append(f"{comment}\n@ 0x{func_va:X} {result['label']};")
                propagated += 1
    except Exception as exc:
        stats["_propagation_error"] = type(exc).__name__

    stats["propagated"] = propagated
    stats["functions_identified"] = (
        stats["sigdb_matches"] + stats["rtti_classes"]
        + stats["strings_seeded"] + propagated
    )

    # -- Write kb.h --------------------------------------------------------
    if not os.path.isfile(kb_path):
        Path(kb_path).write_text("// Auto-generated knowledge base\n\n")

    written = _write_kb_entries(kb_path, kb_entries, known_addresses)

    # -- Write report ------------------------------------------------------
    report_lines = [
        "Bootstrap Report",
        "================",
        "",
        f"Binary: {binary_path}",
        f"Compiler: {stats['compiler']} (confidence: {stats['compiler_confidence']:.0%})",
        "",
        f"Signature DB matches: {stats['sigdb_matches']}",
        f"RTTI classes found: {stats['rtti_classes']}",
        f"Imports cataloged: {stats['imports']}",
        f"Error strings seeded: {stats['strings_seeded']}",
        f"Propagated labels: {stats['propagated']}",
        f"Functions identified: {stats['functions_identified']}",
        f"KB entries written: {written}",
        "",
    ]

    # Log any errors from best-effort steps
    for key in sorted(stats):
        if key.startswith("_") and key.endswith("_error"):
            step = key[1:].replace("_error", "")
            report_lines.append(f"Note: {step} step raised {stats[key]}")

    report_lines.append("")
    Path(report_path).write_text("\n".join(report_lines))

    return stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("--project", required=True,
                   help="Project directory for output files")
    p.add_argument("--db", default=None,
                   help="Path to signature database (optional)")
    args = p.parse_args(argv)

    result = bootstrap(args.binary, args.project, db_path=args.db)

    if result.get("packed"):
        print("WARNING: Binary appears to be packed. Skipping analysis.")
    else:
        print(f"Compiler: {result.get('compiler', 'unknown')}")
        print(f"Functions identified: {result.get('functions_identified', 0)}")
        print(f"Report written to: {os.path.join(args.project, 'bootstrap_report.txt')}")


if __name__ == "__main__":
    main()
