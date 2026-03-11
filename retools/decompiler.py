#!/usr/bin/env python3
"""Decompile a function from a PE binary using radare2 + r2ghidra/pdc.

Produces pseudo-C output for the function at the given virtual address.
Uses r2ghidra (pdg) when available, falling back to r2's built-in pdc.

Prerequisites:
    pip install r2pipe
    radare2 portable in  tools/radare2-*/bin  (auto-detected)

Usage:
    python -m retools.decompiler <binary> <va>
    python -m retools.decompiler <binary> <va> --backend pdc
    python -m retools.decompiler <binary> <va> --full-analysis

Examples:
    python -m retools.decompiler binary.exe 0x401000
    python -m retools.decompiler binary.exe 0x401000 --backend pdc
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import r2pipe
except ImportError:
    sys.exit("r2pipe not installed. Run: pip install r2pipe")

_HERE = Path(__file__).resolve().parent
_PROJECT = _HERE.parent

_BACKEND_CMDS = {
    "pdg": "pdg",    # r2ghidra – best quality
    "pdc": "pdc",    # r2 built-in pseudo-C
    "pdd": "pdd",    # r2dec (JS-based)
}


def _find_r2_bin() -> str | None:
    """Locate the radare2 binary, preferring the project-local portable install."""
    tools_dir = _PROJECT / "tools"
    if tools_dir.is_dir():
        for child in sorted(tools_dir.iterdir(), reverse=True):
            candidate = child / "bin" / "radare2.exe"
            if candidate.is_file():
                return str(candidate)
            candidate = child / "bin" / "radare2"
            if candidate.is_file():
                return str(candidate)
    # Fall back to PATH
    import shutil
    return shutil.which("radare2") or shutil.which("r2")


def _find_sleigh_home() -> str | None:
    """Locate the r2ghidra_sleigh directory containing flattened .ldefs/.sla files."""
    tools_dir = _PROJECT / "tools"
    if tools_dir.is_dir():
        for child in sorted(tools_dir.iterdir(), reverse=True):
            # Bundled alongside the radare2 install
            candidate = child / "share" / "r2ghidra_sleigh"
            if candidate.is_dir() and any(candidate.glob("*.ldefs")):
                return str(candidate)
    # Fallback: standard r2ghidra install location
    xdg = Path.home() / ".local" / "share" / "radare2" / "plugins" / "r2ghidra_sleigh"
    if xdg.is_dir() and any(xdg.glob("*.ldefs")):
        return str(xdg)
    return None


def _ensure_r2_in_path(r2_bin: str) -> None:
    """Add radare2's bin dir to PATH so DLL deps resolve."""
    bin_dir = str(Path(r2_bin).parent)
    if bin_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")


def decompile(binary: str, va: int, *, backend: str = "auto",
              full_analysis: bool = False) -> str:
    """Decompile the function at *va* and return pseudo-C as a string."""
    r2_bin = _find_r2_bin()
    if r2_bin is None:
        raise FileNotFoundError(
            "radare2 not found. Install to tools/radare2-*/bin or add to PATH.")
    _ensure_r2_in_path(r2_bin)

    r2 = r2pipe.open(binary, flags=["-2"])
    try:
        r2.cmd("e scr.color=0")
        r2.cmd("e log.level=0")
        r2.cmd("e asm.lines=false")

        sleigh = _find_sleigh_home()
        if sleigh:
            r2.cmd(f"e r2ghidra.sleighhome={sleigh}")

        if full_analysis:
            r2.cmd("aaa")
        else:
            r2.cmd(f"af @ {va:#x}")

        # Pick backend
        if backend == "auto":
            for try_be in ("pdg", "pdc"):
                out = r2.cmd(f"{_BACKEND_CMDS[try_be]} @ {va:#x}").strip()
                if out and "install" not in out.lower():
                    return out
            return f"[error] No decompiler backend produced output at {va:#x}"

        cmd = _BACKEND_CMDS.get(backend)
        if cmd is None:
            return f"[error] Unknown backend '{backend}'. Choose from: {', '.join(_BACKEND_CMDS)}"
        out = r2.cmd(f"{cmd} @ {va:#x}").strip()
        return out if out else f"[error] {backend} produced no output at {va:#x}"
    finally:
        r2.quit()


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("va", help="Function virtual address in hex (e.g. 0x401000)")
    p.add_argument(
        "-b", "--backend",
        choices=["auto", *_BACKEND_CMDS],
        default="auto",
        help="Decompiler backend (default: auto – tries pdg then pdc)",
    )
    p.add_argument(
        "-A", "--full-analysis",
        action="store_true",
        help="Run full r2 analysis (aaa) before decompiling – slower but better names",
    )
    args = p.parse_args()
    print(decompile(args.binary, int(args.va, 16),
                    backend=args.backend, full_analysis=args.full_analysis))


if __name__ == "__main__":
    main()
