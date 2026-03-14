#!/usr/bin/env python3
"""Decompile a function from a PE binary using radare2 + r2ghidra/pdc.

Produces pseudo-C output for the function at the given virtual address.
Uses r2ghidra (pdg) when available, falling back to r2's built-in pdc.

Supports loading type/function/global metadata via ``--types`` to produce
richer decompiled output (named structs, function names, enum values).

Prerequisites:
    pip install r2pipe
    radare2 portable in  tools/radare2-*/bin  (auto-detected)
    pip install ollama  (optional, for llm4d backend)

Usage:
    python -m retools.decompiler <binary> <va>
    python -m retools.decompiler <binary> <va> --types kb.h
    python -m retools.decompiler <binary> <va> --backend pdc
    python -m retools.decompiler <binary> <va> --backend llm4d
    python -m retools.decompiler <binary> <va> --backend llm4d --model MHKetbi/llm4decompile-22b-v2:q8_0

Knowledge base format (``--types`` input):
    // C type definitions (struct, enum, typedef) -- no prefix
    struct Foo { int x; float y; };
    enum Mode { MODE_A=0, MODE_B=1 };

    // Function signatures at addresses -- @ prefix
    @ 0x401000 void __cdecl ProcessInput(int key);

    // Global variables at addresses -- $ prefix
    $ 0x7C5548 Foo* g_mainObject

Examples:
    python -m retools.decompiler binary.exe 0x401000
    python -m retools.decompiler binary.exe 0x401000 --types project/kb.h
    python -m retools.decompiler binary.exe 0x401000 --types "struct V { float x; float y; float z; };"
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
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

_ollama = None


def _ensure_ollama():
    """Lazy-import ollama; raises ImportError with install hint if missing."""
    global _ollama
    if _ollama is not None:
        return
    try:
        import ollama as _ol
    except ImportError:
        raise ImportError("ollama not installed. Run: pip install ollama") from None
    _ollama = _ol


def _decompile_llm4d(r2, va: int, model: str) -> str:
    """Decompile via LLM4Decompile through Ollama.

    Args:
        r2: Open r2pipe session with function already analyzed.
        va: Virtual address of the function.
        model: Ollama model name.

    Returns:
        Decompiled C code.

    Raises:
        ImportError: If ollama is not installed.
        RuntimeError: If disassembly extraction or Ollama call fails.
    """
    _ensure_ollama()

    asm = r2.cmd(f"pdf @ {va:#x}").strip()
    if not asm or "Cannot find function" in asm:
        raise RuntimeError(f"No function disassembly at {va:#x}. Try --full-analysis.")

    prompt = f"# This is the assembly code:\n{asm}\n# What is the source code?\n"
    response = _ollama.generate(model=model, prompt=prompt)
    result = response["response"].strip()
    if not result:
        raise RuntimeError(f"LLM4Decompile returned empty output for {va:#x}")
    return result


def _save_training_pair(project: str, asm: str, c_code: str,
                        binary: str, va: int, backend: str) -> Path:
    """Append an (assembly, C) training pair to the project's JSONL file.

    Args:
        project: Project name (subdirectory under patches/).
        asm: Raw function disassembly from r2 pdf.
        c_code: Decompiled or hand-corrected C code.
        binary: Path to the binary (basename stored).
        va: Virtual address of the function.
        backend: Decompiler backend that produced the C code.

    Returns:
        Path to the JSONL file.
    """
    entry = {
        "input": f"# This is the assembly code:\n{asm}\n# What is the source code?\n",
        "output": c_code,
        "metadata": {
            "binary": Path(binary).name,
            "va": f"{va:#x}",
            "backend": backend,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }
    out_dir = _PROJECT / "patches" / project
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "training_pairs.jsonl"
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return out_path


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
    import shutil
    return shutil.which("radare2") or shutil.which("r2")


def _find_sleigh_home() -> str | None:
    """Locate the r2ghidra_sleigh directory containing flattened .ldefs/.sla files."""
    tools_dir = _PROJECT / "tools"
    if tools_dir.is_dir():
        for child in sorted(tools_dir.iterdir(), reverse=True):
            candidate = child / "share" / "r2ghidra_sleigh"
            if candidate.is_dir() and any(candidate.glob("*.ldefs")):
                return str(candidate)
    xdg = Path.home() / ".local" / "share" / "radare2" / "plugins" / "r2ghidra_sleigh"
    if xdg.is_dir() and any(xdg.glob("*.ldefs")):
        return str(xdg)
    return None


def _ensure_r2_in_path(r2_bin: str) -> None:
    """Add radare2's bin dir to PATH so DLL deps resolve."""
    bin_dir = str(Path(r2_bin).parent)
    if bin_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")


def _load_types(r2, types_arg: str) -> None:
    """Parse a knowledge-base string and send type/function/global commands to r2."""
    if types_arg == "-":
        text = sys.stdin.read()
    elif os.path.isfile(types_arg):
        text = Path(types_arg).read_text(encoding="utf-8")
    else:
        text = types_arg

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue

        if line.startswith("@ "):
            rest = line[2:]
            addr_str, sig = rest.split(None, 1)
            addr = int(addr_str, 16)
            name = sig.rstrip(";").split("(")[0].split()[-1]
            r2.cmd(f"af @ {addr:#x}")
            r2.cmd(f"afn {name} @ {addr:#x}")
            r2.cmd(f"afs {sig.rstrip(';')} @ {addr:#x}")
        elif line.startswith("$ "):
            parts = line[2:].split()
            addr = int(parts[0], 16)
            name = parts[-1]
            r2.cmd(f"f {name} @ {addr:#x}")
            if len(parts) > 2:
                type_name = " ".join(parts[1:-1])
                r2.cmd(f"tl {type_name} @ {addr:#x}")
        else:
            r2.cmd(f"td {line}")


def decompile(binary: str, va: int, *, backend: str = "auto",
              full_analysis: bool = False, types: str | None = None,
              model: str = "MHKetbi/llm4decompile-22b-v2",
              save: str | None = None,
              save_from: str | None = None) -> str:
    """Decompile the function at *va* and return pseudo-C as a string.

    Args:
        binary: Path to PE file.
        va: Virtual address of the function.
        backend: Decompiler backend ("auto", "pdg", "pdc", "pdd", "llm4d").
        full_analysis: If True, run ``aaa`` before decompiling.
        types: Knowledge-base string, stdin marker (``-``), or file path.
        model: Ollama model name for the llm4d backend.
        save: Project name to save (asm, C) training pair under patches/.
        save_from: Path to hand-corrected C file to use as training output.
    """
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

        if types:
            _load_types(r2, types)

        if full_analysis:
            r2.cmd("aaa")
        else:
            r2.cmd(f"af @ {va:#x}")

        if backend == "llm4d":
            result = _decompile_llm4d(r2, va, model)
        elif backend == "auto":
            result = None
            for try_be in ("pdg", "pdc"):
                out = r2.cmd(f"{_BACKEND_CMDS[try_be]} @ {va:#x}").strip()
                if out and "install" not in out.lower():
                    result = out
                    break
            if result is None:
                result = f"[error] No decompiler backend produced output at {va:#x}"
        else:
            cmd = _BACKEND_CMDS.get(backend)
            if cmd is None:
                valid = ", ".join([*_BACKEND_CMDS, "llm4d"])
                result = f"[error] Unknown backend '{backend}'. Choose from: {valid}"
            else:
                out = r2.cmd(f"{cmd} @ {va:#x}").strip()
                result = out if out else f"[error] {backend} produced no output at {va:#x}"

        if save and not result.startswith("[error]"):
            asm = r2.cmd(f"pdf @ {va:#x}").strip()
            c_output = Path(save_from).read_text(encoding="utf-8") if save_from else result
            path = _save_training_pair(save, asm, c_output, binary, va, backend)
            print(f"[saved] Training pair → {path}", file=sys.stderr)

        return result
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
        choices=["auto", *_BACKEND_CMDS, "llm4d"],
        default="auto",
        help="Decompiler backend (default: auto – tries pdg then pdc)",
    )
    p.add_argument(
        "-m", "--model",
        default="MHKetbi/llm4decompile-22b-v2",
        help="Ollama model for llm4d backend (default: MHKetbi/llm4decompile-22b-v2)",
    )
    p.add_argument(
        "-A", "--full-analysis",
        action="store_true",
        help="Run full r2 analysis (aaa) before decompiling – slower but better names",
    )
    p.add_argument(
        "-t", "--types",
        help="Knowledge base: inline types string, '-' for stdin, "
             "or path to .h file with structs/functions/globals",
    )
    p.add_argument(
        "-s", "--save", metavar="PROJECT",
        help="Save (asm, C) training pair to patches/PROJECT/training_pairs.jsonl",
    )
    p.add_argument(
        "--save-from", metavar="FILE",
        help="Use hand-corrected C file as training output (requires --save)",
    )
    args = p.parse_args()
    if args.save_from and not args.save:
        p.error("--save-from requires --save PROJECT")
    print(decompile(args.binary, int(args.va, 16),
                    backend=args.backend, full_analysis=args.full_analysis,
                    types=args.types, model=args.model,
                    save=args.save, save_from=args.save_from))


if __name__ == "__main__":
    main()
