"""Pydantic AI tool wrappers for DX9 analysis scripts.

All scripts live under rtx_remix_tools/dx/scripts/ and follow the same
pattern: `python <script>.py <binary> [args]` → stdout text output.
"""

from __future__ import annotations

from harness.tools.base import run_subprocess
from harness.validation.schemas import (
    DX9ScriptInput,
    DX9ScriptOutput,
    DX9TracerAnalyzeInput,
    DX9TracerOutput,
    DX9TracerTriggerInput,
)

_repo_root: str = "."

# All valid DX9 script names (without .py extension)
VALID_SCRIPTS = {
    "find_d3d_calls",
    "find_vs_constants",
    "find_ps_constants",
    "find_device_calls",
    "find_vtable_calls",
    "find_render_states",
    "find_texture_ops",
    "find_transforms",
    "find_surface_formats",
    "find_stateblocks",
    "decode_fvf",
    "decode_vtx_decls",
    "find_shader_bytecode",
    "classify_draws",
    "find_matrix_registers",
    "find_skinning",
    "find_blend_states",
    "scan_d3d_region",
}


def set_repo_root(path: str) -> None:
    global _repo_root
    _repo_root = path


async def dx9_script(inp: DX9ScriptInput) -> DX9ScriptOutput:
    """Run a DX9 analysis script on a binary.

    Args:
        inp: Script name (e.g. 'find_d3d_calls') and binary path.
    """
    if inp.script not in VALID_SCRIPTS:
        return DX9ScriptOutput(
            output="",
            error=f"Unknown script '{inp.script}'. Valid: {sorted(VALID_SCRIPTS)}",
        )

    script_path = f"rtx_remix_tools/dx/scripts/{inp.script}.py"
    cmd = ["python", script_path, inp.binary] + inp.extra_args

    r = await run_subprocess(cmd, cwd=_repo_root, timeout=120)
    return DX9ScriptOutput(
        output=r.stdout.strip(),
        error=r.stderr.strip() if r.returncode != 0 else None,
    )


# ── DX9 Tracer ───────────────────────────────────────────────────────────────

async def dx9_tracer_trigger(inp: DX9TracerTriggerInput) -> DX9TracerOutput:
    """Signal a running game to capture N frames."""
    cmd = [
        "python", "-m", "graphics.directx.dx9.tracer", "trigger",
        "--game-dir", inp.game_dir,
        "--frames", str(inp.frames),
    ]
    r = await run_subprocess(cmd, cwd=_repo_root, timeout=30)
    return DX9TracerOutput(
        output=r.stdout.strip(),
        error=r.stderr.strip() if r.returncode != 0 else None,
    )


async def dx9_tracer_analyze(inp: DX9TracerAnalyzeInput) -> DX9TracerOutput:
    """Run offline analysis on a captured frame JSONL."""
    cmd = [
        "python", "-m", "graphics.directx.dx9.tracer", "analyze",
        inp.jsonl_path, f"--{inp.analysis}",
    ]
    r = await run_subprocess(cmd, cwd=_repo_root, timeout=120)
    return DX9TracerOutput(
        output=r.stdout.strip(),
        error=r.stderr.strip() if r.returncode != 0 else None,
    )


# ── Tool registry entry ─────────────────────────────────────────────────────

ALL_DX9_TOOLS = {
    "dx9_script": (DX9ScriptInput, DX9ScriptOutput, dx9_script),
    "dx9_tracer_trigger": (DX9TracerTriggerInput, DX9TracerOutput, dx9_tracer_trigger),
    "dx9_tracer_analyze": (DX9TracerAnalyzeInput, DX9TracerOutput, dx9_tracer_analyze),
}
