"""Pydantic AI tool wrappers for livetools (Frida-based dynamic analysis).

Lifecycle commands (attach/detach) use subprocess since they manage the daemon.
Runtime commands use the TCP client (livetools.client.send_command).
"""

from __future__ import annotations

import json
import logging

from harness.tools.base import run_subprocess
from harness.validation.schemas import (
    LiveAttachInput,
    LiveBpInput,
    LiveDetachInput,
    LiveGenericOutput,
    LiveMemReadInput,
    LiveMemWriteInput,
    LiveModulesInput,
    LiveRegsInput,
    LiveScanInput,
    LiveStackInput,
    LiveStatusOutput,
    LiveTraceInput,
)

logger = logging.getLogger(__name__)

_repo_root: str = "."


def set_repo_root(path: str) -> None:
    global _repo_root
    _repo_root = path


def _send_command(cmd: dict, timeout: float | None = None) -> dict:
    """Send a command to the livetools daemon via TCP.

    Imports livetools.client at call time to avoid import errors
    when livetools dependencies (frida) aren't installed.
    """
    import sys
    sys.path.insert(0, _repo_root)
    try:
        from livetools.client import send_command
        return send_command(cmd, timeout=timeout)
    finally:
        if sys.path[0] == _repo_root:
            sys.path.pop(0)


# ── Lifecycle (subprocess) ───────────────────────────────────────────────────

async def attach(inp: LiveAttachInput) -> LiveGenericOutput:
    """Attach to a running process or spawn one."""
    cmd = ["python", "-m", "livetools", "attach", inp.target]
    if inp.spawn:
        cmd.append("--spawn")
    r = await run_subprocess(cmd, cwd=_repo_root, timeout=30)
    return LiveGenericOutput(
        result=r.stdout.strip(),
        error=r.stderr.strip() if r.returncode != 0 else None,
    )


async def detach(_inp: LiveDetachInput) -> LiveGenericOutput:
    """Detach from the current process."""
    cmd = ["python", "-m", "livetools", "detach"]
    r = await run_subprocess(cmd, cwd=_repo_root, timeout=10)
    return LiveGenericOutput(
        result=r.stdout.strip(),
        error=r.stderr.strip() if r.returncode != 0 else None,
    )


# ── Runtime commands (TCP) ───────────────────────────────────────────────────

async def status() -> LiveStatusOutput:
    """Get daemon status."""
    try:
        resp = _send_command({"cmd": "status"})
        return LiveStatusOutput(
            target=resp.get("target", ""),
            pid=resp.get("pid", 0),
            state=resp.get("state", "UNKNOWN"),
            bp_count=resp.get("bpCount", 0),
        )
    except Exception as e:
        return LiveStatusOutput(state=f"ERROR: {e}")


async def trace(inp: LiveTraceInput) -> LiveGenericOutput:
    """Trace function calls at a VA."""
    cmd_dict: dict = {"cmd": "trace", "va": inp.va, "count": inp.count}
    if inp.read:
        cmd_dict["read"] = inp.read
    if inp.output:
        cmd_dict["output"] = inp.output
    try:
        resp = _send_command(cmd_dict, timeout=60)
        return LiveGenericOutput(result=json.dumps(resp, indent=2))
    except Exception as e:
        return LiveGenericOutput(result="", error=str(e))


async def bp(inp: LiveBpInput) -> LiveGenericOutput:
    """Manage breakpoints: add, del, list."""
    cmd_dict: dict = {"cmd": f"bp_{inp.action}"}
    if inp.va:
        cmd_dict["va"] = inp.va
    if inp.on_hit:
        cmd_dict["onHit"] = inp.on_hit
    try:
        resp = _send_command(cmd_dict)
        return LiveGenericOutput(result=json.dumps(resp, indent=2))
    except Exception as e:
        return LiveGenericOutput(result="", error=str(e))


async def mem_read(inp: LiveMemReadInput) -> LiveGenericOutput:
    """Read memory from the target process."""
    try:
        resp = _send_command({
            "cmd": "mem_read",
            "va": inp.va,
            "size": inp.size,
            "format": inp.format,
        })
        return LiveGenericOutput(result=json.dumps(resp, indent=2))
    except Exception as e:
        return LiveGenericOutput(result="", error=str(e))


async def mem_write(inp: LiveMemWriteInput) -> LiveGenericOutput:
    """Write memory in the target process."""
    try:
        resp = _send_command({"cmd": "mem_write", "va": inp.va, "data": inp.data})
        return LiveGenericOutput(result=json.dumps(resp, indent=2))
    except Exception as e:
        return LiveGenericOutput(result="", error=str(e))


async def regs(_inp: LiveRegsInput) -> LiveGenericOutput:
    """Read current register values."""
    try:
        resp = _send_command({"cmd": "regs"})
        return LiveGenericOutput(result=json.dumps(resp, indent=2))
    except Exception as e:
        return LiveGenericOutput(result="", error=str(e))


async def stack(inp: LiveStackInput) -> LiveGenericOutput:
    """Read stack entries."""
    try:
        resp = _send_command({"cmd": "stack", "count": inp.count})
        return LiveGenericOutput(result=json.dumps(resp, indent=2))
    except Exception as e:
        return LiveGenericOutput(result="", error=str(e))


async def modules(_inp: LiveModulesInput) -> LiveGenericOutput:
    """List loaded modules with base addresses."""
    try:
        resp = _send_command({"cmd": "modules"})
        return LiveGenericOutput(result=json.dumps(resp, indent=2))
    except Exception as e:
        return LiveGenericOutput(result="", error=str(e))


async def scan(inp: LiveScanInput) -> LiveGenericOutput:
    """Scan memory for a byte pattern."""
    cmd_dict: dict = {"cmd": "scan", "pattern": inp.pattern}
    if inp.region:
        cmd_dict["region"] = inp.region
    try:
        resp = _send_command(cmd_dict)
        return LiveGenericOutput(result=json.dumps(resp, indent=2))
    except Exception as e:
        return LiveGenericOutput(result="", error=str(e))


# ── Tool registry entry ─────────────────────────────────────────────────────

ALL_LIVETOOLS = {
    "live_attach": (LiveAttachInput, LiveGenericOutput, attach),
    "live_detach": (LiveDetachInput, LiveGenericOutput, detach),
    "live_status": (None, LiveStatusOutput, status),
    "live_trace": (LiveTraceInput, LiveGenericOutput, trace),
    "live_bp": (LiveBpInput, LiveGenericOutput, bp),
    "live_mem_read": (LiveMemReadInput, LiveGenericOutput, mem_read),
    "live_mem_write": (LiveMemWriteInput, LiveGenericOutput, mem_write),
    "live_regs": (LiveRegsInput, LiveGenericOutput, regs),
    "live_stack": (LiveStackInput, LiveGenericOutput, stack),
    "live_modules": (LiveModulesInput, LiveGenericOutput, modules),
    "live_scan": (LiveScanInput, LiveGenericOutput, scan),
}
