"""Subprocess tool runner — execute CLI tools with timeout and output capture."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SubprocessResult:
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False


async def run_subprocess(
    cmd: list[str],
    *,
    cwd: str | Path | None = None,
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> SubprocessResult:
    """Run a command asynchronously with timeout.

    Args:
        cmd: Command and arguments.
        cwd: Working directory (defaults to repo root).
        timeout: Max seconds before killing the process.
        env: Extra environment variables (merged with os.environ).
    """
    import os

    full_env = dict(os.environ)
    if env:
        full_env.update(env)

    logger.debug("Running: %s", " ".join(cmd))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=full_env,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return SubprocessResult(
            stdout=stdout_bytes.decode(errors="replace"),
            stderr=stderr_bytes.decode(errors="replace"),
            returncode=proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return SubprocessResult(
            stdout="",
            stderr=f"Process timed out after {timeout}s",
            returncode=-1,
            timed_out=True,
        )
    except FileNotFoundError as e:
        return SubprocessResult(
            stdout="",
            stderr=str(e),
            returncode=-1,
        )
