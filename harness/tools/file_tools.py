"""File I/O tools for KB, findings, and JSONL state files."""

from __future__ import annotations

from pathlib import Path

from harness.validation.schemas import (
    ReadFileInput, ReadFileOutput,
    WriteFileInput, WriteFileOutput,
)

_repo_root: str = "."


def set_repo_root(path: str) -> None:
    global _repo_root
    _repo_root = path


def _resolve(path: str) -> Path:
    p = Path(path)
    if not p.is_absolute():
        p = Path(_repo_root) / p
    return p


async def read_file(inp: ReadFileInput) -> ReadFileOutput:
    """Read a file from the project."""
    try:
        p = _resolve(inp.path)
        return ReadFileOutput(content=p.read_text(errors="replace"))
    except Exception as e:
        return ReadFileOutput(content="", error=str(e))


async def write_file(inp: WriteFileInput) -> WriteFileOutput:
    """Write or append to a file."""
    try:
        p = _resolve(inp.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if inp.append:
            with p.open("a") as f:
                f.write(inp.content)
        else:
            p.write_text(inp.content)
        return WriteFileOutput(success=True)
    except Exception as e:
        return WriteFileOutput(success=False, error=str(e))


ALL_FILE_TOOLS = {
    "read_file": (ReadFileInput, ReadFileOutput, read_file),
    "write_file": (WriteFileInput, WriteFileOutput, write_file),
}
