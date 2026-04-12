"""Tests for tool wrapper command construction."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from harness.tools.base import SubprocessResult
from harness.validation.schemas import (
    DecompileInput,
    DX9ScriptInput,
    SearchInput,
    XrefsInput,
)


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


def _mock_subprocess(stdout="output", stderr="", returncode=0):
    return AsyncMock(return_value=SubprocessResult(
        stdout=stdout, stderr=stderr, returncode=returncode,
    ))


def test_decompile_basic_command(event_loop):
    mock = _mock_subprocess(stdout="int func() {}")

    with patch("harness.tools.retools_wrap.run_subprocess", mock):
        from harness.tools.retools_wrap import decompile
        inp = DecompileInput(binary="game.exe", va="0x401000")
        result = event_loop.run_until_complete(decompile(inp))

    assert result.pseudocode == "int func() {}"
    assert result.error is None
    # Verify command was constructed correctly
    call_args = mock.call_args
    cmd = call_args[0][0]
    assert "retools.decompiler" in " ".join(cmd)
    assert "game.exe" in cmd
    assert "0x401000" in cmd


def test_decompile_with_types(event_loop):
    mock = _mock_subprocess()

    with patch("harness.tools.retools_wrap.run_subprocess", mock):
        from harness.tools.retools_wrap import decompile
        inp = DecompileInput(
            binary="game.exe", va="0x401000",
            types="patches/Game/kb.h", backend="pdg",
        )
        event_loop.run_until_complete(decompile(inp))

    cmd = mock.call_args[0][0]
    assert "--types" in cmd
    assert "patches/Game/kb.h" in cmd
    assert "--backend" in cmd
    assert "pdg" in cmd


def test_xrefs_indirect(event_loop):
    mock = _mock_subprocess(stdout="0x401000 -> 0x402000\n0x401000 -> 0x403000")

    with patch("harness.tools.retools_wrap.run_subprocess", mock):
        from harness.tools.retools_wrap import xrefs
        inp = XrefsInput(binary="game.exe", target="0x401000", indirect=True)
        result = event_loop.run_until_complete(xrefs(inp))

    assert result.count == 2
    cmd = mock.call_args[0][0]
    assert "--indirect" in cmd


def test_search_strings(event_loop):
    mock = _mock_subprocess(stdout="0x500000: 'Direct3D'\n0x500100: 'D3DDevice'")

    with patch("harness.tools.retools_wrap.run_subprocess", mock):
        from harness.tools.retools_wrap import search
        inp = SearchInput(binary="game.exe", mode="strings", query="d3d", min_len=3)
        result = event_loop.run_until_complete(search(inp))

    assert result.count == 2
    cmd = mock.call_args[0][0]
    assert "--min-len" in cmd
    assert "3" in cmd


def test_dx9_script_valid(event_loop):
    mock = _mock_subprocess(stdout="Found 15 D3D calls")

    with patch("harness.tools.dx9_scripts_wrap.run_subprocess", mock):
        from harness.tools.dx9_scripts_wrap import dx9_script
        inp = DX9ScriptInput(binary="game.exe", script="find_d3d_calls")
        result = event_loop.run_until_complete(dx9_script(inp))

    assert "15 D3D calls" in result.output
    assert result.error is None


def test_dx9_script_invalid(event_loop):
    from harness.tools.dx9_scripts_wrap import dx9_script
    inp = DX9ScriptInput(binary="game.exe", script="not_a_real_script")
    result = event_loop.run_until_complete(dx9_script(inp))

    assert result.error is not None
    assert "Unknown script" in result.error
