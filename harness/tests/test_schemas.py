"""Tests for Pydantic input/output schemas."""

import pytest
from harness.validation.schemas import (
    BootstrapInput, BootstrapOutput,
    DecompileInput, DecompileOutput,
    DX9ScriptInput, DX9ScriptOutput,
    LiveTraceInput,
    SearchInput, SearchOutput,
    ToolError,
    XrefsInput, XrefsOutput,
)


def test_decompile_input_defaults():
    inp = DecompileInput(binary="game.exe", va="0x401000")
    assert inp.backend == "auto"
    assert inp.types is None
    assert inp.project is None


def test_decompile_input_full():
    inp = DecompileInput(
        binary="game.exe",
        va="0x401000",
        backend="pdg",
        types="patches/Game/kb.h",
        project="patches/Game",
    )
    assert inp.backend == "pdg"
    assert inp.types == "patches/Game/kb.h"


def test_decompile_output():
    out = DecompileOutput(pseudocode="int func() { return 0; }")
    assert out.error is None
    assert "func" in out.pseudocode


def test_decompile_output_with_error():
    out = DecompileOutput(pseudocode="", error="Function not found")
    assert out.error == "Function not found"


def test_bootstrap_input():
    inp = BootstrapInput(binary="game.exe", project="patches/Game")
    assert inp.binary == "game.exe"


def test_xrefs_input():
    inp = XrefsInput(binary="game.exe", target="0x401000", indirect=True)
    assert inp.indirect is True


def test_search_input():
    inp = SearchInput(binary="game.exe", mode="strings", query="d3d")
    assert inp.min_len == 4


def test_dx9_script_input():
    inp = DX9ScriptInput(binary="game.exe", script="find_d3d_calls")
    assert inp.extra_args == []


def test_live_trace_input():
    inp = LiveTraceInput(va="0x401000", count=20, read="ecx; [esp+4]:12:float32")
    assert inp.count == 20


def test_tool_error():
    err = ToolError(error="timeout", raw_output="partial", retries_exhausted=True)
    assert err.retries_exhausted


def test_json_roundtrip():
    inp = DecompileInput(binary="game.exe", va="0x401000")
    json_str = inp.model_dump_json()
    restored = DecompileInput.model_validate_json(json_str)
    assert restored.binary == inp.binary
    assert restored.va == inp.va
