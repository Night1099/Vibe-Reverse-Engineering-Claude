"""Pydantic input/output models for all wrapped tools.

Flat schemas only — local models struggle with deeply nested structures.
Complex data (callgraph trees, JSONL arrays) goes as serialized JSON strings.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


# ── Shared ────────────────────────────────────────────────────────────────────

class ToolError(BaseModel):
    """Returned when a tool call fails after retries."""
    error: str
    raw_output: str = ""
    retries_exhausted: bool = False


# ── retools: bootstrap ────────────────────────────────────────────────────────

class BootstrapInput(BaseModel):
    binary: str = Field(description="Path to PE binary")
    project: str = Field(description="Project dir under patches/, e.g. 'patches/MyGame'")

class BootstrapOutput(BaseModel):
    report: str = Field(description="Bootstrap report text")
    kb_path: str = Field(description="Path to generated kb.h")
    error: str | None = None


# ── retools: decompiler ──────────────────────────────────────────────────────

class DecompileInput(BaseModel):
    binary: str
    va: str = Field(description="Hex virtual address, e.g. '0x401000'")
    backend: str = "auto"
    types: str | None = Field(default=None, description="Path to kb.h")
    project: str | None = None

class DecompileOutput(BaseModel):
    pseudocode: str
    error: str | None = None


# ── retools: xrefs ───────────────────────────────────────────────────────────

class XrefsInput(BaseModel):
    binary: str
    target: str = Field(description="Hex VA to find references to")
    indirect: bool = False

class XrefsOutput(BaseModel):
    refs: str = Field(description="Cross-reference listing text")
    count: int = 0
    error: str | None = None


# ── retools: callgraph ───────────────────────────────────────────────────────

class CallgraphInput(BaseModel):
    binary: str
    va: str
    depth: int = 2
    direction: str = "both"
    indirect: bool = False
    types: str | None = None

class CallgraphOutput(BaseModel):
    graph: str = Field(description="Callgraph text (serialized)")
    error: str | None = None


# ── retools: search ──────────────────────────────────────────────────────────

class SearchInput(BaseModel):
    binary: str
    mode: str = Field(description="Search mode: strings, imports, pattern, instruction")
    query: str = Field(default="", description="Search query/pattern")
    min_len: int = 4

class SearchOutput(BaseModel):
    results: str = Field(description="Search results text")
    count: int = 0
    error: str | None = None


# ── retools: dataflow ────────────────────────────────────────────────────────

class DataflowConstantsInput(BaseModel):
    binary: str
    va: str

class DataflowSliceInput(BaseModel):
    binary: str
    va: str
    target: str = Field(description="TARGET_VA:REG, e.g. '0x401050:eax'")

class DataflowOutput(BaseModel):
    analysis: str
    error: str | None = None


# ── retools: context ─────────────────────────────────────────────────────────

class ContextInput(BaseModel):
    binary: str
    va: str
    project: str | None = None

class ContextOutput(BaseModel):
    context: str = Field(description="Full analysis context for the function")
    error: str | None = None


# ── retools: sigdb ───────────────────────────────────────────────────────────

class SigdbFingerprintInput(BaseModel):
    binary: str

class SigdbIdentifyInput(BaseModel):
    binary: str
    va: str

class SigdbOutput(BaseModel):
    result: str
    error: str | None = None


# ── retools: disasm ──────────────────────────────────────────────────────────

class DisasmInput(BaseModel):
    binary: str
    va: str
    count: int = 30

class DisasmOutput(BaseModel):
    disassembly: str
    error: str | None = None


# ── retools: funcinfo ────────────────────────────────────────────────────────

class FuncinfoInput(BaseModel):
    binary: str
    va: str

class FuncinfoOutput(BaseModel):
    info: str
    error: str | None = None


# ── retools: readmem ─────────────────────────────────────────────────────────

class ReadmemInput(BaseModel):
    binary: str
    va: str
    type_spec: str = Field(description="C type like 'uint32' or 'char[64]'")

class ReadmemOutput(BaseModel):
    value: str
    error: str | None = None


# ── retools: rtti ────────────────────────────────────────────────────────────

class RttiInput(BaseModel):
    binary: str
    va: str | None = None

class RttiOutput(BaseModel):
    result: str
    error: str | None = None


# ── retools: vtable ──────────────────────────────────────────────────────────

class VtableInput(BaseModel):
    binary: str
    va: str

class VtableOutput(BaseModel):
    result: str
    error: str | None = None


# ── retools: datarefs ────────────────────────────────────────────────────────

class DatarefsInput(BaseModel):
    binary: str
    va: str

class DatarefsOutput(BaseModel):
    refs: str
    error: str | None = None


# ── retools: structrefs ──────────────────────────────────────────────────────

class StructrefsInput(BaseModel):
    binary: str
    struct_name: str
    types: str | None = None

class StructrefsOutput(BaseModel):
    refs: str
    error: str | None = None


# ── retools: cfg ─────────────────────────────────────────────────────────────

class CfgInput(BaseModel):
    binary: str
    va: str

class CfgOutput(BaseModel):
    cfg: str = Field(description="Control flow graph data")
    error: str | None = None


# ── retools: throwmap ────────────────────────────────────────────────────────

class ThrowmapInput(BaseModel):
    binary: str
    dumpfile: str | None = None

class ThrowmapOutput(BaseModel):
    result: str
    error: str | None = None


# ── retools: dumpinfo ────────────────────────────────────────────────────────

class DumpinfoInput(BaseModel):
    dumpfile: str

class DumpinfoOutput(BaseModel):
    result: str
    error: str | None = None


# ── retools: pyghidra_backend ────────────────────────────────────────────────

class PyghidraAnalyzeInput(BaseModel):
    binary: str
    project: str

class PyghidraStatusInput(BaseModel):
    project: str

class PyghidraOutput(BaseModel):
    result: str
    error: str | None = None


# ── retools: asi_patcher ─────────────────────────────────────────────────────

class AsiPatcherInput(BaseModel):
    spec_file: str

class AsiPatcherOutput(BaseModel):
    result: str
    error: str | None = None


# ── livetools ────────────────────────────────────────────────────────────────

class LiveAttachInput(BaseModel):
    target: str = Field(description="Process name, PID, or exe path")
    spawn: bool = False

class LiveDetachInput(BaseModel):
    pass

class LiveTraceInput(BaseModel):
    va: str
    count: int = 10
    read: str | None = Field(default=None, description="Register read spec")
    output: str | None = None

class LiveBpInput(BaseModel):
    action: str = Field(description="add, del, or list")
    va: str | None = None
    on_hit: str | None = None

class LiveMemReadInput(BaseModel):
    va: str
    size: int = 64
    format: str = "hex"

class LiveMemWriteInput(BaseModel):
    va: str
    data: str = Field(description="Hex bytes or value")

class LiveRegsInput(BaseModel):
    pass

class LiveStackInput(BaseModel):
    count: int = 16

class LiveModulesInput(BaseModel):
    pass

class LiveScanInput(BaseModel):
    pattern: str
    region: str | None = None

class LiveStatusOutput(BaseModel):
    target: str = ""
    pid: int = 0
    state: str = "UNKNOWN"
    bp_count: int = 0

class LiveGenericOutput(BaseModel):
    result: str
    error: str | None = None


# ── DX9 scripts ──────────────────────────────────────────────────────────────

class DX9ScriptInput(BaseModel):
    binary: str
    script: str = Field(description="Script name without .py, e.g. 'find_d3d_calls'")
    extra_args: list[str] = Field(default_factory=list)

class DX9ScriptOutput(BaseModel):
    output: str
    error: str | None = None


# ── DX9 tracer ───────────────────────────────────────────────────────────────

class DX9TracerTriggerInput(BaseModel):
    game_dir: str
    frames: int = 1

class DX9TracerAnalyzeInput(BaseModel):
    jsonl_path: str
    analysis: str = Field(description="Analysis type: summary, render-passes, shader-map, etc.")

class DX9TracerOutput(BaseModel):
    output: str
    error: str | None = None


# ── File tools ───────────────────────────────────────────────────────────────

class ReadFileInput(BaseModel):
    path: str

class ReadFileOutput(BaseModel):
    content: str
    error: str | None = None

class WriteFileInput(BaseModel):
    path: str
    content: str
    append: bool = False

class WriteFileOutput(BaseModel):
    success: bool
    error: str | None = None
