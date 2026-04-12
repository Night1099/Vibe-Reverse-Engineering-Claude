"""Pydantic AI tool wrappers for all 22 retools modules.

Each tool executes via subprocess (`python -m retools.<module>`) for isolation.
All commands run from repo root. Always pass --types kb.h when available.
"""

from __future__ import annotations

from harness.tools.base import SubprocessResult, run_subprocess
from harness.validation.schemas import (
    AsiPatcherInput, AsiPatcherOutput,
    BootstrapInput, BootstrapOutput,
    CallgraphInput, CallgraphOutput,
    CfgInput, CfgOutput,
    ContextInput, ContextOutput,
    DataflowConstantsInput, DataflowOutput, DataflowSliceInput,
    DatarefsInput, DatarefsOutput,
    DecompileInput, DecompileOutput,
    DisasmInput, DisasmOutput,
    DumpinfoInput, DumpinfoOutput,
    FuncinfoInput, FuncinfoOutput,
    PyghidraAnalyzeInput, PyghidraOutput, PyghidraStatusInput,
    ReadmemInput, ReadmemOutput,
    RttiInput, RttiOutput,
    SearchInput, SearchOutput,
    SigdbFingerprintInput, SigdbIdentifyInput, SigdbOutput,
    StructrefsInput, StructrefsOutput,
    ThrowmapInput, ThrowmapOutput,
    VtableInput, VtableOutput,
    XrefsInput, XrefsOutput,
)

# Repo root is set at runtime via config; default to cwd
_repo_root: str = "."


def set_repo_root(path: str) -> None:
    global _repo_root
    _repo_root = path


def _result_text(r: SubprocessResult) -> tuple[str, str | None]:
    """Extract output text and error from subprocess result."""
    text = r.stdout.strip()
    err = r.stderr.strip() if r.returncode != 0 else None
    if r.timed_out:
        err = r.stderr
    return text, err


# ── bootstrap ────────────────────────────────────────────────────────────────

async def bootstrap(inp: BootstrapInput) -> BootstrapOutput:
    """Run retools.bootstrap to seed KB with signatures, RTTI, imports."""
    cmd = ["python", "-m", "retools.bootstrap", inp.binary, "--project", inp.project]
    r = await run_subprocess(cmd, cwd=_repo_root, timeout=300)
    text, err = _result_text(r)
    kb_path = f"{inp.project}/kb.h"
    return BootstrapOutput(report=text, kb_path=kb_path, error=err)


# ── decompiler ───────────────────────────────────────────────────────────────

async def decompile(inp: DecompileInput) -> DecompileOutput:
    """Decompile a function at the given VA."""
    cmd = ["python", "-m", "retools.decompiler", inp.binary, inp.va]
    if inp.types:
        cmd += ["--types", inp.types]
    if inp.backend != "auto":
        cmd += ["--backend", inp.backend]
    if inp.project:
        cmd += ["--project", inp.project]
    r = await run_subprocess(cmd, cwd=_repo_root, timeout=120)
    text, err = _result_text(r)
    return DecompileOutput(pseudocode=text, error=err)


# ── xrefs ────────────────────────────────────────────────────────────────────

async def xrefs(inp: XrefsInput) -> XrefsOutput:
    """Find cross-references to a virtual address."""
    cmd = ["python", "-m", "retools.xrefs", inp.binary, inp.target]
    if inp.indirect:
        cmd.append("--indirect")
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    count = text.count("\n") + 1 if text else 0
    return XrefsOutput(refs=text, count=count, error=err)


# ── callgraph ────────────────────────────────────────────────────────────────

async def callgraph(inp: CallgraphInput) -> CallgraphOutput:
    """Build caller/callee tree for a function."""
    cmd = ["python", "-m", "retools.callgraph", inp.binary, inp.va]
    cmd += ["--depth", str(inp.depth)]
    if inp.direction != "both":
        cmd += ["--direction", inp.direction]
    if inp.indirect:
        cmd.append("--indirect")
    if inp.types:
        cmd += ["--types", inp.types]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return CallgraphOutput(graph=text, error=err)


# ── search ───────────────────────────────────────────────────────────────────

async def search(inp: SearchInput) -> SearchOutput:
    """Search binary for strings, imports, patterns, or instructions."""
    cmd = ["python", "-m", "retools.search", inp.binary, inp.mode]
    if inp.query:
        cmd.append(inp.query)
    if inp.mode == "strings":
        cmd += ["--min-len", str(inp.min_len)]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    count = text.count("\n") + 1 if text else 0
    return SearchOutput(results=text, count=count, error=err)


# ── dataflow ─────────────────────────────────────────────────────────────────

async def dataflow_constants(inp: DataflowConstantsInput) -> DataflowOutput:
    """Forward constant propagation for a function."""
    cmd = ["python", "-m", "retools.dataflow", inp.binary, inp.va, "--constants"]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return DataflowOutput(analysis=text, error=err)


async def dataflow_slice(inp: DataflowSliceInput) -> DataflowOutput:
    """Backward register slice to a target."""
    cmd = ["python", "-m", "retools.dataflow", inp.binary, inp.va, "--slice", inp.target]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return DataflowOutput(analysis=text, error=err)


# ── context ──────────────────────────────────────────────────────────────────

async def context_assemble(inp: ContextInput) -> ContextOutput:
    """Gather full analysis context for a function."""
    cmd = ["python", "-m", "retools.context", "assemble", inp.binary, inp.va]
    if inp.project:
        cmd += ["--project", inp.project]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return ContextOutput(context=text, error=err)


# ── sigdb ────────────────────────────────────────────────────────────────────

async def sigdb_fingerprint(inp: SigdbFingerprintInput) -> SigdbOutput:
    """Identify compiler/linker from binary."""
    cmd = ["python", "-m", "retools.sigdb", "fingerprint", inp.binary]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return SigdbOutput(result=text, error=err)


async def sigdb_identify(inp: SigdbIdentifyInput) -> SigdbOutput:
    """Look up a single function signature."""
    cmd = ["python", "-m", "retools.sigdb", "identify", inp.binary, inp.va]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return SigdbOutput(result=text, error=err)


# ── disasm ───────────────────────────────────────────────────────────────────

async def disasm(inp: DisasmInput) -> DisasmOutput:
    """Disassemble instructions at a VA."""
    cmd = ["python", "-m", "retools.disasm", inp.binary, inp.va, "--count", str(inp.count)]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return DisasmOutput(disassembly=text, error=err)


# ── funcinfo ─────────────────────────────────────────────────────────────────

async def funcinfo(inp: FuncinfoInput) -> FuncinfoOutput:
    """Get function boundary and metadata."""
    cmd = ["python", "-m", "retools.funcinfo", inp.binary, inp.va]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return FuncinfoOutput(info=text, error=err)


# ── readmem ──────────────────────────────────────────────────────────────────

async def readmem(inp: ReadmemInput) -> ReadmemOutput:
    """Read typed data from PE at a VA."""
    cmd = ["python", "-m", "retools.readmem", inp.binary, inp.va, inp.type_spec]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return ReadmemOutput(value=text, error=err)


# ── rtti ─────────────────────────────────────────────────────────────────────

async def rtti(inp: RttiInput) -> RttiOutput:
    """RTTI class hierarchy analysis."""
    cmd = ["python", "-m", "retools.rtti", inp.binary]
    if inp.va:
        cmd.append(inp.va)
    r = await run_subprocess(cmd, cwd=_repo_root, timeout=180)
    text, err = _result_text(r)
    return RttiOutput(result=text, error=err)


# ── vtable ───────────────────────────────────────────────────────────────────

async def vtable(inp: VtableInput) -> VtableOutput:
    """Resolve vtable at a VA."""
    cmd = ["python", "-m", "retools.vtable", inp.binary, inp.va]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return VtableOutput(result=text, error=err)


# ── datarefs ─────────────────────────────────────────────────────────────────

async def datarefs(inp: DatarefsInput) -> DatarefsOutput:
    """Find data references to a VA."""
    cmd = ["python", "-m", "retools.datarefs", inp.binary, inp.va]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return DatarefsOutput(refs=text, error=err)


# ── structrefs ───────────────────────────────────────────────────────────────

async def structrefs(inp: StructrefsInput) -> StructrefsOutput:
    """Find references to struct fields."""
    cmd = ["python", "-m", "retools.structrefs", inp.binary, inp.struct_name]
    if inp.types:
        cmd += ["--types", inp.types]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return StructrefsOutput(refs=text, error=err)


# ── cfg ──────────────────────────────────────────────────────────────────────

async def cfg(inp: CfgInput) -> CfgOutput:
    """Build control flow graph for a function."""
    cmd = ["python", "-m", "retools.cfg", inp.binary, inp.va]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return CfgOutput(cfg=text, error=err)


# ── throwmap ─────────────────────────────────────────────────────────────────

async def throwmap(inp: ThrowmapInput) -> ThrowmapOutput:
    """Match crash addresses to exception handlers."""
    cmd = ["python", "-m", "retools.throwmap", inp.binary]
    if inp.dumpfile:
        cmd.append(inp.dumpfile)
    r = await run_subprocess(cmd, cwd=_repo_root, timeout=180)
    text, err = _result_text(r)
    return ThrowmapOutput(result=text, error=err)


# ── dumpinfo ─────────────────────────────────────────────────────────────────

async def dumpinfo(inp: DumpinfoInput) -> DumpinfoOutput:
    """Analyze a minidump crash dump."""
    cmd = ["python", "-m", "retools.dumpinfo", inp.dumpfile]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return DumpinfoOutput(result=text, error=err)


# ── pyghidra_backend ─────────────────────────────────────────────────────────

async def pyghidra_analyze(inp: PyghidraAnalyzeInput) -> PyghidraOutput:
    """Run full Ghidra analysis on a binary (long-running)."""
    cmd = ["python", "-m", "retools.pyghidra_backend", "analyze",
           inp.binary, "--project", inp.project]
    r = await run_subprocess(cmd, cwd=_repo_root, timeout=900)
    text, err = _result_text(r)
    return PyghidraOutput(result=text, error=err)


async def pyghidra_status(inp: PyghidraStatusInput) -> PyghidraOutput:
    """Check if a Ghidra project exists."""
    cmd = ["python", "-m", "retools.pyghidra_backend", "status", "--project", inp.project]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return PyghidraOutput(result=text, error=err)


# ── asi_patcher ──────────────────────────────────────────────────────────────

async def asi_patcher_build(inp: AsiPatcherInput) -> AsiPatcherOutput:
    """Build an ASI patch DLL from spec."""
    cmd = ["python", "-m", "retools.asi_patcher", "build", inp.spec_file]
    r = await run_subprocess(cmd, cwd=_repo_root)
    text, err = _result_text(r)
    return AsiPatcherOutput(result=text, error=err)


# ── Tool registry entry ─────────────────────────────────────────────────────

ALL_RETOOLS = {
    "bootstrap": (BootstrapInput, BootstrapOutput, bootstrap),
    "decompile": (DecompileInput, DecompileOutput, decompile),
    "xrefs": (XrefsInput, XrefsOutput, xrefs),
    "callgraph": (CallgraphInput, CallgraphOutput, callgraph),
    "search": (SearchInput, SearchOutput, search),
    "dataflow_constants": (DataflowConstantsInput, DataflowOutput, dataflow_constants),
    "dataflow_slice": (DataflowSliceInput, DataflowOutput, dataflow_slice),
    "context_assemble": (ContextInput, ContextOutput, context_assemble),
    "sigdb_fingerprint": (SigdbFingerprintInput, SigdbOutput, sigdb_fingerprint),
    "sigdb_identify": (SigdbIdentifyInput, SigdbOutput, sigdb_identify),
    "disasm": (DisasmInput, DisasmOutput, disasm),
    "funcinfo": (FuncinfoInput, FuncinfoOutput, funcinfo),
    "readmem": (ReadmemInput, ReadmemOutput, readmem),
    "rtti": (RttiInput, RttiOutput, rtti),
    "vtable": (VtableInput, VtableOutput, vtable),
    "datarefs": (DatarefsInput, DatarefsOutput, datarefs),
    "structrefs": (StructrefsInput, StructrefsOutput, structrefs),
    "cfg": (CfgInput, CfgOutput, cfg),
    "throwmap": (ThrowmapInput, ThrowmapOutput, throwmap),
    "dumpinfo": (DumpinfoInput, DumpinfoOutput, dumpinfo),
    "pyghidra_analyze": (PyghidraAnalyzeInput, PyghidraOutput, pyghidra_analyze),
    "pyghidra_status": (PyghidraStatusInput, PyghidraOutput, pyghidra_status),
    "asi_patcher_build": (AsiPatcherInput, AsiPatcherOutput, asi_patcher_build),
}
