"""MCP server — exposes the harness as MCP tools for Claude Code / Cursor.

High-level tools that invoke the orchestrator, which dispatches to workers.
Runs as a FastAPI app with SSE transport on port 8080.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from harness.agents.orchestrator import OrchestratorAgent
from harness.agents.worker import WorkerAgent
from harness.config import Config, load_config
from harness.rag.indexer import RAGIndexer
from harness.rag.query import RAGQuery
from harness.state.project import ProjectManager
from harness.state.session import SessionState
from harness.tools.registry import build_registry

logger = logging.getLogger(__name__)

# Global state — initialized on startup
_config: Config | None = None
_orchestrator: OrchestratorAgent | None = None
_project_mgr: ProjectManager | None = None
_session: SessionState | None = None
_registry = None


def _init_harness(config: Config | None = None) -> None:
    """Initialize all harness components."""
    global _config, _orchestrator, _project_mgr, _session, _registry

    _config = config or load_config()
    _registry = build_registry()
    _session = SessionState()
    _project_mgr = ProjectManager(_config.repo_root_path)

    # Set repo root on all tool modules
    from harness.tools import retools_wrap, livetools_wrap, dx9_scripts_wrap, file_tools
    root = str(_config.repo_root_path)
    retools_wrap.set_repo_root(root)
    livetools_wrap.set_repo_root(root)
    dx9_scripts_wrap.set_repo_root(root)
    file_tools.set_repo_root(root)

    # RAG
    rag_query = RAGQuery(_config.rag.persist_dir)

    # Worker + Orchestrator
    worker = WorkerAgent(_config, _registry)
    _orchestrator = OrchestratorAgent(
        _config, _registry, worker,
        rag_query_fn=rag_query.query,
    )


# ── MCP Tool Handlers ────────────────────────────────────────────────────────

async def handle_re_analyze(goal: str, project: str | None = None) -> dict[str, Any]:
    """Natural language goal → full orchestrated analysis."""
    if _orchestrator is None:
        _init_harness()

    if project and _project_mgr:
        _project_mgr.create(project)

    context = _project_mgr.get_context_string() if _project_mgr else ""
    result = await _orchestrator.run(goal, project_context=context)

    steps_summary = []
    for step in result.steps:
        steps_summary.append({
            "tool": step.task.tool_name,
            "success": step.success,
            "output_preview": step.output[:500] if step.output else "",
            "error": step.error,
        })

    return {
        "goal": result.goal,
        "steps": steps_summary,
        "synthesis": result.synthesis,
    }


async def handle_re_decompile(binary: str, va: str, project: str | None = None) -> dict:
    """Decompile a function — wraps decompiler + context + postprocess."""
    if _orchestrator is None:
        _init_harness()

    types_arg = None
    if project and _project_mgr:
        proj = _project_mgr.create(project)
        if proj.bootstrapped:
            types_arg = proj.kb_path

    from harness.validation.schemas import DecompileInput
    from harness.tools.retools_wrap import decompile
    inp = DecompileInput(binary=binary, va=va, types=types_arg, project=project)
    result = await decompile(inp)
    return result.model_dump()


async def handle_re_search(binary: str, mode: str, query: str = "") -> dict:
    """Search binary for strings, patterns, imports."""
    if _orchestrator is None:
        _init_harness()

    from harness.validation.schemas import SearchInput
    from harness.tools.retools_wrap import search
    inp = SearchInput(binary=binary, mode=mode, query=query)
    result = await search(inp)
    return result.model_dump()


async def handle_re_bootstrap(binary: str, project: str) -> dict:
    """Run full bootstrap pipeline on a binary."""
    if _orchestrator is None:
        _init_harness()

    from harness.validation.schemas import BootstrapInput
    from harness.tools.retools_wrap import bootstrap
    inp = BootstrapInput(binary=binary, project=project)
    result = await bootstrap(inp)
    return result.model_dump()


async def handle_re_dx9_scan(binary: str, script: str) -> dict:
    """Run a DX9 analysis script."""
    if _orchestrator is None:
        _init_harness()

    from harness.validation.schemas import DX9ScriptInput
    from harness.tools.dx9_scripts_wrap import dx9_script
    inp = DX9ScriptInput(binary=binary, script=script)
    result = await dx9_script(inp)
    return result.model_dump()


async def handle_re_status() -> dict:
    """Get project state, session costs, connections."""
    return {
        "session": _session.summary() if _session else "not initialized",
        "project": _project_mgr.get_context_string() if _project_mgr else "none",
        "tools": _registry.list_categories() if _registry else [],
    }


# ── MCP Tool Definitions ────────────────────────────────────────────────────

MCP_TOOLS = {
    "re_analyze": {
        "description": "Submit a natural language analysis goal. The orchestrator plans and executes multi-step analysis.",
        "parameters": {"goal": "string", "project": "string (optional)"},
        "handler": handle_re_analyze,
    },
    "re_decompile": {
        "description": "Decompile a function at a virtual address.",
        "parameters": {"binary": "string", "va": "string", "project": "string (optional)"},
        "handler": handle_re_decompile,
    },
    "re_search": {
        "description": "Search binary for strings, imports, patterns, or instructions.",
        "parameters": {"binary": "string", "mode": "string", "query": "string"},
        "handler": handle_re_search,
    },
    "re_bootstrap": {
        "description": "Bootstrap a binary — seeds KB with signatures, RTTI, imports.",
        "parameters": {"binary": "string", "project": "string"},
        "handler": handle_re_bootstrap,
    },
    "re_dx9_scan": {
        "description": "Run a DX9 analysis script on a binary.",
        "parameters": {"binary": "string", "script": "string"},
        "handler": handle_re_dx9_scan,
    },
    "re_status": {
        "description": "Get session status, costs, and project state.",
        "parameters": {},
        "handler": handle_re_status,
    },
}


# ── FastAPI App ──────────────────────────────────────────────────────────────

def create_app(config: Config | None = None):
    """Create the FastAPI MCP server app."""
    try:
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
    except ImportError:
        logger.error("fastapi not installed — cannot create MCP server")
        return None

    _init_harness(config)

    app = FastAPI(title="Vibe RE Harness MCP Server", version="0.1.0")

    @app.get("/health")
    async def health():
        return {"status": "ok", "tools": list(MCP_TOOLS.keys())}

    @app.get("/tools")
    async def list_tools():
        tools = []
        for name, spec in MCP_TOOLS.items():
            tools.append({
                "name": name,
                "description": spec["description"],
                "parameters": spec["parameters"],
            })
        return {"tools": tools}

    @app.post("/call/{tool_name}")
    async def call_tool(tool_name: str, request: Request):
        if tool_name not in MCP_TOOLS:
            return JSONResponse(
                status_code=404,
                content={"error": f"Unknown tool: {tool_name}"},
            )
        body = await request.json()
        handler = MCP_TOOLS[tool_name]["handler"]
        try:
            result = await handler(**body)
            return {"result": result}
        except Exception as e:
            logger.exception("Tool call failed: %s", tool_name)
            return JSONResponse(
                status_code=500,
                content={"error": str(e)},
            )

    return app
