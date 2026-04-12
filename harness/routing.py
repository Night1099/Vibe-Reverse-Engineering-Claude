"""Task routing — classifies which tasks go to the orchestrator vs worker.

Routing rule: if the task is a single tool call with well-defined inputs,
route to the worker. If it requires choosing between tools, interpreting
ambiguous output, or making judgment calls, route to the orchestrator.
"""

from __future__ import annotations

from enum import Enum


class TaskType(Enum):
    WORKER = "worker"
    ORCHESTRATOR = "orchestrator"


# Tools that are always executed by the worker (single-tool, mechanical)
WORKER_TOOLS = {
    # retools — all single-invocation analysis tools
    "bootstrap", "decompile", "xrefs", "callgraph", "search",
    "dataflow_constants", "dataflow_slice", "context_assemble",
    "sigdb_fingerprint", "sigdb_identify", "disasm", "funcinfo",
    "readmem", "rtti", "vtable", "datarefs", "structrefs", "cfg",
    "throwmap", "dumpinfo", "pyghidra_analyze", "pyghidra_status",
    "asi_patcher_build",
    # dx9 scripts
    "dx9_script", "dx9_tracer_trigger", "dx9_tracer_analyze",
    # file I/O
    "read_file", "write_file",
}

# Tools that the orchestrator handles directly (require session awareness)
ORCHESTRATOR_TOOLS = {
    "live_attach", "live_detach", "live_status",
    "live_trace", "live_bp",
    "live_mem_read", "live_mem_write",
    "live_regs", "live_stack", "live_modules", "live_scan",
}


class TaskRouter:
    """Classifies tasks for routing to worker or orchestrator."""

    def classify(self, tool_name: str) -> TaskType:
        """Determine whether a tool call should go to worker or orchestrator."""
        if tool_name in ORCHESTRATOR_TOOLS:
            return TaskType.ORCHESTRATOR
        if tool_name in WORKER_TOOLS:
            return TaskType.WORKER
        # Unknown tools default to orchestrator for safety
        return TaskType.ORCHESTRATOR

    def is_worker_task(self, tool_name: str) -> bool:
        return self.classify(tool_name) == TaskType.WORKER

    def is_orchestrator_task(self, tool_name: str) -> bool:
        return self.classify(tool_name) == TaskType.ORCHESTRATOR
