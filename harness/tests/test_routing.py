"""Tests for task routing logic."""

from harness.routing import TaskRouter, TaskType


def test_worker_tools():
    router = TaskRouter()
    worker_tools = [
        "decompile", "xrefs", "callgraph", "search", "bootstrap",
        "dx9_script", "read_file", "write_file",
    ]
    for tool in worker_tools:
        assert router.classify(tool) == TaskType.WORKER, f"{tool} should be WORKER"


def test_orchestrator_tools():
    router = TaskRouter()
    orch_tools = [
        "live_attach", "live_detach", "live_trace", "live_bp",
        "live_mem_read", "live_mem_write", "live_regs", "live_status",
    ]
    for tool in orch_tools:
        assert router.classify(tool) == TaskType.ORCHESTRATOR, f"{tool} should be ORCHESTRATOR"


def test_unknown_defaults_to_orchestrator():
    router = TaskRouter()
    assert router.classify("unknown_tool") == TaskType.ORCHESTRATOR


def test_convenience_methods():
    router = TaskRouter()
    assert router.is_worker_task("decompile")
    assert not router.is_worker_task("live_attach")
    assert router.is_orchestrator_task("live_trace")
    assert not router.is_orchestrator_task("xrefs")
