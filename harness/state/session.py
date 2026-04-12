"""Session state — conversation history and cost tracking."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class CostEntry:
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()


# Approximate per-token costs (USD per 1K tokens) as of April 2026
MODEL_COSTS = {
    "claude-opus-4-6": {"input": 0.015, "output": 0.075},
    "claude-sonnet-4-20250514": {"input": 0.003, "output": 0.015},
    "gpt-5": {"input": 0.01, "output": 0.03},
    "o3": {"input": 0.01, "output": 0.04},
    # Local models via Ollama: $0
    "qwen3:30b-a3b": {"input": 0.0, "output": 0.0},
    "qwen3:32b": {"input": 0.0, "output": 0.0},
    "gemma4:26b": {"input": 0.0, "output": 0.0},
}


@dataclass
class SessionState:
    """Tracks costs and usage for a harness session."""
    costs: list[CostEntry] = field(default_factory=list)
    start_time: float = 0.0
    task_count: int = 0
    worker_calls: int = 0
    orchestrator_calls: int = 0

    def __post_init__(self):
        if self.start_time == 0.0:
            self.start_time = time.time()

    def record_call(self, model: str, input_tokens: int = 0, output_tokens: int = 0) -> None:
        costs = MODEL_COSTS.get(model, {"input": 0.001, "output": 0.005})
        est_cost = (
            input_tokens / 1000 * costs["input"]
            + output_tokens / 1000 * costs["output"]
        )
        self.costs.append(CostEntry(
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=est_cost,
        ))
        self.task_count += 1

    @property
    def total_cost_usd(self) -> float:
        return sum(c.estimated_cost_usd for c in self.costs)

    @property
    def duration_sec(self) -> float:
        return time.time() - self.start_time

    def summary(self) -> str:
        local = sum(1 for c in self.costs if c.estimated_cost_usd == 0)
        cloud = len(self.costs) - local
        return (
            f"Session: {self.task_count} tasks, "
            f"{local} local / {cloud} cloud calls, "
            f"${self.total_cost_usd:.4f} estimated, "
            f"{self.duration_sec:.0f}s elapsed"
        )
