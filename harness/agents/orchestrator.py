"""Orchestrator agent — plans analysis and dispatches to workers.

Runs on Claude Opus / GPT-5 via LiteLLM. Owns the planning loop:
receive goal → RAG for tool discovery → plan tasks → dispatch → synthesize.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from harness.agents.prompts import ORCHESTRATOR_SYSTEM_PROMPT
from harness.agents.worker import WorkerAgent
from harness.config import Config
from harness.routing import TaskRouter, TaskType
from harness.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class TaskSpec(BaseModel):
    """A single task to dispatch to a worker."""
    tool_name: str
    tool_input: dict[str, Any]
    description: str = ""


class AnalysisPlan(BaseModel):
    """Orchestrator's plan for achieving a user goal."""
    goal: str
    tasks: list[TaskSpec]
    reasoning: str = ""


@dataclass
class StepResult:
    task: TaskSpec
    success: bool
    output: str
    error: str | None = None


@dataclass
class AnalysisResult:
    goal: str
    steps: list[StepResult] = field(default_factory=list)
    synthesis: str = ""
    total_cost: float = 0.0


class OrchestratorAgent:
    """Plans and executes multi-step reverse engineering analysis."""

    def __init__(
        self,
        config: Config,
        registry: ToolRegistry,
        worker: WorkerAgent,
        rag_query_fn=None,
    ):
        self.config = config
        self.registry = registry
        self.worker = worker
        self.router = TaskRouter()
        self.rag_query_fn = rag_query_fn
        self._agent = None

    def _ensure_agent(self):
        if self._agent is not None:
            return
        try:
            from pydantic_ai import Agent

            model_str = self.config.orchestrator_model_string()
            self._agent = Agent(
                model_str,
                system_prompt=ORCHESTRATOR_SYSTEM_PROMPT,
            )
        except ImportError:
            logger.warning("pydantic-ai not installed; orchestrator unavailable")

    async def plan(self, goal: str, project_context: str = "") -> AnalysisPlan:
        """Generate an analysis plan for a user goal.

        If the LLM is available, uses it for planning.
        Otherwise, returns a simple single-step plan.
        """
        self._ensure_agent()

        # Enrich context with RAG
        tool_context = ""
        if self.rag_query_fn:
            try:
                chunks = await self.rag_query_fn(goal, top_k=5)
                tool_context = "\n\n".join(chunks)
            except Exception as e:
                logger.warning("RAG query failed: %s", e)

        if self._agent is not None:
            return await self._llm_plan(goal, project_context, tool_context)
        return self._fallback_plan(goal)

    async def _llm_plan(
        self, goal: str, project_context: str, tool_context: str
    ) -> AnalysisPlan:
        """Use the orchestrator LLM to generate a plan."""
        available_tools = self.registry.describe_all()

        prompt = (
            f"Goal: {goal}\n\n"
            f"Available tools:\n{available_tools}\n\n"
        )
        if tool_context:
            prompt += f"Relevant tool documentation:\n{tool_context}\n\n"
        if project_context:
            prompt += f"Project context:\n{project_context}\n\n"
        prompt += (
            "Create an analysis plan as JSON with this schema:\n"
            '{"goal": "...", "tasks": [{"tool_name": "...", "tool_input": {...}, '
            '"description": "..."}], "reasoning": "..."}\n'
            "Return ONLY the JSON."
        )

        try:
            result = await self._agent.run(prompt)
            raw = str(result.data)
            # Try to extract JSON from the response
            if "```json" in raw:
                raw = raw.split("```json")[1].split("```")[0]
            elif "```" in raw:
                raw = raw.split("```")[1].split("```")[0]
            return AnalysisPlan.model_validate_json(raw.strip())
        except Exception as e:
            logger.warning("LLM planning failed: %s, using fallback", e)
            return self._fallback_plan(goal)

    def _fallback_plan(self, goal: str) -> AnalysisPlan:
        """Simple heuristic plan when LLM is unavailable."""
        tasks = []
        goal_lower = goal.lower()

        if "bootstrap" in goal_lower or "new binary" in goal_lower:
            tasks.append(TaskSpec(
                tool_name="bootstrap",
                tool_input={"binary": "<binary>", "project": "<project>"},
                description="Bootstrap the binary",
            ))
        elif "decompile" in goal_lower:
            tasks.append(TaskSpec(
                tool_name="decompile",
                tool_input={"binary": "<binary>", "va": "<va>"},
                description="Decompile the target function",
            ))
        elif "d3d" in goal_lower or "dx9" in goal_lower or "shader" in goal_lower:
            tasks.append(TaskSpec(
                tool_name="dx9_script",
                tool_input={"binary": "<binary>", "script": "find_d3d_calls"},
                description="Scan for D3D9 API calls",
            ))

        return AnalysisPlan(
            goal=goal,
            tasks=tasks,
            reasoning="Fallback plan — LLM orchestrator unavailable",
        )

    async def execute_plan(self, plan: AnalysisPlan) -> AnalysisResult:
        """Execute a plan by dispatching tasks to workers serially."""
        result = AnalysisResult(goal=plan.goal)

        for task in plan.tasks:
            logger.info("Executing: %s (%s)", task.description, task.tool_name)

            task_type = self.router.classify(task.tool_name)
            if task_type == TaskType.WORKER:
                step_result = await self._execute_via_worker(task)
            else:
                step_result = await self._execute_via_worker(task)

            result.steps.append(step_result)

            if not step_result.success:
                logger.warning("Task failed: %s — %s", task.tool_name, step_result.error)

        return result

    async def _execute_via_worker(self, task: TaskSpec) -> StepResult:
        """Dispatch a single task to the worker agent."""
        worker_result = await self.worker.execute(task.tool_name, task.tool_input)

        output = ""
        if worker_result.data and isinstance(worker_result.data, BaseModel):
            output = worker_result.data.model_dump_json(indent=2)
        else:
            output = worker_result.raw_output

        return StepResult(
            task=task,
            success=worker_result.success,
            output=output,
            error=worker_result.last_error if not worker_result.success else None,
        )

    async def run(self, goal: str, project_context: str = "") -> AnalysisResult:
        """Full pipeline: plan → execute → return results."""
        plan = await self.plan(goal, project_context)
        logger.info("Plan: %s (%d tasks)", plan.goal, len(plan.tasks))
        return await self.execute_plan(plan)
