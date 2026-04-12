"""Worker agent — executes single tool calls on a local model (Qwen3/Gemma4 via Ollama)."""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel

from harness.agents.prompts import WORKER_SYSTEM_PROMPT
from harness.config import Config
from harness.tools.registry import ToolRegistry
from harness.validation.retry import RetryResult, validated_tool_call

logger = logging.getLogger(__name__)


class WorkerAgent:
    """Wraps a Pydantic AI agent for tool execution with validation retry.

    The worker receives a tool name + input, executes it, and returns
    validated output. If the local model produces invalid output, the
    retry loop corrects it (up to max_retries).
    """

    def __init__(self, config: Config, registry: ToolRegistry):
        self.config = config
        self.registry = registry
        self._agent = None  # Lazy init — avoids import errors when pydantic-ai not installed

    def _ensure_agent(self):
        """Lazy-initialize the Pydantic AI agent."""
        if self._agent is not None:
            return

        try:
            from pydantic_ai import Agent
            from pydantic_ai.providers.ollama import OllamaProvider
            from pydantic_ai.models.openai import OpenAIChatModel

            model = OpenAIChatModel(
                model_name=self.config.worker.model,
                provider=OllamaProvider(base_url=f"{self.config.ollama.host}/v1"),
            )
            self._agent = Agent(
                model,
                system_prompt=WORKER_SYSTEM_PROMPT,
            )
        except ImportError:
            logger.warning("pydantic-ai not installed; worker will use direct tool execution")
            self._agent = None

    async def execute(
        self,
        tool_name: str,
        tool_input: dict[str, Any] | BaseModel,
    ) -> RetryResult:
        """Execute a tool call through the worker agent with validation.

        If pydantic-ai is available, routes through the local model.
        Otherwise, falls back to direct tool execution (no LLM involved).
        """
        entry = self.registry.get(tool_name)
        if entry is None:
            return RetryResult(
                success=False,
                last_error=f"Unknown tool: {tool_name}",
            )

        # Validate input
        if entry.input_schema and isinstance(tool_input, dict):
            validated_input = entry.input_schema.model_validate(tool_input)
        elif isinstance(tool_input, BaseModel):
            validated_input = tool_input
        else:
            validated_input = tool_input

        # Direct execution path (no LLM overhead for tool calls)
        # The worker agent's value is in the validation retry loop,
        # not in having the LLM re-interpret the tool call.
        return await self._direct_execute(entry, validated_input)

    async def _direct_execute(self, entry, validated_input) -> RetryResult:
        """Execute tool directly and validate output."""
        try:
            if validated_input is None:
                result = await entry.handler()
            else:
                result = await entry.handler(validated_input)

            if isinstance(result, BaseModel):
                return RetryResult(
                    success=True,
                    data=result,
                    raw_output=result.model_dump_json(),
                    attempts=1,
                )
            return RetryResult(
                success=True,
                raw_output=str(result),
                attempts=1,
            )
        except Exception as e:
            logger.error("Tool %s failed: %s", entry.name, e)
            return RetryResult(
                success=False,
                raw_output=str(e),
                last_error=str(e),
                attempts=1,
            )

    async def execute_with_llm(
        self,
        task_description: str,
        output_schema: type[BaseModel],
    ) -> RetryResult:
        """Execute a task through the local LLM with validation retry.

        Used for tasks that need the LLM to interpret and format results,
        not for simple tool dispatch.
        """
        self._ensure_agent()

        if self._agent is None:
            return RetryResult(
                success=False,
                last_error="pydantic-ai not installed",
            )

        async def run_fn(prompt: str):
            return await self._agent.run(prompt)

        return await validated_tool_call(
            run_fn=run_fn,
            initial_prompt=task_description,
            output_schema=output_schema,
            max_retries=self.config.harness.max_worker_retries,
        )
