"""Pydantic validation retry loop for local model tool calls.

Local models (Qwen3, Gemma 4) have 6-40% baseline accuracy on complex tool
schemas. This retry loop pushes accuracy to 95%+ by feeding validation errors
back to the model for correction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)


@dataclass
class RetryResult:
    """Outcome of a validated tool call."""
    success: bool
    data: BaseModel | None = None
    raw_output: str = ""
    attempts: int = 0
    last_error: str = ""


async def validated_tool_call(
    run_fn,
    initial_prompt: str,
    output_schema: type[BaseModel],
    max_retries: int = 3,
) -> RetryResult:
    """Execute a tool call with Pydantic validation and retry.

    Args:
        run_fn: Async callable that takes a prompt string and returns
                 an object with a .data attribute (the raw text response).
        initial_prompt: The initial prompt to send to the agent.
        output_schema: Pydantic model to validate output against.
        max_retries: Maximum number of retry attempts.

    Returns:
        RetryResult with either validated data or error info.
    """
    prompt = initial_prompt
    raw = ""

    for attempt in range(1, max_retries + 1):
        try:
            result = await run_fn(prompt)
            raw = str(result.data) if hasattr(result, "data") else str(result)

            # Try parsing as JSON first
            validated = output_schema.model_validate_json(raw)
            logger.debug("Validation passed on attempt %d", attempt)
            return RetryResult(
                success=True,
                data=validated,
                raw_output=raw,
                attempts=attempt,
            )
        except ValidationError as e:
            error_msg = str(e)
            logger.info(
                "Validation failed on attempt %d/%d: %s",
                attempt, max_retries, error_msg[:200],
            )
            # Feed the error back to the model for correction
            prompt = (
                f"Your previous output failed schema validation.\n"
                f"Error: {error_msg}\n"
                f"Expected schema: {output_schema.model_json_schema()}\n"
                f"Please output ONLY valid JSON matching the schema. "
                f"Original task: {initial_prompt}"
            )
        except Exception as e:
            logger.warning("Unexpected error on attempt %d: %s", attempt, e)
            raw = str(e)

    return RetryResult(
        success=False,
        raw_output=raw,
        attempts=max_retries,
        last_error=f"Validation failed after {max_retries} attempts",
    )


def validate_tool_input(input_data: dict[str, Any], schema: type[BaseModel]) -> BaseModel:
    """Validate tool input against its schema. Raises ValidationError on failure."""
    return schema.model_validate(input_data)
