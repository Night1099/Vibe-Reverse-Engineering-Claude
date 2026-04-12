"""Tests for the Pydantic validation retry loop."""

import asyncio

import pytest
from pydantic import BaseModel

from harness.validation.retry import RetryResult, validated_tool_call


class SampleOutput(BaseModel):
    value: str
    count: int


class MockResult:
    def __init__(self, data):
        self.data = data


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


def test_success_first_try(event_loop):
    async def run_fn(prompt):
        return MockResult('{"value": "hello", "count": 42}')

    result = event_loop.run_until_complete(
        validated_tool_call(run_fn, "test", SampleOutput, max_retries=3)
    )
    assert result.success
    assert result.data.value == "hello"
    assert result.data.count == 42
    assert result.attempts == 1


def test_success_after_retry(event_loop):
    call_count = 0

    async def run_fn(prompt):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return MockResult("invalid json")
        return MockResult('{"value": "fixed", "count": 1}')

    result = event_loop.run_until_complete(
        validated_tool_call(run_fn, "test", SampleOutput, max_retries=3)
    )
    assert result.success
    assert result.data.value == "fixed"
    assert result.attempts == 2


def test_all_retries_exhausted(event_loop):
    async def run_fn(prompt):
        return MockResult("always bad")

    result = event_loop.run_until_complete(
        validated_tool_call(run_fn, "test", SampleOutput, max_retries=2)
    )
    assert not result.success
    assert result.attempts == 2
    assert "failed after" in result.last_error
