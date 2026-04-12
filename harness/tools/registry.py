"""Central tool registry — discovers and exposes all wrapped tools."""

from __future__ import annotations

from typing import Any, Callable

from pydantic import BaseModel

from harness.tools.dx9_scripts_wrap import ALL_DX9_TOOLS
from harness.tools.file_tools import ALL_FILE_TOOLS
from harness.tools.livetools_wrap import ALL_LIVETOOLS
from harness.tools.retools_wrap import ALL_RETOOLS


class ToolEntry:
    """A registered tool with its input/output schemas and handler."""

    def __init__(
        self,
        name: str,
        input_schema: type[BaseModel] | None,
        output_schema: type[BaseModel],
        handler: Callable[..., Any],
    ):
        self.name = name
        self.input_schema = input_schema
        self.output_schema = output_schema
        self.handler = handler

    def describe(self) -> str:
        """One-line description for RAG indexing."""
        doc = self.handler.__doc__ or ""
        first_line = doc.strip().split("\n")[0] if doc else self.name
        return f"{self.name}: {first_line}"


class ToolRegistry:
    """Holds all available tools, organized by category."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolEntry] = {}
        self._categories: dict[str, list[str]] = {}

    def register(self, name: str, input_schema: type[BaseModel] | None,
                 output_schema: type[BaseModel], handler: Callable, category: str) -> None:
        entry = ToolEntry(name, input_schema, output_schema, handler)
        self._tools[name] = entry
        self._categories.setdefault(category, []).append(name)

    def get(self, name: str) -> ToolEntry | None:
        return self._tools.get(name)

    def list_tools(self, category: str | None = None) -> list[str]:
        if category:
            return self._categories.get(category, [])
        return list(self._tools.keys())

    def list_categories(self) -> list[str]:
        return list(self._categories.keys())

    def describe_all(self) -> str:
        """Full catalog for RAG indexing or orchestrator context."""
        lines = []
        for cat in sorted(self._categories):
            lines.append(f"\n## {cat}")
            for name in self._categories[cat]:
                lines.append(f"  - {self._tools[name].describe()}")
        return "\n".join(lines)


def build_registry() -> ToolRegistry:
    """Build a registry with all tools from all modules."""
    reg = ToolRegistry()

    for name, (inp, out, fn) in ALL_RETOOLS.items():
        reg.register(name, inp, out, fn, "retools")

    for name, (inp, out, fn) in ALL_LIVETOOLS.items():
        reg.register(name, inp, out, fn, "livetools")

    for name, (inp, out, fn) in ALL_DX9_TOOLS.items():
        reg.register(name, inp, out, fn, "dx9")

    for name, (inp, out, fn) in ALL_FILE_TOOLS.items():
        reg.register(name, inp, out, fn, "file")

    return reg
