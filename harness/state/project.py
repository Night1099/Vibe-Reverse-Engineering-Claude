"""Project state manager — tracks per-project context."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ProjectState:
    """State for a single reverse engineering project."""
    name: str
    binary_path: str | None = None
    project_dir: str = ""
    kb_path: str = ""
    bootstrapped: bool = False
    ghidra_analyzed: bool = False

    def __post_init__(self):
        if not self.project_dir:
            self.project_dir = f"patches/{self.name}"
        if not self.kb_path:
            self.kb_path = f"{self.project_dir}/kb.h"


class ProjectManager:
    """Manages project state and discovery."""

    def __init__(self, repo_root: str | Path):
        self.repo_root = Path(repo_root)
        self._projects: dict[str, ProjectState] = {}
        self._active: str | None = None

    def create(self, name: str, binary_path: str | None = None) -> ProjectState:
        """Create or load a project."""
        project = ProjectState(name=name, binary_path=binary_path)
        project_dir = self.repo_root / project.project_dir

        # Check existing state
        project_dir.mkdir(parents=True, exist_ok=True)
        kb = project_dir / "kb.h"
        if kb.exists():
            # Count meaningful entries to detect bootstrap status
            text = kb.read_text(errors="replace")
            import re
            count = len(re.findall(r"^[@$]|^struct |^enum ", text, re.MULTILINE))
            project.bootstrapped = count >= 50
            logger.info("Project %s: kb.h has %d entries (bootstrapped=%s)",
                       name, count, project.bootstrapped)

        ghidra_dir = project_dir / "ghidra"
        project.ghidra_analyzed = ghidra_dir.exists() and any(ghidra_dir.glob("*.gpr"))

        self._projects[name] = project
        self._active = name
        return project

    @property
    def active(self) -> ProjectState | None:
        if self._active:
            return self._projects.get(self._active)
        return None

    def set_active(self, name: str) -> ProjectState | None:
        if name in self._projects:
            self._active = name
            return self._projects[name]
        return None

    def list_projects(self) -> list[str]:
        """Discover projects from patches/ directory."""
        patches = self.repo_root / "patches"
        if not patches.exists():
            return []
        return [
            d.name for d in patches.iterdir()
            if d.is_dir() and (d / "kb.h").exists()
        ]

    def get_context_string(self) -> str:
        """Build a context string for the orchestrator."""
        proj = self.active
        if proj is None:
            return "No active project."

        lines = [
            f"Project: {proj.name}",
            f"Binary: {proj.binary_path or 'not set'}",
            f"Project dir: {proj.project_dir}",
            f"KB path: {proj.kb_path}",
            f"Bootstrapped: {proj.bootstrapped}",
            f"Ghidra analyzed: {proj.ghidra_analyzed}",
        ]

        # Include summary of kb.h if it exists
        kb = self.repo_root / proj.kb_path
        if kb.exists():
            text = kb.read_text(errors="replace")
            line_count = text.count("\n")
            lines.append(f"KB entries: ~{line_count} lines")

        # Check for findings
        findings = self.repo_root / proj.project_dir / "findings.md"
        if findings.exists():
            lines.append(f"Findings file: {findings} ({findings.stat().st_size} bytes)")

        return "\n".join(lines)
