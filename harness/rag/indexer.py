"""RAG indexer — indexes tool-catalog.md, CLAUDE.md, and kb.h into ChromaDB.

Uses all-MiniLM-L6-v2 for embeddings (runs locally, no API cost).
Chunks by section headers (## for markdown, groups of 20 for kb.h).
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)


def _chunk_markdown_by_sections(text: str, max_chunk_size: int = 512) -> list[dict]:
    """Split markdown into chunks at ## headers."""
    chunks = []
    sections = re.split(r"(?=^## )", text, flags=re.MULTILINE)

    for section in sections:
        section = section.strip()
        if not section:
            continue
        # If section is too large, split at ### or by lines
        if len(section) > max_chunk_size * 4:
            subsections = re.split(r"(?=^### )", section, flags=re.MULTILINE)
            for sub in subsections:
                sub = sub.strip()
                if sub:
                    chunks.append({
                        "text": sub[:max_chunk_size * 4],
                        "source": "section",
                    })
        else:
            chunks.append({"text": section, "source": "section"})

    return chunks


def _chunk_kb_file(text: str, group_size: int = 20) -> list[dict]:
    """Split kb.h into groups of N entries."""
    lines = text.strip().split("\n")
    chunks = []
    for i in range(0, len(lines), group_size):
        group = "\n".join(lines[i : i + group_size])
        if group.strip():
            chunks.append({"text": group, "source": "kb.h"})
    return chunks


def _content_hash(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()[:12]


class RAGIndexer:
    """Indexes documentation into ChromaDB for tool discovery."""

    def __init__(self, persist_dir: str, embedding_model: str = "all-MiniLM-L6-v2"):
        self.persist_dir = persist_dir
        self.embedding_model = embedding_model
        self._client = None
        self._collection = None

    def _ensure_db(self):
        if self._client is not None:
            return
        try:
            import chromadb
            Path(self.persist_dir).mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(path=self.persist_dir)
            self._collection = self._client.get_or_create_collection(
                name="tool_docs",
                metadata={"hnsw:space": "cosine"},
            )
        except ImportError:
            logger.warning("chromadb not installed; RAG indexing unavailable")

    def index_file(self, path: str | Path, source_label: str = "") -> int:
        """Index a single file. Returns number of chunks indexed."""
        self._ensure_db()
        if self._collection is None:
            return 0

        path = Path(path)
        if not path.exists():
            logger.warning("File not found: %s", path)
            return 0

        text = path.read_text(errors="replace")
        label = source_label or path.name

        if path.suffix == ".h":
            chunks = _chunk_kb_file(text)
        else:
            chunks = _chunk_markdown_by_sections(text)

        if not chunks:
            return 0

        ids = [f"{label}_{_content_hash(c['text'])}_{i}" for i, c in enumerate(chunks)]
        documents = [c["text"] for c in chunks]
        metadatas = [{"source": label, "file": str(path)} for c in chunks]

        self._collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )
        logger.info("Indexed %d chunks from %s", len(chunks), label)
        return len(chunks)

    def index_defaults(self, repo_root: str | Path) -> int:
        """Index the default documentation files."""
        repo = Path(repo_root)
        total = 0

        candidates = [
            (repo / ".claude" / "references" / "tool-catalog.md", "tool-catalog"),
            (repo / ".claude" / "CLAUDE.md", "claude-md"),
            (repo / ".claude" / "rules" / "tool-dispatch.md", "tool-dispatch"),
            (repo / ".claude" / "rules" / "subagent-workflow.md", "subagent-workflow"),
        ]

        for path, label in candidates:
            if path.exists():
                total += self.index_file(path, label)

        return total

    def index_project_kb(self, kb_path: str | Path) -> int:
        """Index a project's kb.h file."""
        return self.index_file(kb_path, "kb.h")

    def clear(self) -> None:
        """Clear the entire index."""
        self._ensure_db()
        if self._client:
            self._client.delete_collection("tool_docs")
            self._collection = self._client.get_or_create_collection(
                name="tool_docs",
                metadata={"hnsw:space": "cosine"},
            )

    @property
    def count(self) -> int:
        self._ensure_db()
        if self._collection:
            return self._collection.count()
        return 0
