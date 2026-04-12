"""RAG query — semantic search over indexed tool documentation."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class RAGQuery:
    """Searches the ChromaDB index for relevant tool documentation."""

    def __init__(self, persist_dir: str):
        self.persist_dir = persist_dir
        self._client = None
        self._collection = None

    def _ensure_db(self):
        if self._client is not None:
            return
        try:
            import chromadb
            if not Path(self.persist_dir).exists():
                logger.warning("RAG index not found at %s — run indexer first", self.persist_dir)
                return
            self._client = chromadb.PersistentClient(path=self.persist_dir)
            self._collection = self._client.get_or_create_collection(name="tool_docs")
        except ImportError:
            logger.warning("chromadb not installed; RAG query unavailable")

    async def query(self, question: str, top_k: int = 5) -> list[str]:
        """Return top-K relevant document chunks for a question."""
        self._ensure_db()
        if self._collection is None or self._collection.count() == 0:
            return []

        results = self._collection.query(
            query_texts=[question],
            n_results=min(top_k, self._collection.count()),
        )

        documents = results.get("documents", [[]])[0]
        return documents

    async def query_with_metadata(
        self, question: str, top_k: int = 5
    ) -> list[dict]:
        """Return chunks with metadata (source, file, distance)."""
        self._ensure_db()
        if self._collection is None or self._collection.count() == 0:
            return []

        results = self._collection.query(
            query_texts=[question],
            n_results=min(top_k, self._collection.count()),
            include=["documents", "metadatas", "distances"],
        )

        items = []
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        dists = results.get("distances", [[]])[0]

        for doc, meta, dist in zip(docs, metas, dists):
            items.append({
                "text": doc,
                "source": meta.get("source", ""),
                "file": meta.get("file", ""),
                "distance": dist,
            })
        return items
