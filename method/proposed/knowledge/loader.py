"""Knowledge-base loading for the proposed method."""

from __future__ import annotations

from pathlib import Path


DEFAULT_KNOWLEDGE_PATH = Path(__file__).with_name("permission_vulnerability_knowledge.md")


class KnowledgeBaseLoader:
    """Load the generic permission vulnerability knowledge base."""

    def load(self, path: str | Path | None = None) -> str:
        source = Path(path).resolve() if path else DEFAULT_KNOWLEDGE_PATH
        if not source.exists():
            raise FileNotFoundError(f"Knowledge base does not exist: {source}")
        return source.read_text(encoding="utf-8")

