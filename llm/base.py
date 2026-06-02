"""Common LLM client protocol."""

from __future__ import annotations

from typing import Protocol


class LLMClient(Protocol):
    """Minimal interface shared by all LLM clients."""

    def generate(self, prompt: str) -> str:
        """Generate text for a prompt."""
