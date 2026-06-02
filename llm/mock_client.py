"""Mock LLM client for local testing."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MockClientConfig:
    """Configuration for mock client."""

    model: str = "mock-llm"


class MockClient:
    """Deterministic local client that does not call external APIs."""

    def __init__(self, cfg: MockClientConfig | None = None) -> None:
        self.cfg = cfg or MockClientConfig()

    def generate(self, prompt: str) -> str:
        """Return a deterministic local response."""

        preview = prompt.strip().replace("\n", " ")[:160]
        return f"[mock response] model={self.cfg.model}; prompt_preview={preview}"
