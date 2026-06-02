"""GPT client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .env import get_env, load_project_env


@dataclass
class GPTClientConfig:
    """Configuration for GPT-series models."""

    model: str = "gpt-5"
    temperature: float = 0.2
    max_tokens: int = 8192
    api_key: Optional[str] = None
    base_url: Optional[str] = None


class GPTClient:
    """GPT API client."""

    def __init__(self, cfg: Optional[GPTClientConfig] = None) -> None:
        load_project_env()
        self.cfg = cfg or GPTClientConfig()
        from openai import OpenAI

        self.client = OpenAI(
            api_key=self.cfg.api_key or get_env("OPENAI_API_KEY"),
            base_url=self.cfg.base_url or get_env("OPENAI_BASE_URL"),
        )

    def generate(self, prompt: str) -> str:
        """Call GPT API and return generated text."""

        response = self.client.chat.completions.create(
            model=self.cfg.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.cfg.temperature,
            max_tokens=self.cfg.max_tokens,
        )
        return response.choices[0].message.content or ""

