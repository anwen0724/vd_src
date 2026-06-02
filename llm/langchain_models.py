"""LangChain chat model factory."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

from llm.env import get_first_env, load_project_env


ProviderName = Literal["gpt", "claude", "deepseek", "qwen"]


@dataclass
class LangChainModelConfig:
    """Configuration for a LangChain chat model."""

    provider: ProviderName
    model: str
    temperature: float = 0.2
    max_tokens: int = 8192
    api_key: Optional[str] = None
    base_url: Optional[str] = None


def create_chat_model(cfg: LangChainModelConfig):
    """Create a LangChain chat model for one provider."""

    load_project_env()

    if cfg.provider == "gpt":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=cfg.model,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
            api_key=cfg.api_key or get_first_env("V3_OPENAI_API_KEY", "OPENAI_API_KEY"),
            base_url=cfg.base_url or get_first_env("V3_OPENAI_BASE_URL", "OPENAI_BASE_URL"),
        )

    if cfg.provider == "claude":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=cfg.model,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
            api_key=cfg.api_key or get_first_env("V3_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
            base_url=cfg.base_url or get_first_env("V3_ANTHROPIC_BASE_URL", "ANTHROPIC_BASE_URL"),
        )

    if cfg.provider == "deepseek":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=cfg.model,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
            api_key=cfg.api_key or get_first_env("V3_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"),
            base_url=cfg.base_url or get_first_env("V3_DEEPSEEK_BASE_URL", "DEEPSEEK_BASE_URL"),
        )

    if cfg.provider == "qwen":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=cfg.model,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
            api_key=cfg.api_key or get_first_env("V3_QWEN_API_KEY", "QWEN_API_KEY"),
            base_url=cfg.base_url or get_first_env("V3_QWEN_BASE_URL", "QWEN_BASE_URL"),
        )

    raise ValueError(f"Unsupported provider: {cfg.provider}")
