from __future__ import annotations

import sys
import types

from llm.langchain_models import LangChainModelConfig, create_chat_model


def test_openai_compatible_chat_model_receives_request_timeout(monkeypatch) -> None:
    captured = {}

    class FakeChatOpenAI:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

    fake_module = types.SimpleNamespace(ChatOpenAI=FakeChatOpenAI)
    monkeypatch.setitem(sys.modules, "langchain_openai", fake_module)
    monkeypatch.setenv("V3_DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setenv("V3_DEEPSEEK_BASE_URL", "https://example.invalid/v1")

    create_chat_model(
        LangChainModelConfig(
            provider="deepseek",
            model="deepseek-v4-pro",
            request_timeout=123,
        )
    )

    assert captured["timeout"] == 123
