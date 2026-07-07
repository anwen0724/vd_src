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


def test_gemini_chat_model_uses_google_genai_integration(monkeypatch) -> None:
    captured = {}

    class FakeChatGoogleGenerativeAI:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

    fake_module = types.SimpleNamespace(ChatGoogleGenerativeAI=FakeChatGoogleGenerativeAI)
    monkeypatch.setitem(sys.modules, "langchain_google_genai", fake_module)
    monkeypatch.setenv("V3_GEMINI_API_KEY", "gemini-key")
    monkeypatch.setenv("GEMINI_BASE_URL", "")

    create_chat_model(
        LangChainModelConfig(
            provider="gemini",
            model="gemini-2.5-pro",
            temperature=0.1,
            max_tokens=4096,
            request_timeout=321,
        )
    )

    assert captured["model"] == "gemini-2.5-pro"
    assert captured["temperature"] == 0.1
    assert captured["max_output_tokens"] == 4096
    assert captured["api_key"] == "gemini-key"
    assert captured["timeout"] == 321


def test_gemini_chat_model_uses_openai_compatible_base_url(monkeypatch) -> None:
    captured = {}

    class FakeChatOpenAI:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

    fake_module = types.SimpleNamespace(ChatOpenAI=FakeChatOpenAI)
    monkeypatch.setitem(sys.modules, "langchain_openai", fake_module)
    monkeypatch.setenv("V3_GEMINI_API_KEY", "gemini-key")
    monkeypatch.setenv("V3_GEMINI_BASE_URL", "https://gemini.example/v1")

    create_chat_model(
        LangChainModelConfig(
            provider="gemini",
            model="gemini-3.1-pro-preview",
            temperature=0.2,
            max_tokens=8192,
            request_timeout=456,
        )
    )

    assert captured["model"] == "gemini-3.1-pro-preview"
    assert captured["temperature"] == 0.2
    assert captured["max_tokens"] == 8192
    assert captured["api_key"] == "gemini-key"
    assert captured["base_url"] == "https://gemini.example/v1"
    assert captured["timeout"] == 456
