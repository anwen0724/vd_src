from __future__ import annotations

import sys
import types

from llm.gemini_client import GeminiClient, GeminiClientConfig


def test_gemini_client_generate_uses_google_genai_sdk(monkeypatch) -> None:
    captured = {}

    class FakeModels:
        def generate_content(self, **kwargs):
            captured["generate_content"] = kwargs
            return types.SimpleNamespace(text="answer")

    class FakeClient:
        def __init__(self, **kwargs) -> None:
            captured["client"] = kwargs
            self.models = FakeModels()

    fake_genai = types.SimpleNamespace(Client=FakeClient)
    fake_google = types.SimpleNamespace(genai=fake_genai)
    monkeypatch.setitem(sys.modules, "google", fake_google)
    monkeypatch.setitem(sys.modules, "google.genai", fake_genai)
    monkeypatch.setenv("V3_GEMINI_API_KEY", "gemini-key")
    monkeypatch.setenv("GEMINI_BASE_URL", "")

    client = GeminiClient(GeminiClientConfig(model="gemini-2.5-pro", temperature=0.1, max_tokens=4096))
    result = client.generate("hello")

    assert result == "answer"
    assert captured["client"]["api_key"] == "gemini-key"
    assert captured["generate_content"]["model"] == "gemini-2.5-pro"


def test_gemini_client_uses_openai_compatible_base_url(monkeypatch) -> None:
    captured = {}

    class FakeMessage:
        content = "ok"

    class FakeChoice:
        message = FakeMessage()

    class FakeResponse:
        choices = [FakeChoice()]

    class FakeCompletions:
        def create(self, **kwargs):
            captured["completion"] = kwargs
            return FakeResponse()

    class FakeChat:
        completions = FakeCompletions()

    class FakeOpenAI:
        def __init__(self, **kwargs) -> None:
            captured["client"] = kwargs
            self.chat = FakeChat()

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=FakeOpenAI))
    monkeypatch.setenv("V3_GEMINI_API_KEY", "gemini-key")
    monkeypatch.setenv("V3_GEMINI_BASE_URL", "https://gemini.example/v1")

    client = GeminiClient(GeminiClientConfig(model="gemini-3.1-pro-preview", temperature=0.2, max_tokens=1024))
    assert client.generate("hello") == "ok"

    assert captured["client"]["api_key"] == "gemini-key"
    assert captured["client"]["base_url"] == "https://gemini.example/v1"
    assert captured["completion"]["model"] == "gemini-3.1-pro-preview"
    assert captured["completion"]["temperature"] == 0.2
    assert captured["completion"]["max_tokens"] == 1024
