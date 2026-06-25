from __future__ import annotations

from pathlib import Path

from method.baseline.langchain_read_search_llm import LangChainReadSearchLLMBaseline
from tools.file_tools import ReadSearchTools


def test_baseline_structured_output_uses_function_calling_method(tmp_path: Path) -> None:
    chat_model = FakeBaselineChatModel()

    LangChainReadSearchLLMBaseline(
        chat_model=chat_model,
        tools=ReadSearchTools(tmp_path),
    )

    assert chat_model.last_structured_output_kwargs == {"method": "function_calling"}


class FakeBaselineChatModel:
    def __init__(self) -> None:
        self.last_structured_output_kwargs = None

    def bind_tools(self, tools):
        return self

    def with_structured_output(self, schema, **kwargs):
        self.last_structured_output_kwargs = kwargs
        return self
