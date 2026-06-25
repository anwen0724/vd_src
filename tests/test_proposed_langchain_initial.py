from __future__ import annotations

from pathlib import Path

from method.proposed.langchain_initial import (
    LangChainInitialVersionLLM,
    _normalize_tool_args,
    _parse_json_object,
)
from method.proposed.models import (
    AnalysisObligation,
    AnalysisObligationSet,
    FactLayer,
    FileFact,
    ObligationAnalysisRecords,
    PermissionFactLayer,
    PermissionSemanticLabels,
)
from tools.file_tools import ReadSearchTools


def test_normalize_tool_args_accepts_model_field_aliases() -> None:
    assert _normalize_tool_args("read_file", {"file": "rtl/top.sv", "offset": 154}) == {
        "path": "rtl/top.sv",
        "offset": 154,
    }
    assert _normalize_tool_args("read_file", {"filepath": "rtl/top.sv"}) == {
        "path": "rtl/top.sv",
    }
    assert _normalize_tool_args("search_text", {"text": "debug_req", "file": "rtl"}) == {
        "query": "debug_req",
        "path": "rtl",
    }
    assert _normalize_tool_args("list_dir", {"directory": "rtl"}) == {"path": "rtl"}


def test_parse_json_object_reports_empty_response_clearly() -> None:
    try:
        _parse_json_object("")
    except ValueError as exc:
        assert "empty response" in str(exc)
    else:
        raise AssertionError("expected empty response to raise ValueError")


def test_structured_output_fallback_retries_after_empty_response() -> None:
    chat_model = FakeRetryChatModel()
    llm = LangChainInitialVersionLLM(chat_model=chat_model)

    result = llm._structured_invoke("Return labels.", PermissionSemanticLabels)

    assert result.summary == "retry ok"
    assert chat_model.invoke_count == 2


def test_structured_output_uses_function_calling_method() -> None:
    chat_model = FakeStructuredChatModel()
    llm = LangChainInitialVersionLLM(chat_model=chat_model)

    llm._structured_invoke("Return labels.", PermissionSemanticLabels)

    assert chat_model.last_structured_output_kwargs == {"method": "function_calling"}


def test_parse_json_object_rejects_dsml_tool_calls_clearly() -> None:
    try:
        _parse_json_object("<｜｜DSML｜｜tool_calls><｜｜DSML｜｜invoke name=\"read_file\">")
    except ValueError as exc:
        assert "tool calls instead of JSON" in str(exc)
    else:
        raise AssertionError("expected DSML tool call response to raise ValueError")


def test_semantic_label_uses_label_only_schema_and_preserves_static_facts() -> None:
    chat_model = FakeStructuredChatModel()
    llm = LangChainInitialVersionLLM(chat_model=chat_model)
    static_facts = FactLayer(files=[FileFact(path="rtl/top.sv", suffix=".sv", line_count=10)])

    result = llm.semantic_label(static_facts, "permission knowledge")

    assert chat_model.last_schema is PermissionSemanticLabels
    assert result.static_facts == static_facts
    assert result.asset_candidates == [{"name": "secret_reg"}]
    assert result.summary == "semantic labels only"


def test_read_file_supports_offset_and_limit(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    rtl = scope / "rtl"
    rtl.mkdir(parents=True)
    (rtl / "top.sv").write_text("line1\nline2\nline3\nline4\n", encoding="utf-8")

    result = ReadSearchTools(scope).read_file("rtl/top.sv", offset=2, limit=2)

    assert result.status == "ok"
    assert result.content == "2: line2\n3: line3"


def test_inspection_synthesizes_report_from_clean_non_tool_prompt(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    rtl = scope / "rtl"
    rtl.mkdir(parents=True)
    (rtl / "top.sv").write_text("line1\nassign secret_reg = debug_req;\nline3\n", encoding="utf-8")
    chat_model = FakeToolThenStructuredChatModel()
    llm = LangChainInitialVersionLLM(chat_model=chat_model, max_steps=3)
    obligations = AnalysisObligationSet(
        scope_id="scope",
        obligations=[
            AnalysisObligation(
                obligation_id="O1",
                reason="Check debug access",
                subject="debug_req",
                operation="write",
                object="secret_reg",
                expected_guard="debug authorization",
                candidate_path="top.debug_req -> top.secret_reg",
            )
        ],
    )

    records = llm.inspect_obligations(
        obligations=obligations,
        permission_facts=PermissionFactLayer(static_facts=FactLayer()),
        input_scope=scope,
    )

    assert records.inspection_records[0].obligation_id == "O1"
    assert records.tool_observations
    assert chat_model.structured_invoker.saw_clean_prompt


class FakeStructuredChatModel:
    def __init__(self) -> None:
        self.last_schema = None
        self.last_structured_output_kwargs = None

    def with_structured_output(self, schema, **kwargs):
        self.last_schema = schema
        self.last_structured_output_kwargs = kwargs
        return FakeStructuredInvoker(schema)


class FakeStructuredInvoker:
    def __init__(self, schema) -> None:
        self.schema = schema

    def invoke(self, messages):
        return self.schema(
            asset_candidates=[{"name": "secret_reg"}],
            subject_candidates=[],
            operation_candidates=[],
            guard_candidates=[],
            state_lifecycle_facts=[],
            path_candidates=[],
            summary="semantic labels only",
        )


class FakeRetryChatModel:
    def __init__(self) -> None:
        self.invoke_count = 0

    def with_structured_output(self, schema, **kwargs):
        return FakeFailingStructuredInvoker()

    def invoke(self, messages):
        self.invoke_count += 1
        if self.invoke_count == 1:
            return FakeMessage("")
        return FakeMessage('{"summary": "retry ok"}')


class FakeFailingStructuredInvoker:
    def invoke(self, messages):
        raise RuntimeError("structured output unavailable")


class FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class FakeToolThenStructuredChatModel:
    def __init__(self) -> None:
        self.tool_model = FakeToolBoundModel()
        self.structured_invoker = FakeInspectionStructuredInvoker()

    def bind_tools(self, tools):
        return self.tool_model

    def with_structured_output(self, schema, **kwargs):
        self.structured_invoker.schema = schema
        return self.structured_invoker


class FakeToolBoundModel:
    def __init__(self) -> None:
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        if self.calls == 1:
            return FakeToolCallMessage(
                [
                    {
                        "name": "read_file",
                        "args": {"path": "rtl/top.sv", "offset": 2, "limit": 1},
                        "id": "tool-1",
                    }
                ]
            )
        return FakeMessage("Finished tool exploration.")


class FakeToolCallMessage:
    def __init__(self, tool_calls):
        self.content = ""
        self.tool_calls = tool_calls


class FakeInspectionStructuredInvoker:
    def __init__(self) -> None:
        self.schema = ObligationAnalysisRecords
        self.saw_clean_prompt = False

    def invoke(self, messages):
        self.saw_clean_prompt = len(messages) == 1 and "Tool observations JSON" in messages[0].content
        if any(hasattr(message, "tool_call_id") for message in messages):
            raise AssertionError("structured report synthesis received tool messages")
        return self.schema(
            scope_id="scope",
            obligations=[],
            inspection_records=[
                {
                    "obligation_id": "O1",
                    "inspection_status": "candidate_violation",
                    "evidence_slots": {
                        "subject": "debug_req",
                        "operation": "write",
                        "object": "secret_reg",
                        "expected_guard": "debug authorization",
                        "observed_behavior": "debug_req controls secret_reg",
                        "path": "top.debug_req -> top.secret_reg",
                        "impact": "protected state can be modified",
                        "rtl_evidence": [
                            {
                                "file": "rtl/top.sv",
                                "line_start": 2,
                                "line_end": 2,
                                "module": "top",
                                "object": "secret_reg",
                                "evidence_type": "assignment",
                                "description": "debug_req controls secret_reg",
                                "supports_claim": "shows observed behavior",
                            }
                        ],
                    },
                }
            ],
        )
