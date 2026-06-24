"""LangChain-backed LLM stages for the proposed initial-version method."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TypeVar

from langchain_core.messages import HumanMessage, ToolMessage
from pydantic import BaseModel

from method.proposed.models import (
    AnalysisObligationSet,
    FactLayer,
    ObligationAnalysisRecords,
    PermissionFactLayer,
)
from tools.file_tools import ReadSearchTools
from tools.langchain_file_tools import build_langchain_file_tools


ModelT = TypeVar("ModelT", bound=BaseModel)


class LangChainInitialVersionLLM:
    """LLM implementation for semantic labeling, planning, and inspection."""

    def __init__(
        self,
        chat_model: Any,
        max_steps: int = 20,
        max_tool_result_chars: int = 8_000,
        max_prompt_json_chars: int = 80_000,
    ) -> None:
        self.chat_model = chat_model
        self.max_steps = max_steps
        self.max_tool_result_chars = max_tool_result_chars
        self.max_prompt_json_chars = max_prompt_json_chars

    def semantic_label(self, static_facts: FactLayer, knowledge: str) -> PermissionFactLayer:
        prompt = f"""You are constructing Module 1 of a proposed RTL permission vulnerability analysis method.

Input:
1. Static RTL facts extracted from the visible source scope.
2. Generic permission vulnerability knowledge.

Task:
Label permission-oriented facts. Do not decide final vulnerabilities.
Identify protected asset candidates, subject/requester candidates, operation candidates,
guard/mediation candidates, state lifecycle facts, and path candidates.

Knowledge:
{_trim(knowledge, 20_000)}

Static facts JSON:
{_trim(static_facts.model_dump_json(indent=2), self.max_prompt_json_chars)}
"""
        result = self._structured_invoke(prompt, PermissionFactLayer)
        if not result.static_facts.files:
            result.static_facts = static_facts
        return result

    def plan_obligations(
        self,
        permission_facts: PermissionFactLayer,
        knowledge: str,
    ) -> AnalysisObligationSet:
        prompt = f"""You are constructing Module 2 planning for an RTL permission vulnerability analysis method.

Input:
1. Permission-oriented RTL fact layer for the current source scope.
2. Generic permission vulnerability knowledge.

Task:
Generate scope-specific analysis obligations.
Do not use benchmark ground truth, case IDs, or expected bugs.
Each obligation should describe what permission condition should be checked in the visible RTL.

Knowledge:
{_trim(knowledge, 20_000)}

Permission fact layer JSON:
{_trim(permission_facts.model_dump_json(indent=2), self.max_prompt_json_chars)}
"""
        return self._structured_invoke(prompt, AnalysisObligationSet)

    def inspect_obligations(
        self,
        obligations: AnalysisObligationSet,
        permission_facts: PermissionFactLayer,
        input_scope: Path,
        missing_evidence_requests: list[dict] | None = None,
    ) -> ObligationAnalysisRecords:
        tools = ReadSearchTools(input_scope)
        langchain_tools = build_langchain_file_tools(tools)
        tools_by_name = {tool.name: tool for tool in langchain_tools}
        model = self.chat_model.bind_tools(langchain_tools)
        messages: list[Any] = [
            HumanMessage(
                content=f"""You are executing Module 2 inspection for an RTL permission vulnerability analysis method.

Use only the bound read/search tools to inspect files under the visible input scope.
Do not use benchmark ground truth, case IDs, official bug descriptions, or external knowledge beyond the provided generic knowledge already reflected in the obligations.
Do not modify files or run tools other than list_dir, read_file, and search_text.

For each obligation:
1. inspect the relevant RTL files;
2. fill subject, operation, object, expected_guard, observed_behavior, path, state_condition, impact, and rtl_evidence;
3. mark candidate_violation, obligation_satisfied, inconclusive, or not_applicable.

Obligations JSON:
{_trim(obligations.model_dump_json(indent=2), self.max_prompt_json_chars)}

Permission fact layer JSON:
{_trim(permission_facts.model_dump_json(indent=2), self.max_prompt_json_chars)}

Missing evidence requests from closure checker:
{json.dumps(missing_evidence_requests or [], ensure_ascii=False, indent=2)}
"""
            )
        ]

        for _step in range(1, self.max_steps + 1):
            ai_message = model.invoke(messages)
            messages.append(ai_message)
            tool_calls = getattr(ai_message, "tool_calls", None) or []
            if not tool_calls:
                break
            for tool_call in tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call.get("args", {})
                tool_id = tool_call["id"]
                tool = tools_by_name.get(tool_name)
                if tool is None:
                    content = json.dumps({"status": "error", "error": f"Unknown tool: {tool_name}"}, ensure_ascii=False)
                else:
                    content = tool.invoke(tool_args)
                    if len(content) > self.max_tool_result_chars:
                        content = content[: self.max_tool_result_chars] + "\n[TRUNCATED: tool result exceeded max_tool_result_chars]"
                messages.append(ToolMessage(content=content, tool_call_id=tool_id))

        final_prompt = "Produce the final inspection records using the required structured output schema."
        final_messages = [*messages, HumanMessage(content=final_prompt)]
        return self._structured_invoke_messages(final_messages, ObligationAnalysisRecords)

    def _structured_invoke(self, prompt: str, schema: type[ModelT]) -> ModelT:
        return self._structured_invoke_messages([HumanMessage(content=prompt)], schema)

    def _structured_invoke_messages(self, messages: list[Any], schema: type[ModelT]) -> ModelT:
        structured_model = self.chat_model.with_structured_output(schema)
        try:
            output = structured_model.invoke(messages)
            if isinstance(output, schema):
                return output
            if hasattr(output, "model_dump"):
                return schema.model_validate(output.model_dump())
            return schema.model_validate(output)
        except Exception as exc:  # noqa: BLE001 - provider compatibility fallback.
            fallback_messages = [
                *messages,
                HumanMessage(
                    content=(
                        "Return a single valid JSON object conforming to this JSON schema. "
                        "Do not wrap it in Markdown.\n"
                        f"{json.dumps(schema.model_json_schema(), ensure_ascii=False)}\n"
                        f"Previous structured-output error: {exc}"
                    )
                ),
            ]
            output = self.chat_model.invoke(fallback_messages)
            raw_text = _message_text(output)
            return schema.model_validate(_parse_json_object(raw_text))


def _trim(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n[TRUNCATED]"


def _message_text(message: Any) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    return str(content)


def _parse_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        parsed = json.loads(stripped[start : end + 1])
    if not isinstance(parsed, dict):
        raise TypeError("Expected JSON object")
    return parsed

