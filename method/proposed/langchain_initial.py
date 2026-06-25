"""LangChain-backed LLM stages for the proposed initial-version method."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

try:
    from langchain_core.messages import HumanMessage, ToolMessage
except ModuleNotFoundError:  # pragma: no cover - local unit tests can run without LangChain installed.
    class HumanMessage:  # type: ignore[no-redef]
        def __init__(self, content: str) -> None:
            self.content = content

    class ToolMessage:  # type: ignore[no-redef]
        def __init__(self, content: str, tool_call_id: str) -> None:
            self.content = content
            self.tool_call_id = tool_call_id

from method.proposed.models import (
    AnalysisObligationSet,
    FactLayer,
    ObligationAnalysisRecords,
    PermissionSemanticLabels,
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
Do not reproduce or rewrite static_facts. Only output semantic label fields.

Knowledge:
{_trim(knowledge, 20_000)}

Static facts JSON:
{_trim(static_facts.model_dump_json(indent=2), self.max_prompt_json_chars)}
"""
        labels = self._structured_invoke(prompt, PermissionSemanticLabels)
        return PermissionFactLayer(
            static_facts=static_facts,
            asset_candidates=labels.asset_candidates,
            subject_candidates=labels.subject_candidates,
            operation_candidates=labels.operation_candidates,
            guard_candidates=labels.guard_candidates,
            state_lifecycle_facts=labels.state_lifecycle_facts,
            path_candidates=labels.path_candidates,
            summary=labels.summary,
        )

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
        observations = self._collect_tool_observations(
            obligations=obligations,
            permission_facts=permission_facts,
            input_scope=input_scope,
            missing_evidence_requests=missing_evidence_requests,
        )
        records = self._synthesize_inspection_records(
            obligations=obligations,
            permission_facts=permission_facts,
            missing_evidence_requests=missing_evidence_requests,
            tool_observations=observations,
        )
        records.tool_observations = observations
        return records

    def _collect_tool_observations(
        self,
        obligations: AnalysisObligationSet,
        permission_facts: PermissionFactLayer,
        input_scope: Path,
        missing_evidence_requests: list[dict] | None = None,
    ) -> list[dict[str, Any]]:
        tools = ReadSearchTools(input_scope)
        langchain_tools = build_langchain_file_tools(tools)
        tools_by_name = {tool.name: tool for tool in langchain_tools}
        model = self.chat_model.bind_tools(langchain_tools)
        observations: list[dict[str, Any]] = []
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

        for step in range(1, self.max_steps + 1):
            ai_message = model.invoke(messages)
            messages.append(ai_message)
            tool_calls = getattr(ai_message, "tool_calls", None) or []
            if not tool_calls:
                text = _message_text(ai_message).strip()
                if text:
                    observations.append(
                        {
                            "step": step,
                            "tool": "model_message",
                            "args": {},
                            "status": "ok",
                            "content": _trim(text, self.max_tool_result_chars),
                            "truncated": len(text) > self.max_tool_result_chars,
                        }
                    )
                break
            for tool_call in tool_calls:
                tool_name = tool_call["name"]
                tool_args = _normalize_tool_args(tool_name, tool_call.get("args", {}))
                tool_id = tool_call["id"]
                tool = tools_by_name.get(tool_name)
                if tool is None:
                    content = json.dumps({"status": "error", "error": f"Unknown tool: {tool_name}"}, ensure_ascii=False)
                else:
                    try:
                        content = tool.invoke(tool_args)
                        if len(content) > self.max_tool_result_chars:
                            content = content[: self.max_tool_result_chars] + "\n[TRUNCATED: tool result exceeded max_tool_result_chars]"
                    except Exception as exc:  # noqa: BLE001 - tool errors should be visible to the model, not crash the run.
                        content = _tool_error_content(tool_name, tool_args, exc)
                observations.append(_tool_observation(step, tool_name, tool_args, content))
                messages.append(ToolMessage(content=content, tool_call_id=tool_id))
        return observations

    def _synthesize_inspection_records(
        self,
        obligations: AnalysisObligationSet,
        permission_facts: PermissionFactLayer,
        missing_evidence_requests: list[dict] | None,
        tool_observations: list[dict[str, Any]],
    ) -> ObligationAnalysisRecords:
        prompt = f"""You are synthesizing Module 2 inspection records for an RTL permission vulnerability analysis method.

This is the structured report stage. Do not call tools. Do not request additional tool calls.
Use only the provided obligations, permission fact layer, missing evidence requests, and tool observations.
Return inspection records using the required schema.

Obligations JSON:
{_trim(obligations.model_dump_json(indent=2), self.max_prompt_json_chars)}

Permission fact layer JSON:
{_trim(permission_facts.model_dump_json(indent=2), self.max_prompt_json_chars)}

Missing evidence requests JSON:
{json.dumps(missing_evidence_requests or [], ensure_ascii=False, indent=2)}

Tool observations JSON:
{_trim(json.dumps(tool_observations, ensure_ascii=False, indent=2), self.max_prompt_json_chars)}
"""
        records = self._structured_invoke(prompt, ObligationAnalysisRecords)
        if not records.obligations:
            records.obligations = obligations.obligations
        return records

    def _structured_invoke(self, prompt: str, schema: type[ModelT]) -> ModelT:
        return self._structured_invoke_messages([HumanMessage(content=prompt)], schema)

    def _structured_invoke_messages(self, messages: list[Any], schema: type[ModelT]) -> ModelT:
        structured_model = self.chat_model.with_structured_output(schema, method="function_calling")
        try:
            output = structured_model.invoke(messages)
            if isinstance(output, schema):
                return output
            if hasattr(output, "model_dump"):
                return schema.model_validate(output.model_dump())
            return schema.model_validate(output)
        except Exception as exc:  # noqa: BLE001 - provider compatibility fallback.
            schema_text = json.dumps(schema.model_json_schema(), ensure_ascii=False)
            fallback_messages = [
                *messages,
                HumanMessage(
                    content=(
                        "Return a single valid JSON object conforming to this JSON schema. "
                        "Do not wrap it in Markdown.\n"
                        f"{schema_text}\n"
                        f"Previous structured-output error: {exc}"
                    )
                ),
            ]
            output = self.chat_model.invoke(fallback_messages)
            raw_text = _message_text(output)
            try:
                return schema.model_validate(_parse_json_object(raw_text))
            except Exception as first_parse_error:  # noqa: BLE001 - one repair retry for provider JSON drift.
                retry_messages = [
                    *messages,
                    HumanMessage(
                        content=(
                            "Your previous response was not valid JSON for the required schema. "
                            "Return only one valid JSON object. No Markdown, no prose.\n"
                            f"Required JSON schema:\n{schema_text}\n"
                            f"Previous parse error: {first_parse_error}\n"
                            f"Previous response preview:\n{_preview(raw_text)}"
                        )
                    ),
                ]
                retry_output = self.chat_model.invoke(retry_messages)
                retry_text = _message_text(retry_output)
                try:
                    return schema.model_validate(_parse_json_object(retry_text))
                except Exception as second_parse_error:  # noqa: BLE001
                    raise ValueError(
                        "Structured output parse failed "
                        f"for {schema.__name__}: {second_parse_error}. "
                        f"First response preview: {_preview(raw_text)}. "
                        f"Retry response preview: {_preview(retry_text)}."
                    ) from second_parse_error


def _normalize_tool_args(tool_name: str, tool_args: dict[str, Any] | None) -> dict[str, Any]:
    args = dict(tool_args or {})
    if tool_name == "read_file":
        _copy_first_alias(args, "path", ["file", "filename", "filepath", "file_path"])
    elif tool_name == "search_text":
        _copy_first_alias(args, "query", ["text", "keyword", "regex", "pattern"])
        _copy_first_alias(args, "path", ["file", "filename", "filepath", "file_path"])
    elif tool_name == "list_dir":
        _copy_first_alias(args, "path", ["dir", "directory", "folder"])
    return args


def _copy_first_alias(args: dict[str, Any], target: str, aliases: list[str]) -> None:
    has_target = bool(args.get(target))
    for alias in aliases:
        if not has_target and args.get(alias):
            args[target] = args[alias]
            has_target = True
        if alias in args:
            args.pop(alias, None)


def _tool_error_content(tool_name: str, tool_args: dict[str, Any], exc: Exception) -> str:
    hints = {
        "read_file": "Use read_file with {'path': '<relative file path under INPUT_SCOPE>'}.",
        "search_text": "Use search_text with {'query': '<text to search>', 'path': '<optional relative path>'}.",
        "list_dir": "Use list_dir with {'path': '<relative directory path under INPUT_SCOPE>'}.",
    }
    return json.dumps(
        {
            "tool": tool_name,
            "status": "error",
            "args": tool_args,
            "error": str(exc),
            "hint": hints.get(tool_name, "Check the tool argument schema and retry."),
        },
        ensure_ascii=False,
    )


def _tool_observation(step: int, tool_name: str, tool_args: dict[str, Any], content: str) -> dict[str, Any]:
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        parsed = {"status": "unknown", "content": content}
    raw_content = str(parsed.get("content", ""))
    return {
        "step": step,
        "tool": tool_name,
        "args": tool_args,
        "status": str(parsed.get("status", "")),
        "path": parsed.get("path"),
        "error": parsed.get("error"),
        "content": _trim(raw_content, 4_000),
        "truncated": bool(parsed.get("truncated", False)) or len(raw_content) > 4_000,
    }


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
    if not stripped:
        raise ValueError("Structured output parse failed: model returned empty response")
    if "<｜｜DSML｜｜tool_calls>" in stripped or "<||DSML||tool_calls>" in stripped:
        raise ValueError("Structured report stage returned tool calls instead of JSON")
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


def _preview(text: str, max_chars: int = 500) -> str:
    if not text:
        return "<empty>"
    return text[:max_chars] + ("...[truncated]" if len(text) > max_chars else "")
