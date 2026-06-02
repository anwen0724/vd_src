"""Read/search-only LLM baseline method."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from llm.base import LLMClient
from tools.file_tools import ReadSearchTools, ToolResult


@dataclass(frozen=True)
class ToolTraceEntry:
    """One tool-call trace entry."""

    step: int
    tool: str
    arguments: dict[str, Any]
    status: str
    content_preview: str
    error: str | None = None
    truncated: bool = False


@dataclass(frozen=True)
class BaselineResult:
    """Result returned by the read/search-only baseline."""

    final_answer: str
    stopped_reason: str
    steps_used: int
    tool_trace: list[ToolTraceEntry]
    raw_model_outputs: list[str]


class ReadSearchLLMBaseline:
    """LLM baseline with read/search-only tools."""

    def __init__(
        self,
        llm_client: LLMClient,
        tools: ReadSearchTools,
        max_steps: int = 20,
        max_tool_result_chars: int = 8_000,
    ) -> None:
        self.llm_client = llm_client
        self.tools = tools
        self.max_steps = max_steps
        self.max_tool_result_chars = max_tool_result_chars

    def run(self, prompt: str) -> BaselineResult:
        """Run the baseline method and return the final answer and trace."""

        conversation = self._initial_prompt(prompt)
        trace: list[ToolTraceEntry] = []
        raw_outputs: list[str] = []

        for step in range(1, self.max_steps + 1):
            model_output = self.llm_client.generate(conversation)
            raw_outputs.append(model_output)

            parsed = self._parse_model_output(model_output)
            if parsed is None:
                conversation = self._append_parse_error(conversation, model_output)
                continue

            response_type = parsed.get("type")
            if response_type == "final_answer":
                return BaselineResult(
                    final_answer=str(parsed.get("content", "")),
                    stopped_reason="final_answer",
                    steps_used=step,
                    tool_trace=trace,
                    raw_model_outputs=raw_outputs,
                )

            if response_type != "tool_call":
                conversation = self._append_protocol_error(
                    conversation,
                    model_output,
                    "The JSON field 'type' must be either 'tool_call' or 'final_answer'.",
                )
                continue

            tool_name = str(parsed.get("tool", ""))
            arguments = parsed.get("arguments", {})
            if not isinstance(arguments, dict):
                arguments = {}

            tool_result = self._dispatch_tool(tool_name, arguments)
            trace.append(self._build_trace_entry(step, tool_name, arguments, tool_result))
            conversation = self._append_tool_result(conversation, model_output, tool_result)

        final_prompt = self._finalization_prompt(conversation)
        final_output = self.llm_client.generate(final_prompt)
        raw_outputs.append(final_output)
        final_answer = self._extract_final_answer(final_output)

        return BaselineResult(
            final_answer=final_answer,
            stopped_reason="max_steps",
            steps_used=self.max_steps,
            tool_trace=trace,
            raw_model_outputs=raw_outputs,
        )

    def _dispatch_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolResult:
        if tool_name == "list_dir":
            return self.tools.list_dir(path=str(arguments.get("path", ".")))
        if tool_name == "read_file":
            return self.tools.read_file(path=str(arguments.get("path", "")))
        if tool_name == "search_text":
            return self.tools.search_text(
                query=str(arguments.get("query", "")),
                path=str(arguments.get("path", ".")),
                case_sensitive=bool(arguments.get("case_sensitive", False)),
            )

        return ToolResult(
            tool=tool_name or "unknown",
            status="error",
            content="",
            error=f"Unknown tool: {tool_name}",
        )

    def _initial_prompt(self, task_prompt: str) -> str:
        return f"""{task_prompt}

## Tool Protocol

You may inspect the input scope only through the following tools:

1. list_dir
2. read_file
3. search_text

At each step, output exactly one JSON object and no extra text.

To call a tool:

{{"type": "tool_call", "tool": "list_dir", "arguments": {{"path": "."}}}}

{{"type": "tool_call", "tool": "read_file", "arguments": {{"path": "relative/path.sv"}}}}

{{"type": "tool_call", "tool": "search_text", "arguments": {{"query": "debug", "path": "."}}}}

When you are ready to answer:

{{"type": "final_answer", "content": "your final report"}}

Rules:
- Use only relative paths under the provided input scope.
- Do not request files outside the input scope.
- Do not invent file names, modules, signals, line numbers, or evidence.
- If a tool result is denied or errors, use that information and continue safely.
- Final answer must be based only on visible source evidence and tool results.
"""

    @staticmethod
    def _parse_model_output(model_output: str) -> dict[str, Any] | None:
        text = model_output.strip()
        if text.startswith("```"):
            text = _strip_fenced_json(text)
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def _append_tool_result(
        self,
        conversation: str,
        model_output: str,
        tool_result: ToolResult,
    ) -> str:
        content = tool_result.content
        if len(content) > self.max_tool_result_chars:
            content = content[: self.max_tool_result_chars]
            content += "\n\n[TRUNCATED: tool result exceeded max_tool_result_chars]"

        result_payload = {
            "tool": tool_result.tool,
            "status": tool_result.status,
            "path": tool_result.path,
            "error": tool_result.error,
            "truncated": tool_result.truncated,
            "content": content,
        }
        return f"""{conversation}

## Previous Model Output

{model_output}

## Tool Result

{json.dumps(result_payload, ensure_ascii=False, indent=2)}

Continue. Output exactly one JSON object and no extra text.
"""

    @staticmethod
    def _append_parse_error(conversation: str, model_output: str) -> str:
        return f"""{conversation}

## Previous Model Output

{model_output}

## Protocol Error

Your previous output was not valid JSON. Output exactly one valid JSON object using the tool protocol.
"""

    @staticmethod
    def _append_protocol_error(conversation: str, model_output: str, error: str) -> str:
        return f"""{conversation}

## Previous Model Output

{model_output}

## Protocol Error

{error}
Output exactly one valid JSON object using the tool protocol.
"""

    @staticmethod
    def _finalization_prompt(conversation: str) -> str:
        return f"""{conversation}

## Finalization Required

The maximum number of tool steps has been reached. Based only on the visible evidence and tool results above, output exactly one JSON object:

{{"type": "final_answer", "content": "your final report"}}
"""

    @staticmethod
    def _extract_final_answer(model_output: str) -> str:
        parsed = ReadSearchLLMBaseline._parse_model_output(model_output)
        if parsed and parsed.get("type") == "final_answer":
            return str(parsed.get("content", ""))
        return model_output

    @staticmethod
    def _build_trace_entry(
        step: int,
        tool_name: str,
        arguments: dict[str, Any],
        tool_result: ToolResult,
    ) -> ToolTraceEntry:
        preview = tool_result.content[:500]
        return ToolTraceEntry(
            step=step,
            tool=tool_name,
            arguments=arguments,
            status=tool_result.status,
            content_preview=preview,
            error=tool_result.error,
            truncated=tool_result.truncated,
        )


def result_to_dict(result: BaselineResult) -> dict[str, Any]:
    """Convert a baseline result to a JSON-serializable dictionary."""

    return {
        "final_answer": result.final_answer,
        "stopped_reason": result.stopped_reason,
        "steps_used": result.steps_used,
        "tool_trace": [asdict(entry) for entry in result.tool_trace],
        "raw_model_outputs": result.raw_model_outputs,
    }


def _strip_fenced_json(text: str) -> str:
    lines = text.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()
