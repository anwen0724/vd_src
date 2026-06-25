"""LangChain implementation of the read/search-only LLM baseline."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any

from schemas.agent_output import AgentOutput
from tools.file_tools import ReadSearchTools
from tools.langchain_file_tools import build_langchain_file_tools


@dataclass(frozen=True)
class LangChainToolTraceEntry:
    """One LangChain tool-call trace entry."""

    step: int
    tool: str
    arguments: dict[str, Any]
    tool_call_id: str
    content_preview: str


@dataclass(frozen=True)
class LangChainBaselineResult:
    """Result returned by the LangChain read/search-only baseline."""

    final_answer: str
    structured_output: dict[str, Any]
    stopped_reason: str
    steps_used: int
    tool_trace: list[LangChainToolTraceEntry]
    raw_message_texts: list[str]


class LangChainReadSearchLLMBaseline:
    """Read/search-only baseline using LangChain tool calling."""

    def __init__(
        self,
        chat_model: Any,
        tools: ReadSearchTools,
        max_steps: int = 20,
        max_tool_result_chars: int = 8_000,
    ) -> None:
        self.file_tools = tools
        self.langchain_tools = build_langchain_file_tools(tools)
        self.tools_by_name = {tool.name: tool for tool in self.langchain_tools}
        self.base_model = chat_model
        self.model = chat_model.bind_tools(self.langchain_tools)
        self.structured_model = chat_model.with_structured_output(AgentOutput, method="function_calling")
        self.max_steps = max_steps
        self.max_tool_result_chars = max_tool_result_chars

    def run(self, prompt: str) -> LangChainBaselineResult:
        """Run the baseline method and return final answer and trace."""

        from langchain_core.messages import HumanMessage, ToolMessage

        messages: list[Any] = [HumanMessage(content=self._initial_prompt(prompt))]
        trace: list[LangChainToolTraceEntry] = []
        raw_message_texts: list[str] = []

        for step in range(1, self.max_steps + 1):
            ai_message = self.model.invoke(messages)
            messages.append(ai_message)
            raw_message_texts.append(_message_text(ai_message))

            tool_calls = getattr(ai_message, "tool_calls", None) or []
            if not tool_calls:
                structured_output, final_raw_text = self._produce_structured_output(messages)
                raw_message_texts.append(final_raw_text)
                return LangChainBaselineResult(
                    final_answer=json.dumps(structured_output, ensure_ascii=False, indent=2),
                    structured_output=structured_output,
                    stopped_reason="final_answer",
                    steps_used=step,
                    tool_trace=trace,
                    raw_message_texts=raw_message_texts,
                )

            for tool_call in tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call.get("args", {})
                tool_id = tool_call["id"]
                tool_result = self._invoke_tool(tool_name, tool_args)
                messages.append(ToolMessage(content=tool_result, tool_call_id=tool_id))
                trace.append(
                    LangChainToolTraceEntry(
                        step=step,
                        tool=tool_name,
                        arguments=tool_args,
                        tool_call_id=tool_id,
                        content_preview=tool_result[:500],
                    )
                )

        messages.append(HumanMessage(content=self._finalization_prompt()))
        structured_output, final_raw_text = self._produce_structured_output(messages)
        raw_message_texts.append(final_raw_text)

        return LangChainBaselineResult(
            final_answer=json.dumps(structured_output, ensure_ascii=False, indent=2),
            structured_output=structured_output,
            stopped_reason="max_steps",
            steps_used=self.max_steps,
            tool_trace=trace,
            raw_message_texts=raw_message_texts,
        )

    def _invoke_tool(self, tool_name: str, tool_args: dict[str, Any]) -> str:
        tool = self.tools_by_name.get(tool_name)
        if tool is None:
            return f'{{"status":"error","error":"Unknown tool: {tool_name}"}}'

        result = tool.invoke(tool_args)
        if len(result) > self.max_tool_result_chars:
            result = result[: self.max_tool_result_chars]
            result += "\n[TRUNCATED: tool result exceeded max_tool_result_chars]"
        return result

    def _produce_structured_output(self, messages: list[Any]) -> tuple[dict[str, Any], str]:
        from langchain_core.messages import HumanMessage

        final_messages = [
            *messages,
            HumanMessage(content="Produce the final result using the required structured output schema."),
        ]
        try:
            output = self.structured_model.invoke(final_messages)
            if isinstance(output, AgentOutput):
                data = output.model_dump()
            elif hasattr(output, "model_dump"):
                data = output.model_dump()
            elif isinstance(output, dict):
                data = AgentOutput.model_validate(output).model_dump()
            else:
                raise TypeError(f"Unexpected structured output type: {type(output)}")
            return data, json.dumps(data, ensure_ascii=False)
        except Exception as exc:  # noqa: BLE001 - provider compatibility fallback.
            return self._produce_structured_output_by_json_prompt(messages, exc)

    def _produce_structured_output_by_json_prompt(
        self,
        messages: list[Any],
        structured_error: Exception,
    ) -> tuple[dict[str, Any], str]:
        from langchain_core.messages import HumanMessage

        schema = AgentOutput.model_json_schema()
        fallback_messages = [
            *messages,
            HumanMessage(
                content=(
                    "Produce the final result as a single valid JSON object that conforms to "
                    "the following JSON schema. Do not wrap it in Markdown. "
                    f"Schema:\n{json.dumps(schema, ensure_ascii=False)}"
                )
            ),
        ]
        output = self.base_model.invoke(fallback_messages)
        raw_text = _message_text(output)
        data = _parse_json_object(raw_text)
        data["_structured_output_fallback"] = {
            "reason": "langchain_structured_output_failed",
            "error": str(structured_error),
        }
        validated = AgentOutput.model_validate(data).model_dump()
        return validated, raw_text

    @staticmethod
    def _initial_prompt(task_prompt: str) -> str:
        return f"""{task_prompt}

You may inspect the input scope only through the bound tools:

1. list_dir
2. read_file
3. search_text

Rules:
- Use only relative paths under the provided input scope.
- Do not request files outside the input scope.
- Do not modify files.
- Do not run code, scripts, simulation, formal tools, lint, synthesis, or network search.
- Final answer must be based only on visible source evidence and tool results.

When you have enough evidence, stop calling tools and provide the final report.
"""

    @staticmethod
    def _finalization_prompt() -> str:
        return (
            "The maximum number of tool steps has been reached. "
            "Based only on the visible evidence and tool results above, provide the final report."
        )


def result_to_dict(result: LangChainBaselineResult) -> dict[str, Any]:
    """Convert a LangChain baseline result to a JSON-serializable dictionary."""

    return {
        "final_answer": result.final_answer,
        "structured_output": result.structured_output,
        "stopped_reason": result.stopped_reason,
        "steps_used": result.steps_used,
        "tool_trace": [asdict(entry) for entry in result.tool_trace],
        "raw_message_texts": result.raw_message_texts,
    }


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
        raise TypeError("Structured JSON fallback must return an object")
    return parsed
