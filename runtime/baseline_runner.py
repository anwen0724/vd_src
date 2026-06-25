"""Runtime entry for baseline experiments."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from llm import (
    ClaudeClient,
    ClaudeClientConfig,
    DeepSeekClient,
    DeepSeekClientConfig,
    GPTClient,
    GPTClientConfig,
    MockClient,
    MockClientConfig,
    QwenClient,
    QwenClientConfig,
)
from llm.langchain_models import LangChainModelConfig, create_chat_model
from method.baseline.langchain_read_search_llm import LangChainReadSearchLLMBaseline
from method.baseline.read_search_llm import ReadSearchLLMBaseline
from tools.file_tools import ReadSearchTools


ProviderName = Literal["mock", "gpt", "claude", "deepseek", "qwen"]
MethodName = Literal["json_read_search", "langchain_read_search"]


@dataclass(frozen=True)
class BaselineRunConfig:
    """Configuration for one baseline run."""

    run_id: str
    method_name: MethodName
    provider: ProviderName
    model: str | None
    input_scope_path: str
    prompt_path: str
    output_dir: str = "runs/baseline"
    temperature: float = 0.2
    max_tokens: int = 8192
    max_steps: int = 20
    max_file_chars: int = 20_000
    max_tool_result_chars: int = 8_000
    request_timeout: float | None = 600


@dataclass(frozen=True)
class BaselineRunRecord:
    """Paths and metadata produced by one baseline run."""

    run_id: str
    run_dir: str
    final_answer_path: str
    structured_output_path: str | None
    prompt_path: str
    tool_trace_path: str
    raw_model_outputs_path: str
    run_metadata_path: str


class BaselineRunner:
    """Run and persist one baseline experiment."""

    def __init__(self, project_root: str | Path | None = None) -> None:
        self.project_root = Path(project_root).resolve() if project_root else _default_project_root()

    def run(self, config: BaselineRunConfig) -> BaselineRunRecord:
        """Run one baseline experiment and save all runtime artifacts."""

        started_at = _now_iso()
        input_scope_path = self._resolve_path(config.input_scope_path)
        prompt_template_path = self._resolve_path(config.prompt_path)
        run_dir = self._resolve_path(config.output_dir) / config.run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        _log_stage(config.run_id, "build_prompt", "START")
        final_prompt = self._build_prompt(prompt_template_path, input_scope_path)
        _log_stage(config.run_id, "build_prompt", "OK")
        _log_stage(config.run_id, "run_method", "START")
        tools = ReadSearchTools(input_scope_path, max_file_chars=config.max_file_chars)
        result = self._run_method(config, final_prompt, tools)
        _log_stage(config.run_id, "run_method", "OK")
        completed_at = _now_iso()

        prompt_out = run_dir / "prompt.txt"
        final_answer_out = run_dir / "final_answer.md"
        structured_output_out = run_dir / "final_answer.json"
        tool_trace_out = run_dir / "tool_trace.jsonl"
        raw_outputs_out = run_dir / "raw_model_outputs.jsonl"
        metadata_out = run_dir / "run_metadata.json"

        _log_stage(config.run_id, "write_outputs", "START")
        prompt_out.write_text(final_prompt, encoding="utf-8")
        final_answer_out.write_text(result["final_answer"], encoding="utf-8")
        structured_output_path: str | None = None
        if result.get("structured_output") is not None:
            structured_output_out.write_text(
                json.dumps(result["structured_output"], ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            structured_output_path = str(structured_output_out)
        _write_jsonl(tool_trace_out, result["tool_trace"])
        _write_jsonl(raw_outputs_out, [{"text": text} for text in result["raw_outputs"]])

        metadata = {
            "run_id": config.run_id,
            "method_name": config.method_name,
            "provider": config.provider,
            "model": result["model"],
            "input_scope_path": str(input_scope_path),
            "prompt_template_path": str(prompt_template_path),
            "output_dir": str(run_dir),
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            "max_steps": config.max_steps,
            "max_file_chars": config.max_file_chars,
            "max_tool_result_chars": config.max_tool_result_chars,
            "request_timeout": config.request_timeout,
            "started_at": started_at,
            "completed_at": completed_at,
            "stopped_reason": result["stopped_reason"],
            "steps_used": result["steps_used"],
            "structured_output_path": structured_output_path,
        }
        metadata_out.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
        _log_stage(config.run_id, "write_outputs", "OK")

        return BaselineRunRecord(
            run_id=config.run_id,
            run_dir=str(run_dir),
            final_answer_path=str(final_answer_out),
            structured_output_path=structured_output_path,
            prompt_path=str(prompt_out),
            tool_trace_path=str(tool_trace_out),
            raw_model_outputs_path=str(raw_outputs_out),
            run_metadata_path=str(metadata_out),
        )

    def _run_method(
        self,
        config: BaselineRunConfig,
        final_prompt: str,
        tools: ReadSearchTools,
    ) -> dict[str, Any]:
        if config.method_name == "json_read_search":
            llm_client = _create_llm_client(config)
            baseline = ReadSearchLLMBaseline(
                llm_client=llm_client,
                tools=tools,
                max_steps=config.max_steps,
                max_tool_result_chars=config.max_tool_result_chars,
            )
            result = baseline.run(final_prompt)
            return {
                "final_answer": result.final_answer,
                "stopped_reason": result.stopped_reason,
                "steps_used": result.steps_used,
                "tool_trace": [asdict(entry) for entry in result.tool_trace],
                "raw_outputs": result.raw_model_outputs,
                "structured_output": None,
                "model": _model_name(config),
            }

        if config.method_name == "langchain_read_search":
            if config.provider == "mock":
                raise ValueError("langchain_read_search does not support provider='mock'")

            chat_model = create_chat_model(
                LangChainModelConfig(
                    provider=config.provider,
                    model=_model_name(config),
                    temperature=config.temperature,
                    max_tokens=config.max_tokens,
                    request_timeout=config.request_timeout,
                )
            )
            baseline = LangChainReadSearchLLMBaseline(
                chat_model=chat_model,
                tools=tools,
                max_steps=config.max_steps,
                max_tool_result_chars=config.max_tool_result_chars,
            )
            result = baseline.run(final_prompt)
            return {
                "final_answer": result.final_answer,
                "stopped_reason": result.stopped_reason,
                "steps_used": result.steps_used,
                "tool_trace": [asdict(entry) for entry in result.tool_trace],
                "raw_outputs": result.raw_message_texts,
                "structured_output": result.structured_output,
                "model": _model_name(config),
            }

        raise ValueError(f"Unsupported method_name: {config.method_name}")

    def _build_prompt(self, prompt_template_path: Path, input_scope_path: Path) -> str:
        template = prompt_template_path.read_text(encoding="utf-8")
        input_scope_text = str(input_scope_path)
        if "{input_scope_path}" in template:
            return template.replace("{input_scope_path}", input_scope_text)
        return f"INPUT_SCOPE:\n{input_scope_text}\n\n{template}"

    def _resolve_path(self, path: str) -> Path:
        raw = Path(path)
        if raw.is_absolute():
            return raw.resolve()
        return (self.project_root / raw).resolve()


def _create_llm_client(config: BaselineRunConfig):
    model = config.model
    if config.provider == "mock":
        return MockClient(MockClientConfig(model=model or MockClientConfig().model))
    if config.provider == "gpt":
        return GPTClient(
            GPTClientConfig(
                model=model or GPTClientConfig().model,
                temperature=config.temperature,
                max_tokens=config.max_tokens,
            )
        )
    if config.provider == "claude":
        return ClaudeClient(
            ClaudeClientConfig(
                model=model or ClaudeClientConfig().model,
                temperature=config.temperature,
                max_tokens=config.max_tokens,
            )
        )
    if config.provider == "deepseek":
        return DeepSeekClient(
            DeepSeekClientConfig(
                model=model or DeepSeekClientConfig().model,
                temperature=config.temperature,
                max_tokens=config.max_tokens,
            )
        )
    if config.provider == "qwen":
        return QwenClient(
            QwenClientConfig(
                model=model or QwenClientConfig().model,
                temperature=config.temperature,
                max_tokens=config.max_tokens,
            )
        )
    raise ValueError(f"Unsupported provider: {config.provider}")


def _model_name(config: BaselineRunConfig) -> str:
    if config.model:
        return config.model
    if config.provider == "mock":
        return MockClientConfig().model
    if config.provider == "gpt":
        return GPTClientConfig().model
    if config.provider == "claude":
        return ClaudeClientConfig().model
    if config.provider == "deepseek":
        return DeepSeekClientConfig().model
    if config.provider == "qwen":
        return QwenClientConfig().model
    raise ValueError(f"Unsupported provider: {config.provider}")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    lines = [json.dumps(row, ensure_ascii=False) for row in rows]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _log_stage(run_id: str, stage: str, status: str) -> None:
    print(f"[baseline-stage] run={run_id} stage={stage} {status}", flush=True)


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def _default_project_root() -> Path:
    return Path(__file__).resolve().parents[1]
