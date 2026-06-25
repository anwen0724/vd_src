"""Runtime entry for proposed-method experiments."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from method.proposed.mock_llm import MockInitialVersionLLM
from method.proposed.models import ProposedPipelineConfig
from method.proposed.pipeline import ProposedMethodPipeline


ProviderName = Literal["mock", "gpt", "claude", "deepseek", "qwen"]


@dataclass(frozen=True)
class ProposedRunConfig:
    """Configuration for one proposed-method run."""

    run_id: str
    provider: ProviderName
    model: str | None
    input_scope_path: str
    knowledge_base_path: str | None = None
    output_dir: str = "runs/proposed"
    temperature: float = 0.2
    max_tokens: int = 8192
    max_steps: int = 20
    max_closure_iterations: int = 1
    max_tool_result_chars: int = 8_000
    request_timeout: float | None = 600


@dataclass(frozen=True)
class ProposedRunRecord:
    """Paths and metadata produced by one proposed-method run."""

    run_id: str
    run_dir: str
    static_fact_layer_path: str
    permission_fact_layer_path: str
    obligations_path: str
    inspection_records_path: str
    tool_observations_path: str
    closure_records_path: str
    final_answer_path: str
    structured_output_path: str
    run_metadata_path: str


class ProposedRunner:
    """Run and persist one proposed-method experiment."""

    def __init__(self, project_root: str | Path | None = None) -> None:
        self.project_root = Path(project_root).resolve() if project_root else _default_project_root()

    def run(self, config: ProposedRunConfig) -> ProposedRunRecord:
        started_at = _now_iso()
        input_scope_path = self._resolve_path(config.input_scope_path)
        knowledge_path = self._resolve_path(config.knowledge_base_path) if config.knowledge_base_path else None
        run_dir = self._resolve_path(config.output_dir) / config.run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        llm = self._create_stage_llm(config)
        pipeline = ProposedMethodPipeline(llm=llm)
        result = pipeline.run(
            ProposedPipelineConfig(
                scope_id=input_scope_path.name,
                input_scope_path=input_scope_path,
                knowledge_base_path=knowledge_path,
                output_dir=run_dir,
                max_closure_iterations=config.max_closure_iterations,
            )
        )
        completed_at = _now_iso()

        metadata_out = run_dir / "run_metadata.json"
        metadata = {
            "run_id": config.run_id,
            "method_name": "proposed_initial",
            "provider": config.provider,
            "model": config.model or ("mock-proposed" if config.provider == "mock" else ""),
            "input_scope_path": str(input_scope_path),
            "knowledge_base_path": str(knowledge_path) if knowledge_path else None,
            "output_dir": str(run_dir),
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            "max_steps": config.max_steps,
            "max_closure_iterations": config.max_closure_iterations,
            "max_tool_result_chars": config.max_tool_result_chars,
            "request_timeout": config.request_timeout,
            "started_at": started_at,
            "completed_at": completed_at,
            "final_answer_path": str(result.final_answer_path),
            "structured_output_path": str(result.structured_output_path),
            "tool_observations_path": str(result.tool_observations_path),
        }
        metadata_out.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")

        return ProposedRunRecord(
            run_id=config.run_id,
            run_dir=str(run_dir),
            static_fact_layer_path=str(result.static_fact_layer_path),
            permission_fact_layer_path=str(result.permission_fact_layer_path),
            obligations_path=str(result.obligations_path),
            inspection_records_path=str(result.inspection_records_path),
            tool_observations_path=str(result.tool_observations_path),
            closure_records_path=str(result.closure_records_path),
            final_answer_path=str(result.final_answer_path),
            structured_output_path=str(result.structured_output_path),
            run_metadata_path=str(metadata_out),
        )

    def _create_stage_llm(self, config: ProposedRunConfig):
        if config.provider == "mock":
            return MockInitialVersionLLM()
        from llm.langchain_models import LangChainModelConfig, create_chat_model
        from method.proposed.langchain_initial import LangChainInitialVersionLLM

        chat_model = create_chat_model(
            LangChainModelConfig(
                provider=config.provider,  # type: ignore[arg-type]
                model=config.model or _default_model(config.provider),
                temperature=config.temperature,
                max_tokens=config.max_tokens,
                request_timeout=config.request_timeout,
            )
        )
        return LangChainInitialVersionLLM(
            chat_model=chat_model,
            max_steps=config.max_steps,
            max_tool_result_chars=config.max_tool_result_chars,
        )

    def _resolve_path(self, path: str | Path | None) -> Path:
        if path is None:
            raise ValueError("Path is required")
        raw = Path(path)
        if raw.is_absolute():
            return raw.resolve()
        return (self.project_root / raw).resolve()


def _default_model(provider: str) -> str:
    defaults = {
        "gpt": "gpt-5.5",
        "claude": "claude-opus-4-20250514",
        "deepseek": "deepseek-v4-pro",
        "qwen": "qwen3-max",
    }
    return defaults.get(provider, "")


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def _default_project_root() -> Path:
    return Path(__file__).resolve().parents[1]
