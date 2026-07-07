"""Single-run runtime entry for the ours chain-context method."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from llm.langchain_models import LangChainModelConfig, create_chat_model
from method.ours.chain_context_analysis.config import ChainContextAnalysisConfig
from method.ours.chain_context_analysis.pipeline import run_chain_context_analysis


ProviderName = Literal["gpt", "claude", "deepseek", "qwen", "gemini"]


@dataclass(frozen=True)
class OursChainContextRunConfig:
    """Configuration for one module-3 chain-context analysis run."""

    run_id: str
    provider: ProviderName
    model: str
    context_path: str
    repo_path: str
    output_dir: str = "runs/ours_chain_context"
    temperature: float = 0.2
    max_tokens: int = 8192
    max_chains: int | None = None
    request_timeout: float | None = 600
    require_violation_evidence: bool = True


@dataclass(frozen=True)
class OursChainContextRunRecord:
    """Paths produced by one chain-context run."""

    run_id: str
    run_dir: str
    final_answer_path: str
    final_findings_path: str
    diagnostics_path: str
    run_metadata_path: str


class OursChainContextRunner:
    """Run module 3 on one prepared permission-chain context file."""

    def __init__(self, project_root: str | Path | None = None) -> None:
        self.project_root = Path(project_root).resolve() if project_root else _default_project_root()

    def run(self, config: OursChainContextRunConfig) -> OursChainContextRunRecord:
        started_at = _now_iso()
        started = time.monotonic()
        context_path = self._resolve_path(config.context_path)
        repo_path = self._resolve_path(config.repo_path)
        run_dir = self._resolve_path(config.output_dir) / config.run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        if not context_path.exists():
            raise FileNotFoundError(f"Context file does not exist: {context_path}")
        if not repo_path.exists():
            raise FileNotFoundError(f"Repo path does not exist: {repo_path}")
        if not repo_path.is_dir():
            raise NotADirectoryError(f"Repo path is not a directory: {repo_path}")

        chat_model = create_chat_model(
            LangChainModelConfig(
                provider=config.provider,
                model=config.model,
                temperature=config.temperature,
                max_tokens=config.max_tokens,
                request_timeout=config.request_timeout,
            )
        )
        summary = run_chain_context_analysis(
            contexts_path=context_path,
            repo_root=repo_path,
            output_dir=run_dir,
            chat_model=chat_model,
            config=ChainContextAnalysisConfig(
                max_chains=config.max_chains,
                require_violation_evidence=config.require_violation_evidence,
            ),
        )

        final_answer_path = run_dir / "final_answer.json"
        final_findings_path = run_dir / "final_findings.json"
        diagnostics_path = run_dir / "module3B_analysis_diagnostics.json"
        metadata_path = run_dir / "run_metadata.json"
        completed_at = _now_iso()
        elapsed_seconds = time.monotonic() - started
        metadata = {
            "run_id": config.run_id,
            "method_name": "ours_chain_context",
            "provider": config.provider,
            "model": config.model,
            "context_path": str(context_path),
            "repo_path": str(repo_path),
            "output_dir": str(run_dir),
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            "max_chains": config.max_chains,
            "request_timeout": config.request_timeout,
            "require_violation_evidence": config.require_violation_evidence,
            "started_at": started_at,
            "completed_at": completed_at,
            "elapsed_seconds": elapsed_seconds,
            "summary": summary,
            "config": asdict(config),
        }
        metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")

        return OursChainContextRunRecord(
            run_id=config.run_id,
            run_dir=str(run_dir),
            final_answer_path=str(final_answer_path),
            final_findings_path=str(final_findings_path),
            diagnostics_path=str(diagnostics_path),
            run_metadata_path=str(metadata_path),
        )

    def _resolve_path(self, path: str | Path) -> Path:
        raw = Path(path)
        if raw.is_absolute():
            return raw.resolve()
        return (self.project_root / raw).resolve()


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def _default_project_root() -> Path:
    return Path(__file__).resolve().parents[1]
