"""Batch runner for baseline experiments."""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from runtime.baseline_runner import BaselineRunConfig, BaselineRunner


@dataclass(frozen=True)
class BatchModelConfig:
    """One model entry in a baseline batch."""

    model_id: str
    provider: str
    model: str


@dataclass(frozen=True)
class BatchInputScopeConfig:
    """One input-scope entry in a baseline batch."""

    scope_id: str
    path: str


@dataclass(frozen=True)
class BaselineBatchConfig:
    """Configuration for a baseline batch."""

    batch_id: str
    method_name: str
    prompt_path: str
    output_root: str
    repetitions: int
    max_steps: int
    temperature: float
    max_tokens: int
    models: list[BatchModelConfig]
    input_scopes: list[BatchInputScopeConfig]
    max_file_chars: int = 20_000
    max_tool_result_chars: int = 8_000
    request_timeout: float | None = 600


class BaselineBatchRunner:
    """Run baseline experiments in model -> input_scope -> repetition order."""

    def __init__(self, project_root: str | Path | None = None) -> None:
        self.project_root = Path(project_root).resolve() if project_root else _default_project_root()
        self.single_runner = BaselineRunner(project_root=self.project_root)

    def run_from_config(self, config_path: str | Path) -> Path:
        """Load a YAML config and run the batch."""

        resolved_config_path = self._resolve_path(config_path)
        config = self.load_config(resolved_config_path)
        return self.run(config, source_config_path=resolved_config_path)

    def run(self, config: BaselineBatchConfig, source_config_path: Path | None = None) -> Path:
        """Run a batch and return the batch output directory."""

        self._validate_config(config)
        batch_dir = self._resolve_path(config.output_root) / config.batch_id
        batch_dir.mkdir(parents=True, exist_ok=True)

        manifest_path = batch_dir / "batch_manifest.json"
        status_path = batch_dir / "batch_status.jsonl"
        config_copy_path = batch_dir / "batch_config.yaml"
        existing_status_rows = _load_status_rows(status_path)
        successful_run_ids = {
            str(row.get("run_id"))
            for row in existing_status_rows
            if row.get("batch_id") == config.batch_id and row.get("status") == "success"
        }

        if source_config_path:
            shutil.copyfile(source_config_path, config_copy_path)
        else:
            config_copy_path.write_text(
                yaml.safe_dump(_batch_config_to_dict(config), allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )

        manifest = {
            "batch_id": config.batch_id,
            "method_name": config.method_name,
            "prompt_path": str(self._resolve_path(config.prompt_path)),
            "output_root": str(self._resolve_path(config.output_root)),
            "repetitions": config.repetitions,
            "max_steps": config.max_steps,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            "models": [model.__dict__ for model in config.models],
            "input_scopes": [scope.__dict__ for scope in config.input_scopes],
            "started_at": _now_iso(),
            "runs": existing_status_rows.copy(),
        }

        total_runs = len(config.models) * len(config.input_scopes) * config.repetitions
        current_run = 0
        success_count = 0
        failed_count = 0
        skipped_count = 0

        print(
            f"[baseline] batch_id={config.batch_id} total_runs={total_runs} "
            f"models={len(config.models)} scopes={len(config.input_scopes)} "
            f"repetitions={config.repetitions}",
            flush=True,
        )

        for model_cfg in config.models:
            for scope_cfg in config.input_scopes:
                for rep in range(1, config.repetitions + 1):
                    current_run += 1
                    run_id = f"rep_{rep}"
                    full_run_id = f"{config.batch_id}__{model_cfg.model_id}__{scope_cfg.scope_id}__{run_id}"
                    run_output_dir = (
                        Path(config.output_root)
                        / config.batch_id
                        / "models"
                        / model_cfg.model_id
                        / scope_cfg.scope_id
                    )
                    if full_run_id in successful_run_ids:
                        skipped_count += 1
                        print(
                            f"[baseline][{current_run}/{total_runs}] SKIP  "
                            f"model={model_cfg.model_id} scope={scope_cfg.scope_id} "
                            f"rep={rep} existing_success=true",
                            flush=True,
                        )
                        continue

                    run_config = BaselineRunConfig(
                        run_id=run_id,
                        method_name=config.method_name,  # type: ignore[arg-type]
                        provider=model_cfg.provider,  # type: ignore[arg-type]
                        model=model_cfg.model,
                        input_scope_path=scope_cfg.path,
                        prompt_path=config.prompt_path,
                        output_dir=str(run_output_dir),
                        temperature=config.temperature,
                        max_tokens=config.max_tokens,
                        max_steps=config.max_steps,
                        max_file_chars=config.max_file_chars,
                        max_tool_result_chars=config.max_tool_result_chars,
                        request_timeout=config.request_timeout,
                    )

                    started_at = _now_iso()
                    run_started = time.monotonic()
                    print(
                        f"[baseline][{current_run}/{total_runs}] START "
                        f"model={model_cfg.model_id} provider={model_cfg.provider} "
                        f"scope={scope_cfg.scope_id} rep={rep}",
                        flush=True,
                    )
                    try:
                        record = self.single_runner.run(run_config)
                        elapsed_seconds = time.monotonic() - run_started
                        status = {
                            "batch_id": config.batch_id,
                            "run_id": full_run_id,
                            "model_id": model_cfg.model_id,
                            "provider": model_cfg.provider,
                            "model": model_cfg.model,
                            "scope_id": scope_cfg.scope_id,
                            "repetition": rep,
                            "status": "success",
                            "started_at": started_at,
                            "completed_at": _now_iso(),
                            "run_dir": record.run_dir,
                            "error": None,
                        }
                        success_count += 1
                        print(
                            f"[baseline][{current_run}/{total_runs}] OK    "
                            f"model={model_cfg.model_id} scope={scope_cfg.scope_id} "
                            f"rep={rep} seconds={elapsed_seconds:.1f}",
                            flush=True,
                        )
                        print(
                            f"[baseline][{current_run}/{total_runs}] run_dir={record.run_dir}",
                            flush=True,
                        )
                    except Exception as exc:  # noqa: BLE001 - batch runner must record and continue.
                        elapsed_seconds = time.monotonic() - run_started
                        status = {
                            "batch_id": config.batch_id,
                            "run_id": full_run_id,
                            "model_id": model_cfg.model_id,
                            "provider": model_cfg.provider,
                            "model": model_cfg.model,
                            "scope_id": scope_cfg.scope_id,
                            "repetition": rep,
                            "status": "failed",
                            "started_at": started_at,
                            "completed_at": _now_iso(),
                            "run_dir": str(self._resolve_path(str(run_output_dir)) / run_id),
                            "error": str(exc),
                        }
                        failed_count += 1
                        print(
                            f"[baseline][{current_run}/{total_runs}] FAIL  "
                            f"model={model_cfg.model_id} scope={scope_cfg.scope_id} "
                            f"rep={rep} seconds={elapsed_seconds:.1f}",
                            flush=True,
                        )
                        print(
                            f"[baseline][{current_run}/{total_runs}] error={exc}",
                            flush=True,
                        )

                    _append_jsonl(status_path, status)
                    manifest["runs"].append(status)

        manifest["completed_at"] = _now_iso()
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        print(
            f"[baseline] batch completed: success={success_count} "
            f"failed={failed_count} skipped={skipped_count} total={total_runs}",
            flush=True,
        )
        print(f"[baseline] status_file={status_path}", flush=True)
        return batch_dir

    def load_config(self, config_path: str | Path) -> BaselineBatchConfig:
        """Load a YAML batch config."""

        path = self._resolve_path(config_path)
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Batch config must be a YAML mapping")

        return BaselineBatchConfig(
            batch_id=str(raw["batch_id"]),
            method_name=str(raw["method_name"]),
            prompt_path=str(raw["prompt_path"]),
            output_root=str(raw.get("output_root", "runs/baseline")),
            repetitions=int(raw.get("repetitions", 1)),
            max_steps=int(raw.get("max_steps", 20)),
            temperature=float(raw.get("temperature", 0.2)),
            max_tokens=int(raw.get("max_tokens", 8192)),
            max_file_chars=int(raw.get("max_file_chars", 20_000)),
            max_tool_result_chars=int(raw.get("max_tool_result_chars", 8_000)),
            request_timeout=_optional_float(raw.get("request_timeout", 600)),
            models=[
                BatchModelConfig(
                    model_id=str(item["model_id"]),
                    provider=str(item["provider"]),
                    model=str(item["model"]),
                )
                for item in raw["models"]
            ],
            input_scopes=[
                BatchInputScopeConfig(
                    scope_id=str(item["scope_id"]),
                    path=str(item["path"]),
                )
                for item in raw["input_scopes"]
            ],
        )

    def _validate_config(self, config: BaselineBatchConfig) -> None:
        if not config.batch_id:
            raise ValueError("batch_id is required")
        if config.repetitions < 1:
            raise ValueError("repetitions must be >= 1")
        if not config.models:
            raise ValueError("models must not be empty")
        if not config.input_scopes:
            raise ValueError("input_scopes must not be empty")

        prompt_path = self._resolve_path(config.prompt_path)
        if not prompt_path.exists():
            raise FileNotFoundError(f"Prompt path does not exist: {prompt_path}")

        for scope in config.input_scopes:
            scope_path = self._resolve_path(scope.path)
            if not scope_path.exists():
                raise FileNotFoundError(f"Input scope does not exist: {scope.scope_id}: {scope_path}")
            if not scope_path.is_dir():
                raise NotADirectoryError(f"Input scope is not a directory: {scope.scope_id}: {scope_path}")

    def _resolve_path(self, path: str | Path) -> Path:
        raw = Path(path)
        if raw.is_absolute():
            return raw.resolve()
        return (self.project_root / raw).resolve()


def _batch_config_to_dict(config: BaselineBatchConfig) -> dict[str, Any]:
    return {
        "batch_id": config.batch_id,
        "method_name": config.method_name,
        "prompt_path": config.prompt_path,
        "output_root": config.output_root,
        "repetitions": config.repetitions,
        "max_steps": config.max_steps,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "max_file_chars": config.max_file_chars,
        "max_tool_result_chars": config.max_tool_result_chars,
        "request_timeout": config.request_timeout,
        "models": [model.__dict__ for model in config.models],
        "input_scopes": [scope.__dict__ for scope in config.input_scopes],
    }


def _append_jsonl(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _load_status_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def _default_project_root() -> Path:
    return Path(__file__).resolve().parents[1]
