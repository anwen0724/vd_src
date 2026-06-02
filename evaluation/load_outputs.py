"""Helpers for loading baseline run outputs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RunOutput:
    """One completed baseline run and its saved artifacts."""

    batch_id: str
    run_id: str
    run_dir: Path
    model_id: str
    provider: str
    model: str
    input_scope: str
    repetition: int | None
    metadata: dict[str, Any]
    final_answer: dict[str, Any] | None
    tool_trace: list[dict[str, Any]]


def load_batch_outputs(batch_dir: str | Path) -> list[RunOutput]:
    """Load successful runs from a baseline batch directory."""

    root = Path(batch_dir).resolve()
    manifest_path = root / "batch_manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Missing batch manifest: {manifest_path}")

    manifest = _read_json(manifest_path)
    runs: list[RunOutput] = []
    for row in manifest.get("runs", []):
        if row.get("status") != "success":
            continue

        run_dir = Path(str(row["run_dir"])).resolve()
        metadata_path = run_dir / "run_metadata.json"
        metadata = _read_json(metadata_path) if metadata_path.exists() else {}
        final_answer_path = run_dir / "final_answer.json"
        final_answer = _read_json(final_answer_path) if final_answer_path.exists() else None
        tool_trace = _read_jsonl(run_dir / "tool_trace.jsonl")

        runs.append(
            RunOutput(
                batch_id=str(row.get("batch_id") or manifest.get("batch_id", "")),
                run_id=str(row.get("run_id") or metadata.get("run_id") or run_dir.name),
                run_dir=run_dir,
                model_id=str(row.get("model_id", "")),
                provider=str(row.get("provider", metadata.get("provider", ""))),
                model=str(row.get("model", metadata.get("model", ""))),
                input_scope=str(row.get("scope_id", "")),
                repetition=_as_int_or_none(row.get("repetition")),
                metadata=metadata,
                final_answer=final_answer,
                tool_trace=tool_trace,
            )
        )

    return runs


def load_single_run_output(run_dir: str | Path) -> RunOutput:
    """Load one run directory produced by BaselineRunner."""

    root = Path(run_dir).resolve()
    metadata = _read_json(root / "run_metadata.json")
    final_answer_path = root / "final_answer.json"
    final_answer = _read_json(final_answer_path) if final_answer_path.exists() else None
    tool_trace = _read_jsonl(root / "tool_trace.jsonl")

    return RunOutput(
        batch_id="",
        run_id=str(metadata.get("run_id") or root.name),
        run_dir=root,
        model_id=str(metadata.get("provider", "")),
        provider=str(metadata.get("provider", "")),
        model=str(metadata.get("model", "")),
        input_scope=_scope_name_from_path(str(metadata.get("input_scope_path", ""))),
        repetition=None,
        metadata=metadata,
        final_answer=final_answer,
        tool_trace=tool_trace,
    )


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped:
            rows.append(json.loads(stripped))
    return rows


def _as_int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def _scope_name_from_path(path: str) -> str:
    if not path:
        return ""
    return Path(path).name
