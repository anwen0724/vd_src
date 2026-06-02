"""Rerun failed runs in a baseline batch."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


def main() -> int:
    parser = argparse.ArgumentParser(description="Rerun failed baseline runs from a batch.")
    parser.add_argument(
        "--batch-dir",
        default="runs/baseline/baseline_hackatdac_deepseek_gpt_pilot_v1",
        help="Batch output directory relative to src/.",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from runtime.baseline_runner import BaselineRunConfig, BaselineRunner

    batch_dir = _resolve(project_root, args.batch_dir)
    manifest_path = batch_dir / "batch_manifest.json"
    config_path = batch_dir / "batch_config.yaml"
    status_path = batch_dir / "batch_status.jsonl"

    manifest = _read_json(manifest_path)
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    failed_indices = [
        index
        for index, row in enumerate(manifest.get("runs", []))
        if row.get("status") != "success"
    ]

    if not failed_indices:
        print("[rerun] no failed runs found", flush=True)
        return 0

    scopes_by_id = {str(item["scope_id"]): item for item in config["input_scopes"]}
    runner = BaselineRunner(project_root=project_root)

    print(f"[rerun] batch_dir={batch_dir}", flush=True)
    print(f"[rerun] failed_runs={len(failed_indices)}", flush=True)

    for ordinal, index in enumerate(failed_indices, start=1):
        row = manifest["runs"][index]
        model_id = str(row["model_id"])
        scope_id = str(row["scope_id"])
        repetition = int(row["repetition"])
        run_id = f"rep_{repetition}"
        scope_cfg = scopes_by_id[scope_id]
        run_output_dir = batch_dir / "models" / model_id / scope_id

        print(
            f"[rerun][{ordinal}/{len(failed_indices)}] START "
            f"model={model_id} scope={scope_id} rep={repetition}",
            flush=True,
        )

        started_at = _now_iso()
        try:
            record = runner.run(
                BaselineRunConfig(
                    run_id=run_id,
                    method_name=str(config["method_name"]),  # type: ignore[arg-type]
                    provider=str(row["provider"]),  # type: ignore[arg-type]
                    model=str(row["model"]),
                    input_scope_path=str(scope_cfg["path"]),
                    prompt_path=str(config["prompt_path"]),
                    output_dir=str(run_output_dir),
                    temperature=float(config.get("temperature", 0.2)),
                    max_tokens=int(config.get("max_tokens", 8192)),
                    max_steps=int(config.get("max_steps", 20)),
                    max_file_chars=int(config.get("max_file_chars", 20_000)),
                    max_tool_result_chars=int(config.get("max_tool_result_chars", 8_000)),
                )
            )
            updated = {
                **row,
                "status": "success",
                "started_at": started_at,
                "completed_at": _now_iso(),
                "run_dir": record.run_dir,
                "error": None,
                "rerun": True,
            }
            print(
                f"[rerun][{ordinal}/{len(failed_indices)}] OK    "
                f"model={model_id} scope={scope_id} rep={repetition}",
                flush=True,
            )
        except Exception as exc:  # noqa: BLE001 - rerun script must keep going.
            updated = {
                **row,
                "status": "failed",
                "started_at": started_at,
                "completed_at": _now_iso(),
                "run_dir": str(run_output_dir / run_id),
                "error": str(exc),
                "rerun": True,
            }
            print(
                f"[rerun][{ordinal}/{len(failed_indices)}] FAIL  "
                f"model={model_id} scope={scope_id} rep={repetition}",
                flush=True,
            )
            print(f"[rerun][{ordinal}/{len(failed_indices)}] error={exc}", flush=True)

        manifest["runs"][index] = updated

    manifest["rerun_completed_at"] = _now_iso()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    _write_jsonl(status_path, manifest["runs"])

    remaining = sum(1 for row in manifest["runs"] if row.get("status") != "success")
    print(f"[rerun] remaining_failed={remaining}", flush=True)
    print(f"[rerun] manifest_updated={manifest_path}", flush=True)
    print(f"[rerun] status_updated={status_path}", flush=True)
    return 0


def _resolve(project_root: Path, path: str) -> Path:
    raw = Path(path)
    if raw.is_absolute():
        return raw.resolve()
    return (project_root / raw).resolve()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
