from __future__ import annotations

import json
from pathlib import Path

import yaml

from runtime.baseline_batch_runner import BaselineBatchRunner


def test_baseline_batch_runner_skips_existing_success_rows(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    rtl = scope / "rtl"
    rtl.mkdir(parents=True)
    (rtl / "top.sv").write_text("module top; endmodule\n", encoding="utf-8")
    prompt = tmp_path / "prompt.md"
    prompt.write_text("Analyze {input_scope_path}.", encoding="utf-8")
    batch_dir = tmp_path / "runs" / "baseline" / "batch"
    batch_dir.mkdir(parents=True)
    status_path = batch_dir / "batch_status.jsonl"
    status_path.write_text(
        json.dumps(
            {
                "batch_id": "batch",
                "run_id": "batch__mock__scope__rep_1",
                "model_id": "mock",
                "provider": "mock",
                "model": "mock",
                "scope_id": "scope",
                "repetition": 1,
                "status": "success",
                "run_dir": "already-done",
                "error": None,
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "baseline_batch.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "batch_id": "batch",
                "method_name": "json_read_search",
                "prompt_path": str(prompt),
                "output_root": "runs/baseline",
                "repetitions": 2,
                "max_steps": 1,
                "models": [{"model_id": "mock", "provider": "mock", "model": "mock"}],
                "input_scopes": [{"scope_id": "scope", "path": str(scope)}],
            },
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    BaselineBatchRunner(project_root=tmp_path).run_from_config(config_path)

    status_rows = [json.loads(line) for line in status_path.read_text(encoding="utf-8").splitlines()]
    assert len(status_rows) == 2
    assert status_rows[0]["run_id"] == "batch__mock__scope__rep_1"
    assert status_rows[1]["run_id"] == "batch__mock__scope__rep_2"
