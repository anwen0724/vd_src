from __future__ import annotations

import csv
import json
from pathlib import Path

from scripts.evaluate.summarize_ours_execution_cost import summarize_execution_cost


def test_summarize_execution_cost_writes_scope_and_chain_csv(tmp_path: Path) -> None:
    run_dir = (
        tmp_path
        / "runs"
        / "ours_chain_context"
        / "batch"
        / "models"
        / "deepseek"
        / "scope"
        / "rep_1"
    )
    run_dir.mkdir(parents=True)
    (run_dir / "run_metadata.json").write_text(
        json.dumps(
            {
                "run_id": "rep_1",
                "provider": "deepseek",
                "model": "deepseek-v4-pro",
                "elapsed_seconds": 12.5,
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "module3B_analysis_diagnostics.json").write_text(
        json.dumps(
            {
                "graph_id": "scope",
                "chain_count": 2,
                "llm_call_count": 2,
                "input_tokens": 30,
                "output_tokens": 10,
                "total_tokens": 40,
                "elapsed_seconds": 12.0,
                "per_chain": [
                    {
                        "chain_id": "CHAIN-0001",
                        "elapsed_seconds": 5.0,
                        "llm": {
                            "input_tokens": 10,
                            "output_tokens": 5,
                            "total_tokens": 15,
                            "token_usage_source": "api",
                        },
                    },
                    {
                        "chain_id": "CHAIN-0002",
                        "elapsed_seconds": 7.0,
                        "llm": {
                            "input_tokens": 20,
                            "output_tokens": 5,
                            "total_tokens": 25,
                            "token_usage_source": "api",
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    scope_csv, chain_csv = summarize_execution_cost(
        batch_root=tmp_path / "runs" / "ours_chain_context" / "batch",
        output_dir=tmp_path / "results",
    )

    scope_rows = list(csv.DictReader(scope_csv.open(encoding="utf-8")))
    chain_rows = list(csv.DictReader(chain_csv.open(encoding="utf-8")))
    assert scope_rows[0]["scope_id"] == "scope"
    assert scope_rows[0]["total_tokens"] == "40"
    assert chain_rows[1]["chain_id"] == "CHAIN-0002"
    assert chain_rows[1]["elapsed_seconds"] == "7.0"
