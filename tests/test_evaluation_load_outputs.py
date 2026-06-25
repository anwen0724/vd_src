from __future__ import annotations

import json
from pathlib import Path

from evaluation.old.build_score_tables import build_score_tables
from evaluation.old.load_outputs import load_batch_outputs


def test_load_batch_outputs_uses_proposed_tool_observations_when_tool_trace_missing(tmp_path: Path) -> None:
    batch_dir = tmp_path / "runs" / "proposed" / "batch"
    run_dir = batch_dir / "models" / "gpt" / "scope" / "rep_1"
    run_dir.mkdir(parents=True)
    trace_path = run_dir / "tool_observations.jsonl"
    trace_path.write_text('{"tool": "read_file", "path": "rtl/top.sv"}\n', encoding="utf-8")
    (run_dir / "final_answer.json").write_text('{"findings": []}', encoding="utf-8")
    (run_dir / "run_metadata.json").write_text(
        json.dumps({"method_name": "proposed_initial", "provider": "gpt", "model": "gpt-5.5"}),
        encoding="utf-8",
    )
    (batch_dir / "batch_manifest.json").write_text(
        json.dumps(
            {
                "batch_id": "batch",
                "runs": [
                    {
                        "batch_id": "batch",
                        "run_id": "batch__gpt__scope__rep_1",
                        "model_id": "gpt",
                        "provider": "gpt",
                        "model": "gpt-5.5",
                        "scope_id": "scope",
                        "repetition": 1,
                        "status": "success",
                        "run_dir": str(run_dir),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runs = load_batch_outputs(batch_dir)

    assert len(runs) == 1
    assert runs[0].trace_path == trace_path.resolve()
    assert runs[0].tool_trace == [{"tool": "read_file", "path": "rtl/top.sv"}]


def test_build_score_tables_writes_actual_trace_path_for_proposed_runs(tmp_path: Path) -> None:
    batch_dir = tmp_path / "runs" / "proposed" / "batch"
    run_dir = batch_dir / "models" / "gpt" / "scope" / "rep_1"
    run_dir.mkdir(parents=True)
    trace_path = run_dir / "tool_observations.jsonl"
    trace_path.write_text('{"tool": "read_file"}\n', encoding="utf-8")
    (run_dir / "final_answer.json").write_text('{"findings": []}', encoding="utf-8")
    (run_dir / "run_metadata.json").write_text(
        json.dumps({"method_name": "proposed_initial", "provider": "gpt", "model": "gpt-5.5"}),
        encoding="utf-8",
    )
    (batch_dir / "batch_manifest.json").write_text(
        json.dumps(
            {
                "batch_id": "batch",
                "runs": [
                    {
                        "batch_id": "batch",
                        "run_id": "batch__gpt__scope__rep_1",
                        "model_id": "gpt",
                        "provider": "gpt",
                        "model": "gpt-5.5",
                        "scope_id": "scope",
                        "repetition": 1,
                        "status": "success",
                        "run_dir": str(run_dir),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    gt_map = tmp_path / "input_scope_gt_map.csv"
    gt_map.write_text("input_scope,benchmark_id,expected_case_id,case_visibility\n", encoding="utf-8")
    output_dir = tmp_path / "scoring_draft"

    build_score_tables(load_batch_outputs(batch_dir), [gt_map], output_dir)

    run_metadata = (output_dir / "run_metadata.csv").read_text(encoding="utf-8-sig")
    assert str(trace_path.resolve()) in run_metadata


def test_build_score_tables_matches_hackatdac18_scope_alias(tmp_path: Path) -> None:
    batch_dir = tmp_path / "runs" / "baseline" / "batch"
    run_dir = batch_dir / "models" / "gpt" / "h18_debug_jtag_scope" / "rep_1"
    run_dir.mkdir(parents=True)
    (run_dir / "tool_trace.jsonl").write_text("", encoding="utf-8")
    (run_dir / "final_answer.json").write_text('{"findings": []}', encoding="utf-8")
    (run_dir / "run_metadata.json").write_text(
        json.dumps({"method_name": "baseline", "provider": "gpt", "model": "gpt-5.5"}),
        encoding="utf-8",
    )
    (batch_dir / "batch_manifest.json").write_text(
        json.dumps(
            {
                "batch_id": "batch",
                "runs": [
                    {
                        "batch_id": "batch",
                        "run_id": "batch__gpt__h18_debug_jtag_scope__rep_1",
                        "model_id": "gpt",
                        "provider": "gpt",
                        "model": "gpt-5.5",
                        "scope_id": "h18_debug_jtag_scope",
                        "repetition": 1,
                        "status": "success",
                        "run_dir": str(run_dir),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    gt_map = tmp_path / "input_scope_gt_map.csv"
    gt_map.write_text(
        "input_scope,benchmark_id,expected_case_id,case_visibility\n"
        "debug_jtag_scope,hackatdac18,H18-009,visible\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "scoring_draft"

    build_score_tables(load_batch_outputs(batch_dir), [gt_map], output_dir)

    case_scores = (output_dir / "case_level_scores.csv").read_text(encoding="utf-8-sig")
    assert "H18-009" in case_scores
