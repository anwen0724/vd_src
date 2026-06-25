from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from evaluation.old.merge_reviewed_scopes import merge_reviewed_scopes


class MergeReviewedScopesTest(unittest.TestCase):
    def test_writes_model_centered_summary_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            batch_dir = Path(tmp) / "batch"
            scope_dir = batch_dir / "scoring_reviewed_scope_scope_a"
            scope_dir.mkdir(parents=True)

            _write_csv(
                scope_dir / "run_metadata.csv",
                [
                    "run_id",
                    "batch_id",
                    "input_scope",
                    "agent_mode",
                    "model_family",
                    "model_version",
                    "provider",
                    "method_name",
                    "prompt_version",
                    "temperature",
                    "max_output_tokens",
                    "tool_policy",
                    "run_index",
                    "started_at",
                    "completed_at",
                    "output_path",
                    "trace_path",
                    "notes",
                ],
                [
                    {
                        "run_id": "run_a",
                        "batch_id": "batch",
                        "input_scope": "scope_a",
                        "model_family": "model_a",
                        "model_version": "model-a-v1",
                        "run_index": "1",
                    }
                ],
            )
            _write_csv(
                scope_dir / "case_level_scores.csv",
                [
                    "run_id",
                    "input_scope",
                    "benchmark_id",
                    "case_id",
                    "case_visibility",
                    "case_result",
                    "matched_finding_ids",
                    "miss_reason",
                    "scorer_notes",
                ],
                [
                    {
                        "run_id": "run_a",
                        "input_scope": "scope_a",
                        "benchmark_id": "bench_a",
                        "case_id": "case_a",
                        "case_visibility": "visible",
                        "case_result": "TP",
                    }
                ],
            )
            _write_csv(
                scope_dir / "finding_level_scores.csv",
                [
                    "run_id",
                    "finding_id",
                    "input_scope",
                    "claimed_summary",
                    "claimed_files",
                    "claimed_modules",
                    "claimed_signals",
                    "matched_case_id",
                    "detection_match",
                    "evidence_quality",
                    "confidence_label",
                    "wrong_localization",
                    "insufficient_evidence",
                    "fabricated_evidence",
                    "unsupported_claim",
                    "overconfidence",
                    "scorer_notes",
                ],
                [
                    {
                        "run_id": "run_a",
                        "finding_id": "finding_a",
                        "input_scope": "scope_a",
                        "matched_case_id": "case_a",
                        "detection_match": "TP",
                        "evidence_quality": "Sufficient",
                        "wrong_localization": "no",
                        "insufficient_evidence": "no",
                        "fabricated_evidence": "no",
                        "unsupported_claim": "no",
                        "overconfidence": "no",
                    }
                ],
            )
            _write_csv(
                scope_dir / "failure_analysis.csv",
                [
                    "run_id",
                    "input_scope",
                    "case_id_or_finding_id",
                    "failure_manifestation",
                    "failure_layer",
                    "suspected_cause",
                    "evidence_excerpt",
                    "impact_on_engineer",
                    "needs_followup",
                    "notes",
                ],
                [
                    {
                        "run_id": "run_a",
                        "input_scope": "scope_a",
                        "case_id_or_finding_id": "case_a",
                        "failure_manifestation": "",
                    }
                ],
            )

            out = merge_reviewed_scopes(batch_dir)

            self.assertTrue((out / "model_summary.csv").exists())
            self.assertTrue((out / "model_scope_summary.csv").exists())
            self.assertTrue((out / "model_benchmark_summary.csv").exists())
            self.assertTrue((out / "global_summary.csv").exists())
            self.assertFalse((out / "overall_summary.csv").exists())

            model_rows = _read_csv(out / "model_summary.csv")
            self.assertEqual(1, len(model_rows))
            self.assertEqual("model_a", model_rows[0]["model_family"])
            self.assertEqual("1.000000", model_rows[0]["recall"])
            self.assertEqual("1.000000", model_rows[0]["precision"])

    def test_writes_independent_anyhit_summary_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            batch_dir = Path(tmp) / "batch"
            scope_dir = batch_dir / "scoring_reviewed_scope_scope_a"
            scope_dir.mkdir(parents=True)

            _write_csv(
                scope_dir / "run_metadata.csv",
                [
                    "run_id",
                    "batch_id",
                    "input_scope",
                    "agent_mode",
                    "model_family",
                    "model_version",
                    "provider",
                    "method_name",
                    "prompt_version",
                    "temperature",
                    "max_output_tokens",
                    "tool_policy",
                    "run_index",
                    "started_at",
                    "completed_at",
                    "output_path",
                    "trace_path",
                    "notes",
                ],
                [
                    {
                        "run_id": "run_1",
                        "batch_id": "batch",
                        "input_scope": "scope_a",
                        "model_family": "model_a",
                        "model_version": "model-a-v1",
                        "run_index": "1",
                    },
                    {
                        "run_id": "run_2",
                        "batch_id": "batch",
                        "input_scope": "scope_a",
                        "model_family": "model_a",
                        "model_version": "model-a-v1",
                        "run_index": "2",
                    },
                    {
                        "run_id": "run_3",
                        "batch_id": "batch",
                        "input_scope": "scope_a",
                        "model_family": "model_a",
                        "model_version": "model-a-v1",
                        "run_index": "3",
                    },
                ],
            )
            _write_csv(
                scope_dir / "case_level_scores.csv",
                [
                    "run_id",
                    "input_scope",
                    "benchmark_id",
                    "case_id",
                    "case_visibility",
                    "case_result",
                    "matched_finding_ids",
                    "miss_reason",
                    "scorer_notes",
                ],
                [
                    {
                        "run_id": "run_1",
                        "input_scope": "scope_a",
                        "benchmark_id": "bench_a",
                        "case_id": "case_tp",
                        "case_visibility": "visible",
                        "case_result": "FN",
                    },
                    {
                        "run_id": "run_2",
                        "input_scope": "scope_a",
                        "benchmark_id": "bench_a",
                        "case_id": "case_tp",
                        "case_visibility": "visible",
                        "case_result": "Partial",
                    },
                    {
                        "run_id": "run_3",
                        "input_scope": "scope_a",
                        "benchmark_id": "bench_a",
                        "case_id": "case_tp",
                        "case_visibility": "visible",
                        "case_result": "TP",
                    },
                    {
                        "run_id": "run_1",
                        "input_scope": "scope_a",
                        "benchmark_id": "bench_a",
                        "case_id": "case_partial",
                        "case_visibility": "visible",
                        "case_result": "FN",
                    },
                    {
                        "run_id": "run_2",
                        "input_scope": "scope_a",
                        "benchmark_id": "bench_a",
                        "case_id": "case_partial",
                        "case_visibility": "visible",
                        "case_result": "Partial",
                    },
                    {
                        "run_id": "run_3",
                        "input_scope": "scope_a",
                        "benchmark_id": "bench_a",
                        "case_id": "case_partial",
                        "case_visibility": "visible",
                        "case_result": "FN",
                    },
                    {
                        "run_id": "run_1",
                        "input_scope": "scope_a",
                        "benchmark_id": "bench_a",
                        "case_id": "case_fn",
                        "case_visibility": "visible",
                        "case_result": "FN",
                    },
                    {
                        "run_id": "run_2",
                        "input_scope": "scope_a",
                        "benchmark_id": "bench_a",
                        "case_id": "case_fn",
                        "case_visibility": "visible",
                        "case_result": "FN",
                    },
                    {
                        "run_id": "run_3",
                        "input_scope": "scope_a",
                        "benchmark_id": "bench_a",
                        "case_id": "case_fn",
                        "case_visibility": "visible",
                        "case_result": "FN",
                    },
                ],
            )
            _write_csv(
                scope_dir / "finding_level_scores.csv",
                [
                    "run_id",
                    "finding_id",
                    "input_scope",
                    "claimed_summary",
                    "claimed_files",
                    "claimed_modules",
                    "claimed_signals",
                    "matched_case_id",
                    "detection_match",
                    "evidence_quality",
                    "confidence_label",
                    "wrong_localization",
                    "insufficient_evidence",
                    "fabricated_evidence",
                    "unsupported_claim",
                    "overconfidence",
                    "scorer_notes",
                ],
                [
                    {
                        "run_id": "run_3",
                        "finding_id": "finding_1",
                        "input_scope": "scope_a",
                        "claimed_summary": "matched case_tp",
                        "matched_case_id": "case_tp",
                        "detection_match": "TP",
                        "evidence_quality": "Sufficient",
                        "wrong_localization": "no",
                        "insufficient_evidence": "no",
                        "fabricated_evidence": "no",
                        "unsupported_claim": "no",
                        "overconfidence": "no",
                    }
                ],
            )
            _write_csv(
                scope_dir / "failure_analysis.csv",
                [
                    "run_id",
                    "input_scope",
                    "case_id_or_finding_id",
                    "failure_manifestation",
                    "failure_layer",
                    "suspected_cause",
                    "evidence_excerpt",
                    "impact_on_engineer",
                    "needs_followup",
                    "notes",
                ],
                [
                    {
                        "run_id": "run_1",
                        "input_scope": "scope_a",
                        "case_id_or_finding_id": "case_tp",
                    }
                ],
            )

            out = merge_reviewed_scopes(batch_dir)

            self.assertTrue((out / "model_anyhit_summary.csv").exists())
            self.assertTrue((out / "model_benchmark_anyhit_summary.csv").exists())
            self.assertTrue((out / "model_scope_anyhit_summary.csv").exists())

            model_scope_rows = _read_csv(out / "model_scope_anyhit_summary.csv")
            self.assertEqual(1, len(model_scope_rows))
            self.assertEqual("model_a", model_scope_rows[0]["model_family"])
            self.assertEqual("scope_a", model_scope_rows[0]["input_scope"])
            self.assertEqual("3", model_scope_rows[0]["num_cases"])
            self.assertEqual("1", model_scope_rows[0]["tp_cases"])
            self.assertEqual("1", model_scope_rows[0]["partial_cases"])
            self.assertEqual("1", model_scope_rows[0]["fn_cases"])
            self.assertEqual("0.333333", model_scope_rows[0]["recall"])
            self.assertEqual("0.333333", model_scope_rows[0]["partial_rate"])
            self.assertEqual("0.333333", model_scope_rows[0]["fn_rate"])


def _write_csv(path: Path, columns: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


if __name__ == "__main__":
    unittest.main()
