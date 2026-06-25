from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from evaluation.build_failure_candidates import build_failure_candidates
from evaluation.build_finding_review import build_finding_review
from evaluation.build_gt_cases import build_gt_cases
from evaluation.collect_model_summaries import collect_model_summaries
from evaluation.compute_anyhit3_metrics import compute_anyhit3_metrics
from evaluation.compute_single_run_metrics import compute_single_run_metrics
from evaluation.init_failure_analysis import init_failure_analysis
from evaluation.summarize_failure_mechanisms import summarize_failure_mechanisms
from evaluation.validate_finding_review import validate_finding_review


class EvaluationWorkflowScriptsTest(unittest.TestCase):
    def test_build_gt_cases_from_benchmark_assets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bench = root / "datasets" / "benchmarks" / "hackatdacx"
            bench.mkdir(parents=True)
            _write_csv(
                bench / "task_gt.csv",
                [
                    "case_id",
                    "vulnerable_behavior_summary",
                    "notes",
                ],
                [
                    {
                        "case_id": "HX-001",
                        "vulnerable_behavior_summary": "Lock register can be overwritten.",
                        "notes": "case note",
                    }
                ],
            )
            _write_csv(
                bench / "official_gt.csv",
                [
                    "case_id",
                    "official_description",
                ],
                [
                    {
                        "case_id": "HX-001",
                        "official_description": "Official lock register bug.",
                    }
                ],
            )
            _write_csv(
                bench / "input_scope_gt_map.csv",
                [
                    "run_id",
                    "input_scope",
                    "benchmark_id",
                    "expected_case_id",
                    "case_visibility",
                    "reason",
                    "notes",
                ],
                [
                    {
                        "run_id": "run",
                        "input_scope": "scope_a",
                        "benchmark_id": "hackatdacx",
                        "expected_case_id": "HX-001",
                        "case_visibility": "visible",
                    }
                ],
            )
            _write_jsonl(
                bench / "evidence_gt.jsonl",
                [
                    {
                        "case_id": "HX-001",
                        "files": ["third_party/hackatdacx/rtl/a.sv"],
                        "modules": ["mod_a"],
                        "evidence_trace": [
                            {
                                "signal_or_register": "lock_reg",
                                "why_it_matters": "lock guard evidence",
                            }
                        ],
                        "hit_summary": "hit lock case",
                    }
                ],
            )

            out = root / "evaluation_results" / "gt_cases.csv"
            rows = build_gt_cases(root / "datasets" / "benchmarks", out)

            self.assertEqual(1, len(rows))
            self.assertTrue(out.exists())
            self.assertEqual("HX-001", rows[0]["case_id"])
            self.assertEqual("scope_a", rows[0]["input_scope"])
            self.assertEqual("Official lock register bug.", rows[0]["official_description"])
            self.assertEqual("Official lock register bug.", _read_csv(out)[0]["official_description"])
            self.assertEqual("rtl/a.sv", rows[0]["gt_files"])
            self.assertEqual("mod_a", rows[0]["gt_modules"])
            self.assertIn("lock_reg", rows[0]["gt_signals_or_registers"])
            self.assertIn("hit lock case", rows[0]["gt_evidence_notes"])
            self.assertEqual("datasets/benchmarks/hackatdacx/cases/HX-001.md", rows[0]["case_doc_path"])

    def test_build_gt_cases_falls_back_to_evidence_trace_files_and_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bench = root / "datasets" / "benchmarks" / "hackatdacx"
            bench.mkdir(parents=True)
            _write_csv(
                bench / "task_gt.csv",
                ["case_id", "vulnerable_behavior_summary", "notes"],
                [
                    {
                        "case_id": "HX-002",
                        "vulnerable_behavior_summary": "Debug auth signal is exposed.",
                        "notes": "",
                    }
                ],
            )
            _write_csv(
                bench / "input_scope_gt_map.csv",
                ["input_scope", "benchmark_id", "expected_case_id", "case_visibility"],
                [
                    {
                        "input_scope": "scope_b",
                        "benchmark_id": "hackatdacx",
                        "expected_case_id": "HX-002",
                        "case_visibility": "visible",
                    }
                ],
            )
            _write_jsonl(
                bench / "evidence_gt.jsonl",
                [
                    {
                        "case_id": "HX-002",
                        "evidence_trace": [
                            {
                                "file": "third_party/hackatdacx/rtl/debug.sv",
                                "module": "debug_top",
                                "signal_or_register": "debug_unlock",
                            },
                            {
                                "file": "third_party/hackatdacx/rtl/debug.sv",
                                "module": "debug_top",
                                "signal_or_register": "debug_state",
                            },
                        ],
                    }
                ],
            )

            rows = build_gt_cases(root / "datasets" / "benchmarks", root / "gt_cases.csv")

            self.assertEqual("rtl/debug.sv", rows[0]["gt_files"])
            self.assertEqual("debug_top", rows[0]["gt_modules"])

    def test_build_gt_cases_uses_run_scope_id_for_hackatdac18(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bench = root / "datasets" / "benchmarks" / "hackatdac18"
            bench.mkdir(parents=True)
            _write_csv(
                bench / "task_gt.csv",
                ["case_id", "vulnerable_behavior_summary", "notes"],
                [{"case_id": "H18-X", "vulnerable_behavior_summary": "case", "notes": ""}],
            )
            _write_csv(
                bench / "input_scope_gt_map.csv",
                ["input_scope", "benchmark_id", "expected_case_id", "case_visibility"],
                [
                    {
                        "input_scope": "debug_jtag_scope",
                        "benchmark_id": "hackatdac18",
                        "expected_case_id": "H18-X",
                        "case_visibility": "visible",
                    }
                ],
            )
            _write_jsonl(
                bench / "evidence_gt.jsonl",
                [
                    {
                        "case_id": "H18-X",
                        "files": ["third_party/hackatdac18/rtl/top.sv"],
                        "modules": ["top"],
                        "evidence_trace": [{"signal_or_register": "debug"}],
                    }
                ],
            )

            rows = build_gt_cases(root / "datasets" / "benchmarks", root / "gt_cases.csv")

            self.assertEqual("h18_debug_jtag_scope", rows[0]["input_scope"])

    def test_build_finding_review_flattens_final_answer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = _make_run(
                root,
                method="baseline",
                batch="batch_a",
                model="model_a",
                scope="scope_a",
                rep=1,
                findings=[
                    {
                        "finding_id": "F1",
                        "status": "confirmed_finding",
                        "summary": "Debug path lacks guard.",
                        "vulnerability_category": "debug auth",
                        "affected_locations": [
                            {
                                "file": "rtl/top.sv",
                                "line_start": 10,
                                "line_end": 20,
                                "module": "top",
                                "signal_or_register": "debug_en",
                            }
                        ],
                        "evidence": [
                            {
                                "file": "rtl/top.sv",
                                "line_start": 10,
                                "line_end": 20,
                                "module": "top",
                                "object": "debug_en",
                                "evidence_type": "missing_guard",
                                "description": "debug_en drives access directly",
                                "supports_claim": "shows missing guard",
                            }
                        ],
                        "reasoning_summary": "JTAG -> debug path has no guard.",
                        "security_impact": "debug access",
                        "confidence": "high",
                        "uncertainty_or_missing_evidence": "none",
                    }
                ],
            )

            out = root / "evaluation_results" / "baseline" / "model_a" / "finding_review_draft.csv"
            rows = build_finding_review(root / "runs" / "baseline" / "batch_a", out)

            self.assertEqual(1, len(rows))
            self.assertTrue(out.exists())
            row = rows[0]
            self.assertEqual("baseline", row["method_name"])
            self.assertEqual("model_a", row["model_family"])
            self.assertEqual("scope_a", row["input_scope"])
            self.assertEqual("1", row["repetition"])
            self.assertEqual("F1", row["finding_id"])
            self.assertEqual("confirmed_finding", row["model_reported_status"])
            self.assertIn("rtl/top.sv", row["affected_locations"])
            self.assertEqual("rtl/top.sv", row["claimed_files"])
            self.assertEqual("top", row["claimed_modules"])
            self.assertIn("debug_en", row["claimed_signals_or_registers"])
            self.assertIn("missing_guard", row["evidence_items"])
            self.assertEqual(str(run_dir / "final_answer.json"), row["final_answer_path"])
            self.assertEqual("", row["detection_match"])

    def test_build_finding_review_can_filter_one_model(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_run(
                root,
                method="baseline",
                batch="batch_a",
                model="model_a",
                scope="scope_a",
                rep=1,
                findings=[{"finding_id": "A1", "summary": "model a finding"}],
            )
            _make_run(
                root,
                method="baseline",
                batch="batch_a",
                model="model_b",
                scope="scope_a",
                rep=1,
                findings=[{"finding_id": "B1", "summary": "model b finding"}],
            )

            out = root / "evaluation_results" / "baseline" / "model_a" / "finding_review_draft.csv"
            rows = build_finding_review(
                root / "runs" / "baseline" / "batch_a",
                out,
                model_family="model_a",
            )

            self.assertEqual(1, len(rows))
            self.assertEqual("model_a", rows[0]["model_family"])
            self.assertEqual("A1", rows[0]["finding_id"])

    def test_validate_finding_review_rejects_invalid_manual_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gt = root / "gt_cases.csv"
            review = root / "finding_review.csv"
            _write_csv(gt, ["case_id", "benchmark_id", "input_scope"], [{"case_id": "C1"}])
            _write_csv(
                review,
                _finding_review_columns(),
                [
                    _finding_row(
                        finding_uid="F1",
                        matched_case_id="C1",
                        detection_match="Partial",
                        evidence_quality="Sufficient",
                    )
                ],
            )

            errors = validate_finding_review(gt, review)

            self.assertTrue(errors)
            self.assertIn("Partial", "\n".join(errors))

    def test_compute_single_run_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gt, review = _write_metric_fixture(root)

            out_dir = root / "evaluation_results" / "baseline" / "model_a" / "single_run"
            run_rows, summary_rows = compute_single_run_metrics(gt, review, out_dir)

            self.assertEqual(2, len(run_rows))
            rep1 = next(row for row in run_rows if row["repetition"] == "1")
            rep2 = next(row for row in run_rows if row["repetition"] == "2")
            self.assertEqual("0.500000", rep1["precision"])
            self.assertEqual("0.500000", rep1["recall"])
            self.assertEqual("0.500000", rep1["f1_score"])
            self.assertEqual("1.000000", rep1["evidence_sufficiency_rate"])
            self.assertEqual("0.500000", rep1["fabricated_unsupported_evidence_rate"])
            self.assertEqual("1.000000", rep2["precision"])
            self.assertEqual("1.000000", rep2["recall"])
            self.assertEqual(1, len(summary_rows))
            self.assertEqual("0.750000", summary_rows[0]["precision_mean"])
            self.assertEqual("0.750000", summary_rows[0]["recall_mean"])
            self.assertTrue((out_dir / "single_run_metrics.csv").exists())
            self.assertTrue((out_dir / "single_run_model_summary.csv").exists())

    def test_compute_anyhit3_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gt, review = _write_metric_fixture(root)

            out_dir = root / "evaluation_results" / "baseline" / "model_a" / "anyhit3"
            case_rows, summary_rows = compute_anyhit3_metrics(gt, review, out_dir)

            self.assertEqual(2, len(case_rows))
            self.assertTrue(all(row["case_result"] == "TP" for row in case_rows))
            self.assertEqual(1, len(summary_rows))
            summary = summary_rows[0]
            self.assertEqual("2", summary["tp_cases"])
            self.assertEqual("0", summary["fn_cases"])
            self.assertEqual("2", summary["representative_tp_findings"])
            self.assertEqual("1", summary["fp_findings"])
            self.assertEqual("0.666667", summary["precision"])
            self.assertEqual("1.000000", summary["recall"])
            self.assertEqual("0.800000", summary["f1_score"])
            self.assertEqual("1.000000", summary["evidence_sufficiency_rate"])
            self.assertEqual("0.333333", summary["fabricated_unsupported_evidence_rate"])

    def test_build_failure_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gt, review = _write_metric_fixture(root)
            out = root / "evaluation_results" / "baseline" / "model_a" / "failure_analysis"

            rows = build_failure_candidates(gt, review, out)

            object_types = {row["failure_object_type"] for row in rows}
            self.assertIn("FP_finding", object_types)
            self.assertIn("FN_case", object_types)
            self.assertIn("Evidence_failure", object_types)
            self.assertTrue((out / "run_failure_candidates.csv").exists())

    def test_summarize_failure_mechanisms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            analysis = root / "run_failure_analysis.csv"
            _write_csv(
                analysis,
                [
                    "failure_uid",
                    "model_family",
                    "method_name",
                    "input_scope",
                    "failure_mechanism",
                    "method_implication",
                ],
                [
                    {
                        "failure_uid": "E1",
                        "model_family": "model_a",
                        "method_name": "baseline",
                        "input_scope": "scope_a",
                        "failure_mechanism": "semantic",
                        "method_implication": "add knowledge",
                    },
                    {
                        "failure_uid": "E2",
                        "model_family": "model_a",
                        "method_name": "baseline",
                        "input_scope": "scope_b",
                        "failure_mechanism": "semantic",
                        "method_implication": "add guard reasoning",
                    },
                ],
            )

            rows = summarize_failure_mechanisms(analysis, root)

            self.assertEqual(1, len(rows))
            self.assertEqual("semantic", rows[0]["failure_mechanism"])
            self.assertEqual("2", rows[0]["failure_count"])
            self.assertIn("scope_a", rows[0]["affected_input_scopes"])
            self.assertIn("E1", rows[0]["representative_failure_uids"])
            self.assertTrue((root / "failure_mechanism_summary.csv").exists())

    def test_init_failure_analysis_from_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidates = root / "run_failure_candidates.csv"
            _write_csv(
                candidates,
                [
                    "failure_uid",
                    "model_family",
                    "method_name",
                    "input_scope",
                    "repetition",
                    "run_id",
                    "failure_object_type",
                    "related_finding_uid",
                    "related_case_id",
                    "detection_match",
                    "evidence_quality",
                    "summary",
                    "final_answer_path",
                    "tool_trace_path",
                    "candidate_reason",
                ],
                [
                    {
                        "failure_uid": "E00001",
                        "model_family": "model_a",
                        "method_name": "baseline",
                        "input_scope": "scope_a",
                        "repetition": "1",
                        "run_id": "run_1",
                        "failure_object_type": "FP_finding",
                        "related_finding_uid": "F1",
                        "related_case_id": "",
                        "candidate_reason": "FP finding",
                    }
                ],
            )

            rows = init_failure_analysis(candidates, root)

            self.assertEqual(1, len(rows))
            self.assertEqual("E00001", rows[0]["failure_uid"])
            self.assertEqual("FP_finding", rows[0]["failure_object_type"])
            self.assertIn("failure_manifestation", rows[0])
            self.assertIn("failure_mechanism", rows[0])
            self.assertIn("method_implication", rows[0])
            self.assertTrue((root / "run_failure_analysis.csv").exists())

    def test_collect_model_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            model_dir = root / "evaluation_results" / "baseline" / "model_a"
            (model_dir / "single_run").mkdir(parents=True)
            (model_dir / "anyhit3").mkdir()
            (model_dir / "failure_analysis").mkdir()
            _write_csv(
                model_dir / "single_run" / "single_run_model_summary.csv",
                ["model_family", "method_name", "precision_mean"],
                [{"model_family": "model_a", "method_name": "baseline", "precision_mean": "1.000000"}],
            )
            _write_csv(
                model_dir / "anyhit3" / "anyhit3_model_summary.csv",
                ["model_family", "method_name", "precision"],
                [{"model_family": "model_a", "method_name": "baseline", "precision": "1.000000"}],
            )
            _write_csv(
                model_dir / "failure_analysis" / "failure_mechanism_summary.csv",
                ["model_family", "method_name", "failure_mechanism", "failure_count"],
                [
                    {
                        "model_family": "model_a",
                        "method_name": "baseline",
                        "failure_mechanism": "semantic",
                        "failure_count": "2",
                    }
                ],
            )

            outputs = collect_model_summaries(root / "evaluation_results")

            self.assertTrue(outputs["single_run"].exists())
            self.assertTrue(outputs["anyhit3"].exists())
            self.assertTrue(outputs["failure_mechanism"].exists())
            self.assertEqual(1, len(_read_csv(outputs["single_run"])))
            self.assertEqual(1, len(_read_csv(outputs["anyhit3"])))
            self.assertEqual(1, len(_read_csv(outputs["failure_mechanism"])))


def _make_run(
    root: Path,
    *,
    method: str,
    batch: str,
    model: str,
    scope: str,
    rep: int,
    findings: list[dict[str, object]],
) -> Path:
    run_dir = root / "runs" / method / batch / "models" / model / scope / f"rep_{rep}"
    run_dir.mkdir(parents=True)
    (run_dir / "final_answer.json").write_text(
        json.dumps({"analysis_summary": "summary", "findings": findings}, indent=2),
        encoding="utf-8",
    )
    (run_dir / "run_metadata.json").write_text(
        json.dumps(
            {
                "run_id": f"rep_{rep}",
                "method_name": method,
                "model": model,
                "input_scope_path": str(root / "datasets" / "agent_inputs" / scope),
                "structured_output_path": str(run_dir / "final_answer.json"),
            }
        ),
        encoding="utf-8",
    )
    return run_dir


def _write_metric_fixture(root: Path) -> tuple[Path, Path]:
    gt = root / "gt_cases.csv"
    review = root / "finding_review.csv"
    _write_csv(
        gt,
        [
            "case_id",
            "benchmark_id",
            "input_scope",
            "case_description",
            "gt_files",
            "gt_modules",
            "gt_signals_or_registers",
            "gt_evidence_notes",
        ],
        [
            {"case_id": "C1", "benchmark_id": "bench", "input_scope": "scope_a"},
            {"case_id": "C2", "benchmark_id": "bench", "input_scope": "scope_a"},
        ],
    )
    _write_csv(
        review,
        _finding_review_columns(),
        [
            _finding_row(
                finding_uid="R1-F1",
                repetition="1",
                matched_case_id="C1",
                detection_match="TP",
                evidence_quality="Sufficient",
                summary="hits C1",
            ),
            _finding_row(
                finding_uid="R1-F2",
                repetition="1",
                detection_match="FP",
                evidence_quality="Unsupported",
                summary="false positive",
            ),
            _finding_row(
                finding_uid="R2-F1",
                repetition="2",
                matched_case_id="C1",
                detection_match="TP",
                evidence_quality="Insufficient",
                summary="hits C1 weakly",
            ),
            _finding_row(
                finding_uid="R2-F2",
                repetition="2",
                matched_case_id="C2",
                detection_match="TP",
                evidence_quality="Sufficient",
                summary="hits C2",
            ),
        ],
    )
    return gt, review


def _finding_row(**overrides: str) -> dict[str, str]:
    row = {column: "" for column in _finding_review_columns()}
    row.update(
        {
            "model_family": "model_a",
            "method_name": "baseline",
            "input_scope": "scope_a",
            "repetition": "1",
            "run_id": f"scope_a_rep_{overrides.get('repetition', '1')}",
            "final_answer_path": "final_answer.json",
            "finding_id": overrides.get("finding_uid", "F1"),
            "summary": "summary",
            "confidence": "high",
        }
    )
    row.update(overrides)
    return row


def _finding_review_columns() -> list[str]:
    return [
        "finding_uid",
        "model_family",
        "method_name",
        "input_scope",
        "repetition",
        "run_id",
        "final_answer_path",
        "finding_id",
        "model_reported_status",
        "summary",
        "vulnerability_category",
        "affected_locations",
        "claimed_files",
        "claimed_modules",
        "claimed_signals_or_registers",
        "evidence_items",
        "reasoning_summary",
        "security_impact",
        "confidence",
        "uncertainty_or_missing_evidence",
        "matched_case_id",
        "detection_match",
        "duplicate_of_finding_uid",
        "evidence_quality",
        "review_notes",
    ]


def _write_csv(path: Path, columns: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8-sig")


if __name__ == "__main__":
    unittest.main()
