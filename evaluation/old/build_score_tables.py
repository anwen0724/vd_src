"""Build draft scoring tables from baseline/proposed outputs."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any

from evaluation.old.load_outputs import RunOutput, load_batch_outputs, load_single_run_output


RUN_METADATA_COLUMNS = [
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
]

CASE_LEVEL_COLUMNS = [
    "run_id",
    "input_scope",
    "benchmark_id",
    "case_id",
    "case_visibility",
    "case_result",
    "matched_finding_ids",
    "miss_reason",
    "scorer_notes",
]

FINDING_LEVEL_COLUMNS = [
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
]

FAILURE_ANALYSIS_COLUMNS = [
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
]


def build_score_tables(
    runs: list[RunOutput],
    gt_map_paths: list[str | Path],
    output_dir: str | Path,
) -> None:
    """Build draft scoring CSVs for manual review."""

    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    gt_rows = _load_gt_rows(gt_map_paths)

    _write_csv(out / "run_metadata.csv", RUN_METADATA_COLUMNS, _build_run_metadata_rows(runs))
    _write_csv(out / "case_level_scores.csv", CASE_LEVEL_COLUMNS, _build_case_rows(runs, gt_rows))
    _write_csv(out / "finding_level_scores.csv", FINDING_LEVEL_COLUMNS, _build_finding_rows(runs))
    _write_csv(out / "failure_analysis.csv", FAILURE_ANALYSIS_COLUMNS, [])


def _build_run_metadata_rows(runs: list[RunOutput]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in runs:
        metadata = run.metadata
        rows.append(
            {
                "run_id": run.run_id,
                "batch_id": run.batch_id,
                "input_scope": run.input_scope,
                "agent_mode": metadata.get("method_name", ""),
                "model_family": run.model_id,
                "model_version": run.model,
                "provider": run.provider,
                "method_name": metadata.get("method_name", ""),
                "prompt_version": Path(str(metadata.get("prompt_template_path", ""))).stem,
                "temperature": metadata.get("temperature", ""),
                "max_output_tokens": metadata.get("max_tokens", ""),
                "tool_policy": "read_search_only",
                "run_index": run.repetition or "",
                "started_at": metadata.get("started_at", ""),
                "completed_at": metadata.get("completed_at", ""),
                "output_path": str(run.run_dir / "final_answer.json"),
                "trace_path": str(run.trace_path),
                "notes": "",
            }
        )
    return rows


def _build_case_rows(
    runs: list[RunOutput],
    gt_rows: list[dict[str, str]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    gt_by_scope = _group_gt_by_scope(gt_rows)
    for run in runs:
        for gt in gt_by_scope.get(run.input_scope, []):
            rows.append(
                {
                    "run_id": run.run_id,
                    "input_scope": run.input_scope,
                    "benchmark_id": gt.get("benchmark_id", ""),
                    "case_id": gt.get("expected_case_id") or gt.get("case_id", ""),
                    "case_visibility": gt.get("case_visibility", ""),
                    "case_result": "",
                    "matched_finding_ids": "",
                    "miss_reason": "",
                    "scorer_notes": "",
                }
            )
    return rows


def _build_finding_rows(runs: list[RunOutput]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in runs:
        findings = []
        if run.final_answer:
            raw_findings = run.final_answer.get("findings", [])
            findings = raw_findings if isinstance(raw_findings, list) else []

        for index, finding in enumerate(findings, start=1):
            if not isinstance(finding, dict):
                continue
            rows.append(
                {
                    "run_id": run.run_id,
                    "finding_id": str(finding.get("finding_id") or f"F{index}"),
                    "input_scope": run.input_scope,
                    "claimed_summary": finding.get("summary", ""),
                    "claimed_files": _join_unique(_extract_files(finding)),
                    "claimed_modules": _join_unique(_extract_modules(finding)),
                    "claimed_signals": _join_unique(_extract_signals(finding)),
                    "matched_case_id": "",
                    "detection_match": "",
                    "evidence_quality": "",
                    "confidence_label": finding.get("confidence", ""),
                    "wrong_localization": "",
                    "insufficient_evidence": "",
                    "fabricated_evidence": "",
                    "unsupported_claim": "",
                    "overconfidence": "",
                    "scorer_notes": "",
                }
            )
    return rows


def _load_gt_rows(paths: list[str | Path]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for raw_path in paths:
        path = Path(raw_path).resolve()
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            rows.extend(csv.DictReader(handle))
    return rows


def _group_gt_by_scope(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        scope = row.get("input_scope", "")
        if scope:
            grouped.setdefault(scope, []).append(row)
            for alias in _scope_aliases(row):
                grouped.setdefault(alias, []).append(row)
    return grouped


def _scope_aliases(row: dict[str, str]) -> list[str]:
    benchmark = row.get("benchmark_id", "").strip().lower()
    scope = row.get("input_scope", "").strip()
    if benchmark == "hackatdac18" and scope and not scope.startswith("h18_"):
        return [f"h18_{scope}"]
    return []


def _extract_files(finding: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for item in finding.get("affected_locations", []) or []:
        if isinstance(item, dict):
            values.append(str(item.get("file", "")))
    for item in finding.get("evidence", []) or []:
        if isinstance(item, dict):
            values.append(str(item.get("file", "")))
    return values


def _extract_modules(finding: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ["affected_locations", "evidence"]:
        for item in finding.get(key, []) or []:
            if isinstance(item, dict):
                values.append(str(item.get("module", "")))
    return values


def _extract_signals(finding: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for item in finding.get("affected_locations", []) or []:
        if isinstance(item, dict):
            values.append(str(item.get("signal_or_register", "")))
    for item in finding.get("evidence", []) or []:
        if isinstance(item, dict):
            values.append(str(item.get("object", "")))
    return values


def _join_unique(values: list[str]) -> str:
    seen: set[str] = set()
    unique_values: list[str] = []
    for value in values:
        stripped = value.strip()
        if stripped and stripped not in seen:
            seen.add(stripped)
            unique_values.append(stripped)
    return "; ".join(unique_values)


def _write_csv(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build draft scoring tables.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--batch-dir", help="Baseline/proposed batch output directory.")
    source.add_argument("--run-dir", help="Single baseline/proposed run directory.")
    parser.add_argument(
        "--gt-map",
        action="append",
        required=True,
        help="Evaluator-side input_scope_gt_map.csv. Can be repeated.",
    )
    parser.add_argument("--output-dir", required=True, help="Directory for scoring CSVs.")
    args = parser.parse_args()

    runs = load_batch_outputs(args.batch_dir) if args.batch_dir else [load_single_run_output(args.run_dir)]
    build_score_tables(runs, args.gt_map, args.output_dir)


if __name__ == "__main__":
    main()
