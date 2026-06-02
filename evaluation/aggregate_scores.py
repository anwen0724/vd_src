"""Aggregate manually reviewed scoring tables into run-level metrics."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from typing import Any


RUN_SUMMARY_COLUMNS = [
    "run_id",
    "input_scope",
    "agent_mode",
    "model_family",
    "model_version",
    "run_index",
    "num_expected_cases",
    "num_findings",
    "tp_cases",
    "partial_cases",
    "fn_cases",
    "tp_findings",
    "partial_findings",
    "fp_findings",
    "precision",
    "recall",
    "partial_rate",
    "fp_rate",
    "fn_rate",
    "wrong_localization_count",
    "localization_error_rate",
    "evidence_failure_count",
    "evidence_failure_rate",
    "insufficient_evidence_count",
    "fabricated_evidence_count",
    "unsupported_claim_count",
    "overconfidence_count",
    "overconfidence_rate",
    "notes",
]


def aggregate_scores(scoring_dir: str | Path, output_path: str | Path | None = None) -> Path:
    """Aggregate reviewed scoring tables and write run_summary.csv."""

    root = Path(scoring_dir).resolve()
    metadata_rows = _read_csv(root / "run_metadata.csv")
    case_rows = _read_csv(root / "case_level_scores.csv")
    finding_rows = _read_csv(root / "finding_level_scores.csv")

    metadata_by_run = {row.get("run_id", ""): row for row in metadata_rows}
    cases_by_run = _group_by(case_rows, "run_id")
    findings_by_run = _group_by(finding_rows, "run_id")

    run_ids = sorted(set(metadata_by_run) | set(cases_by_run) | set(findings_by_run))
    summary_rows = [
        _summarize_run(
            run_id=run_id,
            metadata=metadata_by_run.get(run_id, {}),
            case_rows=cases_by_run.get(run_id, []),
            finding_rows=findings_by_run.get(run_id, []),
        )
        for run_id in run_ids
    ]

    out = Path(output_path).resolve() if output_path else root / "run_summary.csv"
    _write_csv(out, RUN_SUMMARY_COLUMNS, summary_rows)
    return out


def _summarize_run(
    run_id: str,
    metadata: dict[str, str],
    case_rows: list[dict[str, str]],
    finding_rows: list[dict[str, str]],
) -> dict[str, Any]:
    visible_cases = [
        row
        for row in case_rows
        if _normalize(row.get("case_visibility", "visible")) == "visible"
    ]
    tp_cases = _count_value(visible_cases, "case_result", "TP")
    partial_cases = _count_value(visible_cases, "case_result", "Partial")
    fn_cases = _count_value(visible_cases, "case_result", "FN")
    num_expected_cases = tp_cases + partial_cases + fn_cases

    scored_findings = [
        row
        for row in finding_rows
        if _normalize(row.get("detection_match", "")) in {"tp", "partial", "fp"}
    ]
    tp_findings = _count_value(scored_findings, "detection_match", "TP")
    partial_findings = _count_value(scored_findings, "detection_match", "Partial")
    fp_findings = _count_value(scored_findings, "detection_match", "FP")
    scored_finding_count = tp_findings + partial_findings + fp_findings

    wrong_localization_count = _count_yes(scored_findings, "wrong_localization")
    insufficient_evidence_count = _count_evidence_failure(scored_findings, "Insufficient")
    fabricated_evidence_count = _count_evidence_failure(scored_findings, "Fabricated")
    unsupported_claim_count = _count_evidence_failure(scored_findings, "Unsupported")
    evidence_failure_count = len(
        [
            row
            for row in scored_findings
            if _is_evidence_failure(row)
        ]
    )
    overconfidence_count = _count_yes(scored_findings, "overconfidence")

    precision_denominator = tp_findings + fp_findings
    return {
        "run_id": run_id,
        "input_scope": metadata.get("input_scope", _first_value(case_rows, finding_rows, "input_scope")),
        "agent_mode": metadata.get("agent_mode", ""),
        "model_family": metadata.get("model_family", ""),
        "model_version": metadata.get("model_version", ""),
        "run_index": metadata.get("run_index", ""),
        "num_expected_cases": num_expected_cases,
        "num_findings": len(finding_rows),
        "tp_cases": tp_cases,
        "partial_cases": partial_cases,
        "fn_cases": fn_cases,
        "tp_findings": tp_findings,
        "partial_findings": partial_findings,
        "fp_findings": fp_findings,
        "precision": _ratio(tp_findings, precision_denominator),
        "recall": _ratio(tp_cases, num_expected_cases),
        "partial_rate": _ratio(partial_cases, num_expected_cases),
        "fp_rate": _ratio(fp_findings, scored_finding_count),
        "fn_rate": _ratio(fn_cases, num_expected_cases),
        "wrong_localization_count": wrong_localization_count,
        "localization_error_rate": _ratio(wrong_localization_count, scored_finding_count),
        "evidence_failure_count": evidence_failure_count,
        "evidence_failure_rate": _ratio(evidence_failure_count, scored_finding_count),
        "insufficient_evidence_count": insufficient_evidence_count,
        "fabricated_evidence_count": fabricated_evidence_count,
        "unsupported_claim_count": unsupported_claim_count,
        "overconfidence_count": overconfidence_count,
        "overconfidence_rate": _ratio(overconfidence_count, scored_finding_count),
        "notes": "",
    }


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Missing scoring table: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _group_by(rows: list[dict[str, str]], key: str) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row.get(key, "")].append(row)
    return dict(grouped)


def _count_value(rows: list[dict[str, str]], key: str, value: str) -> int:
    target = _normalize(value)
    return sum(1 for row in rows if _normalize(row.get(key, "")) == target)


def _count_yes(rows: list[dict[str, str]], key: str) -> int:
    return sum(1 for row in rows if _normalize(row.get(key, "")) == "yes")


def _count_evidence_failure(rows: list[dict[str, str]], evidence_value: str) -> int:
    target = _normalize(evidence_value)
    key_map = {
        "insufficient": "insufficient_evidence",
        "fabricated": "fabricated_evidence",
        "unsupported": "unsupported_claim",
    }
    flag_key = key_map[target]
    return sum(
        1
        for row in rows
        if _normalize(row.get("evidence_quality", "")) == target
        or _normalize(row.get(flag_key, "")) == "yes"
    )


def _is_evidence_failure(row: dict[str, str]) -> bool:
    quality = _normalize(row.get("evidence_quality", ""))
    return (
        quality in {"insufficient", "fabricated", "unsupported"}
        or _normalize(row.get("insufficient_evidence", "")) == "yes"
        or _normalize(row.get("fabricated_evidence", "")) == "yes"
        or _normalize(row.get("unsupported_claim", "")) == "yes"
    )


def _ratio(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return ""
    return f"{numerator / denominator:.6f}"


def _first_value(
    case_rows: list[dict[str, str]],
    finding_rows: list[dict[str, str]],
    key: str,
) -> str:
    for row in [*case_rows, *finding_rows]:
        value = row.get(key, "")
        if value:
            return value
    return ""


def _normalize(value: str) -> str:
    return str(value).strip().lower()


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate reviewed scoring tables.")
    parser.add_argument("--scoring-dir", required=True, help="Directory containing scoring CSVs.")
    parser.add_argument("--output-path", help="Optional output path for run_summary.csv.")
    args = parser.parse_args()

    aggregate_scores(args.scoring_dir, args.output_path)


if __name__ == "__main__":
    main()
