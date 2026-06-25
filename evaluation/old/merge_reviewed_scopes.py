"""Merge scope-local reviewed scoring directories into an all-scope result."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from evaluation.old.aggregate_scores import aggregate_scores
from evaluation.old.build_score_tables import (
    CASE_LEVEL_COLUMNS,
    FAILURE_ANALYSIS_COLUMNS,
    FINDING_LEVEL_COLUMNS,
    RUN_METADATA_COLUMNS,
)


REQUIRED_TABLES = [
    "run_metadata.csv",
    "finding_level_scores.csv",
    "case_level_scores.csv",
    "failure_analysis.csv",
]

SUMMARY_METRIC_COLUMNS = [
    "num_runs",
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
]

GLOBAL_SUMMARY_COLUMNS = SUMMARY_METRIC_COLUMNS

MODEL_SUMMARY_COLUMNS = [
    "model_family",
] + SUMMARY_METRIC_COLUMNS

MODEL_BENCHMARK_SUMMARY_COLUMNS = [
    "model_family",
    "benchmark_id",
] + SUMMARY_METRIC_COLUMNS

MODEL_SCOPE_SUMMARY_COLUMNS = [
    "model_family",
    "benchmark_id",
    "input_scope",
] + SUMMARY_METRIC_COLUMNS

ANYHIT_METRIC_COLUMNS = [
    "num_cases",
    "tp_cases",
    "partial_cases",
    "fn_cases",
    "recall",
    "partial_rate",
    "fn_rate",
]

MODEL_ANYHIT_SUMMARY_COLUMNS = [
    "model_family",
] + ANYHIT_METRIC_COLUMNS

MODEL_BENCHMARK_ANYHIT_SUMMARY_COLUMNS = [
    "model_family",
    "benchmark_id",
] + ANYHIT_METRIC_COLUMNS

MODEL_SCOPE_ANYHIT_SUMMARY_COLUMNS = [
    "model_family",
    "benchmark_id",
    "input_scope",
] + ANYHIT_METRIC_COLUMNS


def merge_reviewed_scopes(
    batch_results_dir: str | Path,
    output_dir: str | Path | None = None,
    strict: bool = True,
) -> Path:
    """Merge all scoring_reviewed_scope_* directories under a batch result dir."""

    batch_dir = Path(batch_results_dir).resolve()
    out = Path(output_dir).resolve() if output_dir else batch_dir / "scoring_reviewed_all"
    scope_dirs = _find_scope_dirs(batch_dir, out)
    if not scope_dirs:
        raise ValueError(f"No scoring_reviewed_scope_* directories found under {batch_dir}")

    merged = {
        "run_metadata.csv": _merge_table(scope_dirs, "run_metadata.csv", RUN_METADATA_COLUMNS, strict),
        "finding_level_scores.csv": _merge_table(
            scope_dirs, "finding_level_scores.csv", FINDING_LEVEL_COLUMNS, strict
        ),
        "case_level_scores.csv": _merge_table(scope_dirs, "case_level_scores.csv", CASE_LEVEL_COLUMNS, strict),
        "failure_analysis.csv": _merge_table(
            scope_dirs, "failure_analysis.csv", FAILURE_ANALYSIS_COLUMNS, strict
        ),
    }

    out.mkdir(parents=True, exist_ok=True)
    _write_csv(out / "run_metadata.csv", RUN_METADATA_COLUMNS, merged["run_metadata.csv"])
    _write_csv(out / "finding_level_scores.csv", FINDING_LEVEL_COLUMNS, merged["finding_level_scores.csv"])
    _write_csv(out / "case_level_scores.csv", CASE_LEVEL_COLUMNS, merged["case_level_scores.csv"])
    _write_csv(out / "failure_analysis.csv", FAILURE_ANALYSIS_COLUMNS, merged["failure_analysis.csv"])

    aggregate_scores(out)
    _write_model_centered_summaries(
        out=out,
        run_metadata_rows=merged["run_metadata.csv"],
        case_rows=merged["case_level_scores.csv"],
        finding_rows=merged["finding_level_scores.csv"],
    )
    _write_scope_summary_index(out, scope_dirs)
    return out


def _find_scope_dirs(batch_dir: Path, output_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in batch_dir.glob("scoring_reviewed_scope_*")
        if path.is_dir() and path.resolve() != output_dir.resolve()
    )


def _merge_table(
    scope_dirs: list[Path],
    table_name: str,
    expected_columns: list[str],
    strict: bool,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen_scope_rows: set[tuple[str, str, str]] = set()
    for scope_dir in scope_dirs:
        path = scope_dir / table_name
        if not path.exists():
            raise FileNotFoundError(f"Missing {table_name}: {path}")
        fieldnames, table_rows = _read_csv(path)
        if strict and fieldnames != expected_columns:
            raise ValueError(
                f"Unexpected columns in {path}: {fieldnames}; expected {expected_columns}"
            )
        _validate_single_scope_table(scope_dir, table_name, table_rows, strict)
        for row in table_rows:
            _validate_reviewed_row(scope_dir, table_name, row, strict)
            if table_name != "failure_analysis.csv":
                row_key = (
                    table_name,
                    row.get("run_id", ""),
                    row.get("finding_id") or row.get("case_id") or row.get("input_scope", ""),
                )
                if strict and row_key in seen_scope_rows:
                    raise ValueError(f"Duplicate merged row key {row_key} from {path}")
                seen_scope_rows.add(row_key)
            rows.append({column: row.get(column, "") for column in expected_columns})
    return rows


def _validate_single_scope_table(
    scope_dir: Path,
    table_name: str,
    rows: list[dict[str, str]],
    strict: bool,
) -> None:
    if not strict:
        return
    scopes = {row.get("input_scope", "").strip() for row in rows if row.get("input_scope", "").strip()}
    if not scopes:
        raise ValueError(f"No input_scope values found in {scope_dir / table_name}")
    if len(scopes) > 1:
        raise ValueError(f"Multiple input_scope values found in {scope_dir / table_name}: {sorted(scopes)}")


def _validate_reviewed_row(
    scope_dir: Path,
    table_name: str,
    row: dict[str, str],
    strict: bool,
) -> None:
    if not strict:
        return
    scope = row.get("input_scope", "")
    if not scope:
        raise ValueError(f"Missing input_scope in {scope_dir / table_name}: {row}")
    if table_name == "finding_level_scores.csv":
        match = _normalize(row.get("detection_match", ""))
        matched_case = row.get("matched_case_id", "").strip()
        if match == "fp" and matched_case:
            raise ValueError(
                f"FP finding should not keep matched_case_id in {scope_dir / table_name}: {row}"
            )


def _write_model_centered_summaries(
    out: Path,
    run_metadata_rows: list[dict[str, str]],
    case_rows: list[dict[str, str]],
    finding_rows: list[dict[str, str]],
) -> None:
    run_meta = {row.get("run_id", ""): row for row in run_metadata_rows}
    benchmark_by_run = _benchmark_by_run(case_rows)

    for row in finding_rows:
        run_id = row.get("run_id", "")
        meta = run_meta.get(run_id, {})
        row["_model_family"] = meta.get("model_family", "")
        row["_benchmark_id"] = benchmark_by_run.get(run_id, "")
    for row in case_rows:
        meta = run_meta.get(row.get("run_id", ""), {})
        row["_model_family"] = meta.get("model_family", "")

    global_rows = _select_columns(
        _summarize_groups(
            run_metadata_rows,
            case_rows,
            finding_rows,
            lambda row: ("", "", ""),
        ),
        GLOBAL_SUMMARY_COLUMNS,
    )
    model_rows = _select_columns(
        _summarize_groups(
            run_metadata_rows,
            case_rows,
            finding_rows,
            lambda row: (_model_of(row, run_meta), "", ""),
        ),
        MODEL_SUMMARY_COLUMNS,
    )
    model_benchmark_rows = _select_columns(
        _summarize_groups(
            run_metadata_rows,
            case_rows,
            finding_rows,
            lambda row: (_model_of(row, run_meta), _benchmark_of(row, benchmark_by_run), ""),
        ),
        MODEL_BENCHMARK_SUMMARY_COLUMNS,
    )
    model_scope_rows = _select_columns(
        _summarize_groups(
            run_metadata_rows,
            case_rows,
            finding_rows,
            lambda row: (
                _model_of(row, run_meta),
                _benchmark_of(row, benchmark_by_run),
                row.get("input_scope", ""),
            ),
        ),
        MODEL_SCOPE_SUMMARY_COLUMNS,
    )

    stale_overall = out / "overall_summary.csv"
    if stale_overall.exists():
        stale_overall.unlink()

    _write_csv(out / "global_summary.csv", GLOBAL_SUMMARY_COLUMNS, global_rows)
    _write_csv(out / "model_summary.csv", MODEL_SUMMARY_COLUMNS, model_rows)
    _write_csv(out / "model_benchmark_summary.csv", MODEL_BENCHMARK_SUMMARY_COLUMNS, model_benchmark_rows)
    _write_csv(out / "model_scope_summary.csv", MODEL_SCOPE_SUMMARY_COLUMNS, model_scope_rows)
    _write_anyhit_summaries(out, run_metadata_rows, case_rows)


def _write_anyhit_summaries(
    out: Path,
    run_metadata_rows: list[dict[str, str]],
    case_rows: list[dict[str, str]],
) -> None:
    run_meta = {row.get("run_id", ""): row for row in run_metadata_rows}
    anyhit_cases = _build_anyhit_cases(case_rows, run_meta)

    model_rows = _select_columns(
        _summarize_anyhit_groups(anyhit_cases, lambda row: (row.get("model_family", ""), "", "")),
        MODEL_ANYHIT_SUMMARY_COLUMNS,
    )
    model_benchmark_rows = _select_columns(
        _summarize_anyhit_groups(
            anyhit_cases,
            lambda row: (row.get("model_family", ""), row.get("benchmark_id", ""), ""),
        ),
        MODEL_BENCHMARK_ANYHIT_SUMMARY_COLUMNS,
    )
    model_scope_rows = _select_columns(
        _summarize_anyhit_groups(
            anyhit_cases,
            lambda row: (
                row.get("model_family", ""),
                row.get("benchmark_id", ""),
                row.get("input_scope", ""),
            ),
        ),
        MODEL_SCOPE_ANYHIT_SUMMARY_COLUMNS,
    )

    _write_csv(out / "model_anyhit_summary.csv", MODEL_ANYHIT_SUMMARY_COLUMNS, model_rows)
    _write_csv(
        out / "model_benchmark_anyhit_summary.csv",
        MODEL_BENCHMARK_ANYHIT_SUMMARY_COLUMNS,
        model_benchmark_rows,
    )
    _write_csv(out / "model_scope_anyhit_summary.csv", MODEL_SCOPE_ANYHIT_SUMMARY_COLUMNS, model_scope_rows)


def _build_anyhit_cases(
    case_rows: list[dict[str, str]],
    run_meta: dict[str, dict[str, str]],
) -> list[dict[str, str]]:
    grouped: dict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in case_rows:
        if _normalize(row.get("case_visibility", "visible")) != "visible":
            continue
        model_family = _model_of(row, run_meta)
        benchmark_id = row.get("benchmark_id", "")
        input_scope = row.get("input_scope", "")
        case_id = row.get("case_id", "")
        if not model_family or not input_scope or not case_id:
            continue
        grouped[(model_family, benchmark_id, input_scope, case_id)].append(row)

    anyhit_cases: list[dict[str, str]] = []
    for (model_family, benchmark_id, input_scope, case_id), rows in sorted(grouped.items()):
        case_result = _anyhit_case_result(rows)
        if not case_result:
            continue
        anyhit_cases.append(
            {
                "model_family": model_family,
                "benchmark_id": benchmark_id,
                "input_scope": input_scope,
                "case_id": case_id,
                "case_result": case_result,
            }
        )
    return anyhit_cases


def _anyhit_case_result(rows: list[dict[str, str]]) -> str:
    results = {_normalize(row.get("case_result", "")) for row in rows}
    if "tp" in results:
        return "TP"
    if "partial" in results:
        return "Partial"
    if "fn" in results:
        return "FN"
    return ""


def _summarize_anyhit_groups(
    anyhit_cases: list[dict[str, str]],
    key_fn: Callable[[dict[str, str]], tuple[str, str, str]],
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in anyhit_cases:
        groups[key_fn(row)].append(row)

    output: list[dict[str, Any]] = []
    for key in sorted(groups):
        model_family, benchmark_id, input_scope = key
        output.append(
            _summarize_anyhit_group(
                model_family=model_family,
                benchmark_id=benchmark_id,
                input_scope=input_scope,
                case_rows=groups[key],
            )
        )
    return output


def _summarize_anyhit_group(
    model_family: str,
    benchmark_id: str,
    input_scope: str,
    case_rows: list[dict[str, str]],
) -> dict[str, Any]:
    tp_cases = _count_value(case_rows, "case_result", "TP")
    partial_cases = _count_value(case_rows, "case_result", "Partial")
    fn_cases = _count_value(case_rows, "case_result", "FN")
    num_cases = tp_cases + partial_cases + fn_cases
    return {
        "model_family": model_family,
        "benchmark_id": benchmark_id,
        "input_scope": input_scope,
        "num_cases": num_cases,
        "tp_cases": tp_cases,
        "partial_cases": partial_cases,
        "fn_cases": fn_cases,
        "recall": _ratio(tp_cases, num_cases),
        "partial_rate": _ratio(partial_cases, num_cases),
        "fn_rate": _ratio(fn_cases, num_cases),
    }


def _summarize_groups(
    run_metadata_rows: list[dict[str, str]],
    case_rows: list[dict[str, str]],
    finding_rows: list[dict[str, str]],
    key_fn: Callable[[dict[str, str]], tuple[str, str, str]],
) -> list[dict[str, Any]]:
    run_groups: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    case_groups: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    finding_groups: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)

    for row in run_metadata_rows:
        run_groups[key_fn(row)].add(row.get("run_id", ""))
    for row in case_rows:
        case_groups[key_fn(row)].append(row)
        run_groups[key_fn(row)].add(row.get("run_id", ""))
    for row in finding_rows:
        finding_groups[key_fn(row)].append(row)
        run_groups[key_fn(row)].add(row.get("run_id", ""))

    output: list[dict[str, Any]] = []
    for key in sorted(run_groups):
        model_family, benchmark_id, input_scope = key
        output.append(
            _summarize_group(
                model_family=model_family,
                benchmark_id=benchmark_id,
                input_scope=input_scope,
                run_ids=run_groups[key],
                case_rows=case_groups.get(key, []),
                finding_rows=finding_groups.get(key, []),
            )
        )
    return output


def _summarize_group(
    model_family: str,
    benchmark_id: str,
    input_scope: str,
    run_ids: set[str],
    case_rows: list[dict[str, str]],
    finding_rows: list[dict[str, str]],
) -> dict[str, Any]:
    visible_cases = [
        row for row in case_rows if _normalize(row.get("case_visibility", "visible")) == "visible"
    ]
    scored_findings = [
        row
        for row in finding_rows
        if _normalize(row.get("detection_match", "")) in {"tp", "partial", "fp"}
    ]

    tp_cases = _count_value(visible_cases, "case_result", "TP")
    partial_cases = _count_value(visible_cases, "case_result", "Partial")
    fn_cases = _count_value(visible_cases, "case_result", "FN")
    expected_cases = tp_cases + partial_cases + fn_cases

    tp_findings = _count_value(scored_findings, "detection_match", "TP")
    partial_findings = _count_value(scored_findings, "detection_match", "Partial")
    fp_findings = _count_value(scored_findings, "detection_match", "FP")
    scored_finding_count = tp_findings + partial_findings + fp_findings

    wrong_localization_count = _count_yes(scored_findings, "wrong_localization")
    insufficient_evidence_count = _count_evidence_failure(scored_findings, "Insufficient")
    fabricated_evidence_count = _count_evidence_failure(scored_findings, "Fabricated")
    unsupported_claim_count = _count_evidence_failure(scored_findings, "Unsupported")
    evidence_failure_count = len([row for row in scored_findings if _is_evidence_failure(row)])
    overconfidence_count = _count_yes(scored_findings, "overconfidence")

    precision_denominator = tp_findings + fp_findings
    return {
        "model_family": model_family,
        "benchmark_id": benchmark_id,
        "input_scope": input_scope,
        "num_runs": len([run_id for run_id in run_ids if run_id]),
        "num_expected_cases": expected_cases,
        "num_findings": len(finding_rows),
        "tp_cases": tp_cases,
        "partial_cases": partial_cases,
        "fn_cases": fn_cases,
        "tp_findings": tp_findings,
        "partial_findings": partial_findings,
        "fp_findings": fp_findings,
        "precision": _ratio(tp_findings, precision_denominator),
        "recall": _ratio(tp_cases, expected_cases),
        "partial_rate": _ratio(partial_cases, expected_cases),
        "fp_rate": _ratio(fp_findings, scored_finding_count),
        "fn_rate": _ratio(fn_cases, expected_cases),
        "wrong_localization_count": wrong_localization_count,
        "localization_error_rate": _ratio(wrong_localization_count, scored_finding_count),
        "evidence_failure_count": evidence_failure_count,
        "evidence_failure_rate": _ratio(evidence_failure_count, scored_finding_count),
        "insufficient_evidence_count": insufficient_evidence_count,
        "fabricated_evidence_count": fabricated_evidence_count,
        "unsupported_claim_count": unsupported_claim_count,
        "overconfidence_count": overconfidence_count,
        "overconfidence_rate": _ratio(overconfidence_count, scored_finding_count),
    }


def _select_columns(rows: list[dict[str, Any]], columns: list[str]) -> list[dict[str, Any]]:
    return [{column: row.get(column, "") for column in columns} for row in rows]


def _benchmark_by_run(case_rows: list[dict[str, str]]) -> dict[str, str]:
    benchmarks: dict[str, str] = {}
    for row in case_rows:
        run_id = row.get("run_id", "")
        benchmark_id = row.get("benchmark_id", "")
        if run_id and benchmark_id:
            benchmarks.setdefault(run_id, benchmark_id)
    return benchmarks


def _model_of(row: dict[str, str], run_meta: dict[str, dict[str, str]]) -> str:
    return row.get("model_family") or row.get("_model_family") or run_meta.get(row.get("run_id", ""), {}).get(
        "model_family", ""
    )


def _benchmark_of(row: dict[str, str], benchmark_by_run: dict[str, str]) -> str:
    return row.get("benchmark_id") or row.get("_benchmark_id") or benchmark_by_run.get(row.get("run_id", ""), "")


def _write_scope_summary_index(out: Path, scope_dirs: list[Path]) -> None:
    lines = [
        "# Reviewed Scope Summary Index",
        "",
        "This file lists scope-level human-readable evaluation summaries included in this merge.",
        "",
    ]
    for scope_dir in scope_dirs:
        summary = scope_dir / "scope_evaluation_summary.md"
        status = "present" if summary.exists() else "missing"
        lines.append(f"- `{scope_dir.name}`: `{summary.name}` {status}")
    lines.append("")
    (out / "scope_summary_index.md").write_text("\n".join(lines), encoding="utf-8")


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return reader.fieldnames or [], list(reader)


def _write_csv(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


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


def _normalize(value: str) -> str:
    return str(value).strip().lower()


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge scope-local reviewed scoring directories.")
    parser.add_argument(
        "--batch-results-dir",
        required=True,
        help="Directory containing scoring_reviewed_scope_* directories.",
    )
    parser.add_argument(
        "--output-dir",
        help="Output directory. Defaults to <batch-results-dir>/scoring_reviewed_all.",
    )
    parser.add_argument(
        "--no-strict",
        action="store_true",
        help="Disable strict column, scope-local, and FP matched-case validation.",
    )
    args = parser.parse_args()

    out = merge_reviewed_scopes(
        batch_results_dir=args.batch_results_dir,
        output_dir=args.output_dir,
        strict=not args.no_strict,
    )
    print(f"Merged reviewed scopes into {out}")


if __name__ == "__main__":
    main()
