from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from evaluation.common import (
    read_csv,
    ratio,
    f1_score,
    mean,
    sample_std,
    write_csv,
)


SINGLE_RUN_COLUMNS = [
    "model_family",
    "method_name",
    "repetition",
    "num_gt_cases",
    "tp_cases",
    "fn_cases",
    "tp_findings",
    "fp_findings",
    "precision",
    "recall",
    "f1_score",
    "evidence_sufficiency_rate",
    "fabricated_unsupported_evidence_rate",
]

SINGLE_RUN_SUMMARY_COLUMNS = [
    "model_family",
    "method_name",
    "precision_mean",
    "recall_mean",
    "f1_score_mean",
    "evidence_sufficiency_rate_mean",
    "fabricated_unsupported_evidence_rate_mean",
    "precision_std",
    "recall_std",
    "f1_score_std",
    "evidence_sufficiency_rate_std",
    "fabricated_unsupported_evidence_rate_std",
]


def compute_single_run_metrics(
    gt_cases_path: str | Path,
    finding_review_path: str | Path,
    output_dir: str | Path,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    gt_rows = read_csv(gt_cases_path)
    finding_rows = read_csv(finding_review_path)
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in finding_rows:
        grouped[(row.get("model_family", ""), row.get("method_name", ""), row.get("repetition", ""))].append(row)

    run_metrics: list[dict[str, str]] = []
    for (model_family, method_name, repetition), rows in sorted(grouped.items()):
        scopes = {row.get("input_scope", "") for row in rows if row.get("input_scope", "")}
        gt_for_run = [row for row in gt_rows if row.get("input_scope", "") in scopes] if scopes else gt_rows
        run_metrics.append(_compute_metric_row(model_family, method_name, repetition, gt_for_run, rows))

    summary_rows = _summarize_run_metrics(run_metrics)
    out = Path(output_dir)
    write_csv(out / "single_run_metrics.csv", SINGLE_RUN_COLUMNS, run_metrics)
    write_csv(out / "single_run_model_summary.csv", SINGLE_RUN_SUMMARY_COLUMNS, summary_rows)
    return run_metrics, summary_rows


def _compute_metric_row(
    model_family: str,
    method_name: str,
    repetition: str,
    gt_rows: list[dict[str, str]],
    finding_rows: list[dict[str, str]],
) -> dict[str, str]:
    tp_rows = [row for row in finding_rows if row.get("detection_match") == "TP"]
    fp_rows = [row for row in finding_rows if row.get("detection_match") == "FP"]
    hit_cases = {row.get("matched_case_id", "") for row in tp_rows if row.get("matched_case_id", "")}
    gt_case_ids = {row.get("case_id", "") for row in gt_rows if row.get("case_id", "")}
    tp_cases = len(hit_cases & gt_case_ids)
    fn_cases = len(gt_case_ids - hit_cases)
    tp_findings = len(tp_rows)
    fp_findings = len(fp_rows)
    scored_findings = tp_findings + fp_findings
    sufficient_tp = len([row for row in tp_rows if row.get("evidence_quality") == "Sufficient"])
    fabricated_unsupported = len(
        [
            row
            for row in tp_rows + fp_rows
            if row.get("evidence_quality") in {"Fabricated", "Unsupported"}
        ]
    )
    precision = ratio(tp_findings, tp_findings + fp_findings)
    recall = ratio(tp_cases, tp_cases + fn_cases)
    return {
        "model_family": model_family,
        "method_name": method_name,
        "repetition": repetition,
        "num_gt_cases": str(len(gt_case_ids)),
        "tp_cases": str(tp_cases),
        "fn_cases": str(fn_cases),
        "tp_findings": str(tp_findings),
        "fp_findings": str(fp_findings),
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score(precision, recall),
        "evidence_sufficiency_rate": ratio(sufficient_tp, tp_findings),
        "fabricated_unsupported_evidence_rate": ratio(fabricated_unsupported, scored_findings),
    }


def _summarize_run_metrics(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[(row["model_family"], row["method_name"])].append(row)
    output: list[dict[str, str]] = []
    metric_names = [
        "precision",
        "recall",
        "f1_score",
        "evidence_sufficiency_rate",
        "fabricated_unsupported_evidence_rate",
    ]
    for (model_family, method_name), group_rows in sorted(grouped.items()):
        row = {"model_family": model_family, "method_name": method_name}
        for metric in metric_names:
            values = [item.get(metric, "") for item in group_rows]
            row[f"{metric}_mean"] = mean(values)
        for metric in metric_names:
            values = [item.get(metric, "") for item in group_rows]
            row[f"{metric}_std"] = sample_std(values)
        output.append(row)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Compute single-run mean metrics.")
    parser.add_argument("--gt-cases", required=True)
    parser.add_argument("--finding-review", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    run_rows, summary_rows = compute_single_run_metrics(args.gt_cases, args.finding_review, args.output_dir)
    print(f"Wrote {len(run_rows)} repetition rows and {len(summary_rows)} summary rows to {args.output_dir}")


if __name__ == "__main__":
    main()
