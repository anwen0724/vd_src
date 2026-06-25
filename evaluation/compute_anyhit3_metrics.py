from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from evaluation.common import EVIDENCE_QUALITY_RANK, f1_score, ratio, read_csv, write_csv


ANYHIT_CASE_COLUMNS = [
    "model_family",
    "method_name",
    "input_scope",
    "benchmark_id",
    "case_id",
    "case_result",
    "hit_repetitions",
    "representative_finding_uid",
    "representative_evidence_quality",
    "notes",
]

ANYHIT_SUMMARY_COLUMNS = [
    "model_family",
    "method_name",
    "num_gt_cases",
    "tp_cases",
    "fn_cases",
    "representative_tp_findings",
    "fp_findings",
    "precision",
    "recall",
    "f1_score",
    "evidence_sufficiency_rate",
    "fabricated_unsupported_evidence_rate",
]


def compute_anyhit3_metrics(
    gt_cases_path: str | Path,
    finding_review_path: str | Path,
    output_dir: str | Path,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    gt_rows = read_csv(gt_cases_path)
    finding_rows = read_csv(finding_review_path)
    identities = sorted({(row.get("model_family", ""), row.get("method_name", "")) for row in finding_rows})

    case_rows: list[dict[str, str]] = []
    summary_rows: list[dict[str, str]] = []
    for model_family, method_name in identities:
        model_findings = [
            row
            for row in finding_rows
            if row.get("model_family", "") == model_family and row.get("method_name", "") == method_name
        ]
        scopes = {row.get("input_scope", "") for row in model_findings if row.get("input_scope", "")}
        model_gt = [row for row in gt_rows if row.get("input_scope", "") in scopes] if scopes else gt_rows
        model_case_rows, representative_tp = _build_case_hits(model_family, method_name, model_gt, model_findings)
        case_rows.extend(model_case_rows)
        summary_rows.append(_build_summary(model_family, method_name, model_gt, model_findings, representative_tp))

    out = Path(output_dir)
    write_csv(out / "anyhit3_case_hits.csv", ANYHIT_CASE_COLUMNS, case_rows)
    write_csv(out / "anyhit3_model_summary.csv", ANYHIT_SUMMARY_COLUMNS, summary_rows)
    return case_rows, summary_rows


def _build_case_hits(
    model_family: str,
    method_name: str,
    gt_rows: list[dict[str, str]],
    finding_rows: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    tp_by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in finding_rows:
        if row.get("detection_match") == "TP" and row.get("matched_case_id", ""):
            tp_by_case[row["matched_case_id"]].append(row)

    case_rows: list[dict[str, str]] = []
    representative_tp: list[dict[str, str]] = []
    for gt in sorted(gt_rows, key=lambda row: row.get("case_id", "")):
        case_id = gt.get("case_id", "")
        hits = tp_by_case.get(case_id, [])
        representative = _choose_representative(hits)
        if representative:
            representative_tp.append(representative)
        case_rows.append(
            {
                "model_family": model_family,
                "method_name": method_name,
                "input_scope": gt.get("input_scope", ""),
                "benchmark_id": gt.get("benchmark_id", ""),
                "case_id": case_id,
                "case_result": "TP" if hits else "FN",
                "hit_repetitions": ";".join(sorted({row.get("repetition", "") for row in hits if row.get("repetition", "")})),
                "representative_finding_uid": representative.get("finding_uid", "") if representative else "",
                "representative_evidence_quality": representative.get("evidence_quality", "") if representative else "",
                "notes": "",
            }
        )
    return case_rows, representative_tp


def _choose_representative(rows: list[dict[str, str]]) -> dict[str, str]:
    if not rows:
        return {}
    return sorted(
        rows,
        key=lambda row: (
            EVIDENCE_QUALITY_RANK.get(row.get("evidence_quality", ""), 99),
            row.get("finding_uid", ""),
        ),
    )[0]


def _build_summary(
    model_family: str,
    method_name: str,
    gt_rows: list[dict[str, str]],
    finding_rows: list[dict[str, str]],
    representative_tp: list[dict[str, str]],
) -> dict[str, str]:
    gt_case_ids = {row.get("case_id", "") for row in gt_rows if row.get("case_id", "")}
    tp_cases = len({row.get("matched_case_id", "") for row in representative_tp if row.get("matched_case_id", "")})
    fn_cases = len(gt_case_ids) - tp_cases
    fp_rows = [row for row in finding_rows if row.get("detection_match") == "FP"]
    representative_tp_count = len(representative_tp)
    fp_count = len(fp_rows)
    scored_count = representative_tp_count + fp_count
    sufficient_tp = len([row for row in representative_tp if row.get("evidence_quality") == "Sufficient"])
    fabricated_unsupported = len(
        [
            row
            for row in representative_tp + fp_rows
            if row.get("evidence_quality") in {"Fabricated", "Unsupported"}
        ]
    )
    precision = ratio(representative_tp_count, representative_tp_count + fp_count)
    recall = ratio(tp_cases, tp_cases + fn_cases)
    return {
        "model_family": model_family,
        "method_name": method_name,
        "num_gt_cases": str(len(gt_case_ids)),
        "tp_cases": str(tp_cases),
        "fn_cases": str(fn_cases),
        "representative_tp_findings": str(representative_tp_count),
        "fp_findings": str(fp_count),
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score(precision, recall),
        "evidence_sufficiency_rate": ratio(sufficient_tp, representative_tp_count),
        "fabricated_unsupported_evidence_rate": ratio(fabricated_unsupported, scored_count),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Compute any-hit@3 metrics.")
    parser.add_argument("--gt-cases", required=True)
    parser.add_argument("--finding-review", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    case_rows, summary_rows = compute_anyhit3_metrics(args.gt_cases, args.finding_review, args.output_dir)
    print(f"Wrote {len(case_rows)} case rows and {len(summary_rows)} summary rows to {args.output_dir}")


if __name__ == "__main__":
    main()
