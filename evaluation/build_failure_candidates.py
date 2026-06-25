from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from evaluation.common import read_csv, tool_trace_path, write_csv


FAILURE_CANDIDATE_COLUMNS = [
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
]


def build_failure_candidates(
    gt_cases_path: str | Path,
    finding_review_path: str | Path,
    output_dir: str | Path,
) -> list[dict[str, str]]:
    gt_rows = read_csv(gt_cases_path)
    finding_rows = read_csv(finding_review_path)
    rows: list[dict[str, str]] = []
    counter = 1
    for finding in finding_rows:
        reason = _candidate_reason_for_finding(finding)
        if not reason:
            continue
        rows.append(_candidate_row(counter, finding, reason))
        counter += 1

    rows.extend(_fn_case_candidates(counter, gt_rows, finding_rows))
    out = Path(output_dir)
    write_csv(out / "run_failure_candidates.csv", FAILURE_CANDIDATE_COLUMNS, rows)
    return rows


def _candidate_reason_for_finding(row: dict[str, str]) -> str:
    match = row.get("detection_match", "")
    quality = row.get("evidence_quality", "")
    if match == "FP":
        return "FP finding"
    if match == "Duplicate":
        return "Duplicate finding"
    if match == "Unscorable":
        return "Unscorable finding"
    if match in {"TP", "FP"} and quality in {"Insufficient", "Fabricated", "Unsupported"}:
        return f"{quality} evidence"
    return ""


def _candidate_row(counter: int, row: dict[str, str], reason: str) -> dict[str, str]:
    return {
        "failure_uid": f"E{counter:05d}",
        "model_family": row.get("model_family", ""),
        "method_name": row.get("method_name", ""),
        "input_scope": row.get("input_scope", ""),
        "repetition": row.get("repetition", ""),
        "run_id": row.get("run_id", ""),
        "failure_object_type": _failure_type(row),
        "related_finding_uid": row.get("finding_uid", ""),
        "related_case_id": row.get("matched_case_id", ""),
        "detection_match": row.get("detection_match", ""),
        "evidence_quality": row.get("evidence_quality", ""),
        "summary": row.get("summary", ""),
        "final_answer_path": row.get("final_answer_path", ""),
        "tool_trace_path": tool_trace_path(row.get("final_answer_path", "")),
        "candidate_reason": reason,
    }


def _failure_type(row: dict[str, str]) -> str:
    match = row.get("detection_match", "")
    quality = row.get("evidence_quality", "")
    if match == "FP":
        return "FP_finding"
    if match == "Duplicate":
        return "Duplicate"
    if match == "Unscorable":
        return "Unscorable"
    if quality in {"Insufficient", "Fabricated", "Unsupported"}:
        return "Evidence_failure"
    return "Unclear"


def _fn_case_candidates(
    start_counter: int,
    gt_rows: list[dict[str, str]],
    finding_rows: list[dict[str, str]],
) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    counter = start_counter
    grouped: dict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in finding_rows:
        grouped[
            (
                row.get("model_family", ""),
                row.get("method_name", ""),
                row.get("input_scope", ""),
                row.get("repetition", ""),
            )
        ].append(row)

    for (model_family, method_name, input_scope, repetition), rows in sorted(grouped.items()):
        hit_cases = {
            row.get("matched_case_id", "")
            for row in rows
            if row.get("detection_match") == "TP" and row.get("matched_case_id", "")
        }
        expected_cases = [row for row in gt_rows if row.get("input_scope", "") == input_scope]
        run_id = rows[0].get("run_id", "") if rows else ""
        final_answer_path = rows[0].get("final_answer_path", "") if rows else ""
        for gt in expected_cases:
            case_id = gt.get("case_id", "")
            if case_id in hit_cases:
                continue
            output.append(
                {
                    "failure_uid": f"E{counter:05d}",
                    "model_family": model_family,
                    "method_name": method_name,
                    "input_scope": input_scope,
                    "repetition": repetition,
                    "run_id": run_id,
                    "failure_object_type": "FN_case",
                    "related_finding_uid": "",
                    "related_case_id": case_id,
                    "detection_match": "",
                    "evidence_quality": "",
                    "summary": gt.get("case_description", ""),
                    "final_answer_path": final_answer_path,
                    "tool_trace_path": tool_trace_path(final_answer_path),
                    "candidate_reason": "GT case not hit by any TP finding in this run",
                }
            )
            counter += 1
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Build run-level failure candidate table.")
    parser.add_argument("--gt-cases", required=True)
    parser.add_argument("--finding-review", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    rows = build_failure_candidates(args.gt_cases, args.finding_review, args.output_dir)
    print(f"Wrote {len(rows)} failure candidates to {Path(args.output_dir) / 'run_failure_candidates.csv'}")


if __name__ == "__main__":
    main()
