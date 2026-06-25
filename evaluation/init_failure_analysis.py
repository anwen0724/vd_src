from __future__ import annotations

import argparse
from pathlib import Path

from evaluation.common import read_csv, write_csv


FAILURE_ANALYSIS_COLUMNS = [
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
    "failure_manifestation",
    "failure_mechanism",
    "evidence_from_output",
    "tool_trace_observation",
    "likely_cause",
    "method_implication",
    "review_notes",
]


def init_failure_analysis(
    run_failure_candidates_path: str | Path,
    output_dir: str | Path | None = None,
    overwrite: bool = False,
) -> list[dict[str, str]]:
    candidates_path = Path(run_failure_candidates_path)
    out_dir = Path(output_dir) if output_dir else candidates_path.parent
    output_path = out_dir / "run_failure_analysis.csv"
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"{output_path} already exists; pass overwrite=True to replace it")

    rows: list[dict[str, str]] = []
    for candidate in read_csv(candidates_path):
        row = {column: "" for column in FAILURE_ANALYSIS_COLUMNS}
        for column in FAILURE_ANALYSIS_COLUMNS:
            if column in candidate:
                row[column] = candidate.get(column, "")
        rows.append(row)

    write_csv(output_path, FAILURE_ANALYSIS_COLUMNS, rows)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize run_failure_analysis.csv from candidates.")
    parser.add_argument("--run-failure-candidates", required=True)
    parser.add_argument("--output-dir")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    rows = init_failure_analysis(
        args.run_failure_candidates,
        args.output_dir,
        overwrite=args.overwrite,
    )
    out_dir = Path(args.output_dir) if args.output_dir else Path(args.run_failure_candidates).parent
    print(f"Wrote {len(rows)} failure analysis rows to {out_dir / 'run_failure_analysis.csv'}")


if __name__ == "__main__":
    main()
