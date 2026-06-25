from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from evaluation.common import read_csv, unique_join, write_csv


FAILURE_MECHANISM_COLUMNS = [
    "model_family",
    "method_name",
    "failure_mechanism",
    "failure_count",
    "affected_input_scopes",
    "representative_failure_uids",
    "method_implication_summary",
]


def summarize_failure_mechanisms(
    run_failure_analysis_path: str | Path,
    output_dir: str | Path | None = None,
) -> list[dict[str, str]]:
    rows = read_csv(run_failure_analysis_path)
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        mechanism = row.get("failure_mechanism", "") or "Unclear"
        grouped[(row.get("model_family", ""), row.get("method_name", ""), mechanism)].append(row)

    output: list[dict[str, str]] = []
    for (model_family, method_name, mechanism), group_rows in sorted(grouped.items()):
        output.append(
            {
                "model_family": model_family,
                "method_name": method_name,
                "failure_mechanism": mechanism,
                "failure_count": str(len(group_rows)),
                "affected_input_scopes": unique_join(row.get("input_scope", "") for row in group_rows),
                "representative_failure_uids": unique_join(row.get("failure_uid", "") for row in group_rows[:10]),
                "method_implication_summary": unique_join(
                    row.get("method_implication", "") for row in group_rows
                ),
            }
        )

    out_dir = Path(output_dir) if output_dir else Path(run_failure_analysis_path).parent
    write_csv(out_dir / "failure_mechanism_summary.csv", FAILURE_MECHANISM_COLUMNS, output)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize reviewed failure mechanisms.")
    parser.add_argument("--run-failure-analysis", required=True)
    parser.add_argument("--output-dir")
    args = parser.parse_args()
    rows = summarize_failure_mechanisms(args.run_failure_analysis, args.output_dir)
    out_dir = Path(args.output_dir) if args.output_dir else Path(args.run_failure_analysis).parent
    print(f"Wrote {len(rows)} mechanism rows to {out_dir / 'failure_mechanism_summary.csv'}")


if __name__ == "__main__":
    main()
