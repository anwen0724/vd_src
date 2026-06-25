from __future__ import annotations

import argparse
from pathlib import Path

from evaluation.common import read_csv, write_csv


def collect_model_summaries(evaluation_results_dir: str | Path) -> dict[str, Path]:
    root = Path(evaluation_results_dir)
    summary_dir = root / "summary"
    summary_dir.mkdir(parents=True, exist_ok=True)

    single_run_rows = _collect(root, "single_run/single_run_model_summary.csv")
    anyhit3_rows = _collect(root, "anyhit3/anyhit3_model_summary.csv")
    failure_rows = _collect(root, "failure_analysis/failure_mechanism_summary.csv")

    outputs = {
        "single_run": summary_dir / "single_run_all_models.csv",
        "anyhit3": summary_dir / "anyhit3_all_models.csv",
        "failure_mechanism": summary_dir / "failure_mechanism_all_models.csv",
    }
    _write_dynamic(outputs["single_run"], single_run_rows)
    _write_dynamic(outputs["anyhit3"], anyhit3_rows)
    _write_dynamic(outputs["failure_mechanism"], failure_rows)
    return outputs


def _collect(root: Path, suffix: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in sorted(root.glob(f"*/*/{suffix}")):
        rows.extend(read_csv(path))
    return rows


def _write_dynamic(path: Path, rows: list[dict[str, str]]) -> None:
    columns: list[str] = []
    for row in rows:
        for column in row:
            if column not in columns:
                columns.append(column)
    write_csv(path, columns, rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect model-level evaluation summaries.")
    parser.add_argument("--evaluation-results-dir", default="evaluation_results")
    args = parser.parse_args()
    outputs = collect_model_summaries(args.evaluation_results_dir)
    for name, path in outputs.items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()
