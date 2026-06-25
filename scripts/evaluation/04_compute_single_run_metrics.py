from __future__ import annotations

"""
PyCharm run script: compute single-run mean metrics.

Input:
    GT_CASES
        evaluation_results/gt_cases.csv

    FINDING_REVIEW
        evaluation_results/<method>/<model>/finding_review.csv

Output:
    OUTPUT_DIR/single_run_metrics.csv
    OUTPUT_DIR/single_run_model_summary.csv

Modify the path constants below, then right-click this file in PyCharm and run.
"""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.compute_single_run_metrics import compute_single_run_metrics


METHOD_NAME = "baseline"
MODEL_FAMILY = "deepseek_v4_pro"

GT_CASES = PROJECT_ROOT / "evaluation_results" / "gt_cases.csv"
FINDING_REVIEW = PROJECT_ROOT / "evaluation_results" / METHOD_NAME / MODEL_FAMILY / "finding_review.csv"
OUTPUT_DIR = PROJECT_ROOT / "evaluation_results" / METHOD_NAME / MODEL_FAMILY / "single_run"


def main() -> None:
    run_rows, summary_rows = compute_single_run_metrics(GT_CASES, FINDING_REVIEW, OUTPUT_DIR)
    print(f"[single_run] gt_cases={GT_CASES}")
    print(f"[single_run] finding_review={FINDING_REVIEW}")
    print(f"[single_run] output_dir={OUTPUT_DIR}")
    print(f"[single_run] repetition_rows={len(run_rows)} summary_rows={len(summary_rows)}")


if __name__ == "__main__":
    main()
