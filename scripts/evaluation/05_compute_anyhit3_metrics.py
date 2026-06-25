from __future__ import annotations

"""
PyCharm run script: compute any-hit@3 metrics.

Input:
    GT_CASES
        evaluation_results/gt_cases.csv

    FINDING_REVIEW
        evaluation_results/<method>/<model>/finding_review.csv

Output:
    OUTPUT_DIR/anyhit3_case_hits.csv
    OUTPUT_DIR/anyhit3_model_summary.csv

Modify the path constants below, then right-click this file in PyCharm and run.
"""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.compute_anyhit3_metrics import compute_anyhit3_metrics


METHOD_NAME = "baseline"
MODEL_FAMILY = "deepseek_v4_pro"

GT_CASES = PROJECT_ROOT / "evaluation_results" / "gt_cases.csv"
FINDING_REVIEW = PROJECT_ROOT / "evaluation_results" / METHOD_NAME / MODEL_FAMILY / "finding_review.csv"
OUTPUT_DIR = PROJECT_ROOT / "evaluation_results" / METHOD_NAME / MODEL_FAMILY / "anyhit3"


def main() -> None:
    case_rows, summary_rows = compute_anyhit3_metrics(GT_CASES, FINDING_REVIEW, OUTPUT_DIR)
    print(f"[anyhit3] gt_cases={GT_CASES}")
    print(f"[anyhit3] finding_review={FINDING_REVIEW}")
    print(f"[anyhit3] output_dir={OUTPUT_DIR}")
    print(f"[anyhit3] case_rows={len(case_rows)} summary_rows={len(summary_rows)}")


if __name__ == "__main__":
    main()
