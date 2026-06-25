from __future__ import annotations

"""
PyCharm run script: build run-level failure candidates.

Input:
    GT_CASES
        evaluation_results/gt_cases.csv

    FINDING_REVIEW
        evaluation_results/<method>/<model>/finding_review.csv

Output:
    OUTPUT_DIR/run_failure_candidates.csv

Modify the path constants below, then right-click this file in PyCharm and run.
"""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.build_failure_candidates import build_failure_candidates


METHOD_NAME = "baseline"
MODEL_FAMILY = "deepseek_v4_pro"

GT_CASES = PROJECT_ROOT / "evaluation_results" / "gt_cases.csv"
FINDING_REVIEW = PROJECT_ROOT / "evaluation_results" / METHOD_NAME / MODEL_FAMILY / "finding_review.csv"
OUTPUT_DIR = PROJECT_ROOT / "evaluation_results" / METHOD_NAME / MODEL_FAMILY / "failure_analysis"


def main() -> None:
    rows = build_failure_candidates(GT_CASES, FINDING_REVIEW, OUTPUT_DIR)
    print(f"[failure_candidates] gt_cases={GT_CASES}")
    print(f"[failure_candidates] finding_review={FINDING_REVIEW}")
    print(f"[failure_candidates] output={OUTPUT_DIR / 'run_failure_candidates.csv'}")
    print(f"[failure_candidates] rows={len(rows)}")


if __name__ == "__main__":
    main()
