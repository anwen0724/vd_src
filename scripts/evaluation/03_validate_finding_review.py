from __future__ import annotations

"""
PyCharm run script: validate a manually scored finding_review.csv.

Input:
    GT_CASES
        evaluation_results/gt_cases.csv

    FINDING_REVIEW
        evaluation_results/<method>/<model>/finding_review.csv

Output:
    Console validation report.
    If validation fails, this script raises SystemExit(1).

Modify the path constants below, then right-click this file in PyCharm and run.
"""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.validate_finding_review import validate_finding_review


METHOD_NAME = "baseline"
MODEL_FAMILY = "deepseek_v4_pro"

GT_CASES = PROJECT_ROOT / "evaluation_results" / "gt_cases.csv"
FINDING_REVIEW = PROJECT_ROOT / "evaluation_results" / METHOD_NAME / MODEL_FAMILY / "finding_review.csv"


def main() -> None:
    errors = validate_finding_review(GT_CASES, FINDING_REVIEW)
    print(f"[validate_finding_review] gt_cases={GT_CASES}")
    print(f"[validate_finding_review] finding_review={FINDING_REVIEW}")
    if errors:
        print("[validate_finding_review] FAILED")
        for error in errors:
            print(error)
        raise SystemExit(1)
    print("[validate_finding_review] passed")


if __name__ == "__main__":
    main()
