from __future__ import annotations

"""
PyCharm run script: build the unified GT case table.

Input:
    DATASETS_BENCHMARKS_DIR
        src/datasets/benchmarks, containing hackatdac18/19/21 benchmark assets.

Output:
    OUTPUT_GT_CASES
        evaluation_results/gt_cases.csv

Modify the path constants below, then right-click this file in PyCharm and run.
"""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.build_gt_cases import build_gt_cases


DATASETS_BENCHMARKS_DIR = PROJECT_ROOT / "datasets" / "benchmarks"
OUTPUT_GT_CASES = PROJECT_ROOT / "evaluation_results" / "gt_cases.csv"


def main() -> None:
    rows = build_gt_cases(DATASETS_BENCHMARKS_DIR, OUTPUT_GT_CASES)
    print(f"[build_gt_cases] input={DATASETS_BENCHMARKS_DIR}")
    print(f"[build_gt_cases] output={OUTPUT_GT_CASES}")
    print(f"[build_gt_cases] rows={len(rows)}")


if __name__ == "__main__":
    main()
