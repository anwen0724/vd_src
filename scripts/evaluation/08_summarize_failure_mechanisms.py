from __future__ import annotations

"""
PyCharm run script: summarize manually reviewed failure mechanisms.

Input:
    RUN_FAILURE_ANALYSIS
        evaluation_results/<method>/<model>/failure_analysis/run_failure_analysis.csv

Output:
    OUTPUT_DIR/failure_mechanism_summary.csv

Modify the path constants below, then right-click this file in PyCharm and run.
"""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.summarize_failure_mechanisms import summarize_failure_mechanisms


METHOD_NAME = "baseline"
MODEL_FAMILY = "deepseek_v4_pro"

OUTPUT_DIR = PROJECT_ROOT / "evaluation_results" / METHOD_NAME / MODEL_FAMILY / "failure_analysis"
RUN_FAILURE_ANALYSIS = OUTPUT_DIR / "run_failure_analysis.csv"


def main() -> None:
    rows = summarize_failure_mechanisms(RUN_FAILURE_ANALYSIS, OUTPUT_DIR)
    print(f"[failure_summary] input={RUN_FAILURE_ANALYSIS}")
    print(f"[failure_summary] output={OUTPUT_DIR / 'failure_mechanism_summary.csv'}")
    print(f"[failure_summary] rows={len(rows)}")


if __name__ == "__main__":
    main()
