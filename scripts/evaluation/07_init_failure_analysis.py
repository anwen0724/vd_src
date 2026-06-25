from __future__ import annotations

"""
PyCharm run script: initialize run_failure_analysis.csv from run_failure_candidates.csv.

Input:
    RUN_FAILURE_CANDIDATES
        evaluation_results/<method>/<model>/failure_analysis/run_failure_candidates.csv

Output:
    OUTPUT_DIR/run_failure_analysis.csv

Manual next step:
    Fill failure_manifestation, failure_mechanism, evidence_from_output,
    tool_trace_observation, likely_cause, method_implication, and review_notes.

Safety:
    OVERWRITE_EXISTING = False by default, so manually filled files are not replaced.

Modify the path constants below, then right-click this file in PyCharm and run.
"""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.init_failure_analysis import init_failure_analysis


METHOD_NAME = "baseline"
MODEL_FAMILY = "deepseek_v4_pro"
OVERWRITE_EXISTING = False

OUTPUT_DIR = PROJECT_ROOT / "evaluation_results" / METHOD_NAME / MODEL_FAMILY / "failure_analysis"
RUN_FAILURE_CANDIDATES = OUTPUT_DIR / "run_failure_candidates.csv"


def main() -> None:
    rows = init_failure_analysis(
        RUN_FAILURE_CANDIDATES,
        OUTPUT_DIR,
        overwrite=OVERWRITE_EXISTING,
    )
    print(f"[init_failure_analysis] input={RUN_FAILURE_CANDIDATES}")
    print(f"[init_failure_analysis] output={OUTPUT_DIR / 'run_failure_analysis.csv'}")
    print(f"[init_failure_analysis] rows={len(rows)}")


if __name__ == "__main__":
    main()
