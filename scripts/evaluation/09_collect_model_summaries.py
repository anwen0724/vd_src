from __future__ import annotations

"""
PyCharm run script: collect model-level summaries across methods and models.

Input:
    EVALUATION_RESULTS_DIR
        evaluation_results, containing per-method/per-model result folders.

Output:
    evaluation_results/summary/single_run_all_models.csv
    evaluation_results/summary/anyhit3_all_models.csv
    evaluation_results/summary/failure_mechanism_all_models.csv

Modify the path constants below, then right-click this file in PyCharm and run.
"""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.collect_model_summaries import collect_model_summaries


EVALUATION_RESULTS_DIR = PROJECT_ROOT / "evaluation_results"


def main() -> None:
    outputs = collect_model_summaries(EVALUATION_RESULTS_DIR)
    print(f"[collect_summaries] input={EVALUATION_RESULTS_DIR}")
    for name, path in outputs.items():
        print(f"[collect_summaries] {name}={path}")


if __name__ == "__main__":
    main()
