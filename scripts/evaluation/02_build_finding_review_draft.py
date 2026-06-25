from __future__ import annotations

"""
PyCharm run script: flatten final_answer.json files into a finding review draft.

Input:
    BATCH_DIR
        runs/<method>/<batch_id>, for example:
        src/runs/baseline/baseline_hackatdac_deepseek_gpt_pilot_v1

    MODEL_FAMILY
        Set to one model name, such as "deepseek_v4_pro" or "gpt_5_5".
        Set to None only if you intentionally want all models in the batch.

Output:
    OUTPUT_FINDING_REVIEW_DRAFT
        evaluation_results/<method>/<model>/finding_review_draft.csv

Manual next step:
    Copy or save this draft as finding_review.csv after manual scoring.

Modify the path constants below, then right-click this file in PyCharm and run.
"""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.build_finding_review import build_finding_review


METHOD_NAME = "proposed"
MODEL_FAMILY: str | None = "deepseek_v4_pro"
BATCH_ID = "proposed_hackatdac_deepseek_pilot_v1"

BATCH_DIR = PROJECT_ROOT / "runs" / METHOD_NAME / BATCH_ID
OUTPUT_FINDING_REVIEW_DRAFT = (
    PROJECT_ROOT / "evaluation_results" / METHOD_NAME / str(MODEL_FAMILY) / "finding_review_draft.csv"
)


def main() -> None:
    rows = build_finding_review(BATCH_DIR, OUTPUT_FINDING_REVIEW_DRAFT, model_family=MODEL_FAMILY)
    print(f"[build_finding_review] batch_dir={BATCH_DIR}")
    print(f"[build_finding_review] model_family={MODEL_FAMILY}")
    print(f"[build_finding_review] output={OUTPUT_FINDING_REVIEW_DRAFT}")
    print(f"[build_finding_review] rows={len(rows)}")
    print("[build_finding_review] next: manually review and save as finding_review.csv")


if __name__ == "__main__":
    main()
