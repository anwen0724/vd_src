from __future__ import annotations

import argparse
import sys
from pathlib import Path

from evaluation.common import (
    DETECTION_MATCH_VALUES,
    EVIDENCE_QUALITY_VALUES,
    read_csv,
)


def validate_finding_review(gt_cases_path: str | Path, finding_review_path: str | Path) -> list[str]:
    gt_case_ids = {row.get("case_id", "") for row in read_csv(gt_cases_path)}
    rows = read_csv(finding_review_path)
    errors: list[str] = []
    seen: set[str] = set()
    finding_ids = {row.get("finding_uid", "") for row in rows}
    for index, row in enumerate(rows, start=2):
        finding_uid = row.get("finding_uid", "")
        if not finding_uid:
            errors.append(f"row {index}: missing finding_uid")
        elif finding_uid in seen:
            errors.append(f"row {index}: duplicate finding_uid {finding_uid}")
        seen.add(finding_uid)

        match = row.get("detection_match", "")
        quality = row.get("evidence_quality", "")
        matched_case = row.get("matched_case_id", "")
        duplicate_of = row.get("duplicate_of_finding_uid", "")

        if match == "Partial":
            errors.append(f"row {index}: Partial is not allowed")
        if match not in DETECTION_MATCH_VALUES:
            errors.append(f"row {index}: invalid detection_match {match!r}")
        if quality not in EVIDENCE_QUALITY_VALUES:
            errors.append(f"row {index}: invalid evidence_quality {quality!r}")
        if matched_case and matched_case not in gt_case_ids:
            errors.append(f"row {index}: matched_case_id {matched_case!r} not found in GT")
        if match == "TP" and not matched_case:
            errors.append(f"row {index}: TP requires matched_case_id")
        if match == "FP" and matched_case:
            errors.append(f"row {index}: FP must not keep matched_case_id")
        if match == "Duplicate":
            if not duplicate_of:
                errors.append(f"row {index}: Duplicate requires duplicate_of_finding_uid")
            elif duplicate_of not in finding_ids:
                errors.append(f"row {index}: duplicate_of_finding_uid {duplicate_of!r} not found")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate reviewed finding table.")
    parser.add_argument("--gt-cases", required=True)
    parser.add_argument("--finding-review", required=True)
    args = parser.parse_args()
    errors = validate_finding_review(args.gt_cases, args.finding_review)
    if errors:
        for error in errors:
            print(error)
        sys.exit(1)
    print("finding_review.csv validation passed")


if __name__ == "__main__":
    main()
