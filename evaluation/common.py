from __future__ import annotations

import csv
import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


GT_CASE_COLUMNS = [
    "case_id",
    "benchmark_id",
    "input_scope",
    "case_description",
    "gt_files",
    "gt_modules",
    "gt_signals_or_registers",
    "gt_evidence_notes",
]

FINDING_REVIEW_COLUMNS = [
    "finding_uid",
    "model_family",
    "method_name",
    "input_scope",
    "repetition",
    "run_id",
    "final_answer_path",
    "finding_id",
    "model_reported_status",
    "summary",
    "vulnerability_category",
    "affected_locations",
    "claimed_files",
    "claimed_modules",
    "claimed_signals_or_registers",
    "evidence_items",
    "reasoning_summary",
    "security_impact",
    "confidence",
    "uncertainty_or_missing_evidence",
    "matched_case_id",
    "detection_match",
    "duplicate_of_finding_uid",
    "evidence_quality",
    "review_notes",
]

DETECTION_MATCH_VALUES = {"TP", "FP", "Duplicate", "Unscorable"}
EVIDENCE_QUALITY_VALUES = {"Sufficient", "Insufficient", "Fabricated", "Unsupported", "Unclear"}
SCORED_DETECTION_MATCHES = {"TP", "FP"}
EVIDENCE_QUALITY_RANK = {
    "Sufficient": 0,
    "Insufficient": 1,
    "Unclear": 2,
    "Unsupported": 3,
    "Fabricated": 4,
}


def read_csv(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: str | Path, columns: list[str], rows: Iterable[dict[str, Any]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def read_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    target = Path(path)
    if not target.exists():
        return rows
    for line in target.read_text(encoding="utf-8-sig").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def unique_join(values: Iterable[Any]) -> str:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return "; ".join(output)


def normalize(value: Any) -> str:
    return str(value or "").strip()


def ratio(numerator: int | float, denominator: int | float) -> str:
    if not denominator:
        return ""
    return f"{numerator / denominator:.6f}"


def f1_score(precision: str, recall: str) -> str:
    if not precision or not recall:
        return ""
    p = float(precision)
    r = float(recall)
    if p + r == 0:
        return ""
    return f"{(2 * p * r) / (p + r):.6f}"


def mean(values: list[str]) -> str:
    nums = [float(value) for value in values if value != ""]
    if not nums:
        return ""
    return f"{sum(nums) / len(nums):.6f}"


def sample_std(values: list[str]) -> str:
    nums = [float(value) for value in values if value != ""]
    if len(nums) < 2:
        return ""
    avg = sum(nums) / len(nums)
    return f"{math.sqrt(sum((value - avg) ** 2 for value in nums) / (len(nums) - 1)):.6f}"


def repetition_from_name(name: str) -> str:
    match = re.search(r"rep[_-]?(\d+)", name)
    return match.group(1) if match else name


def gt_by_scope(gt_rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in gt_rows:
        grouped[row.get("input_scope", "")].append(row)
    return dict(grouped)


def tool_trace_path(final_answer_path: str | Path) -> str:
    run_dir = Path(final_answer_path).parent
    for name in ("tool_trace.jsonl", "tool_observations.jsonl"):
        candidate = run_dir / name
        if candidate.exists():
            return str(candidate)
    return ""
