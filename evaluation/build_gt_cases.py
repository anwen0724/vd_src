from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from evaluation.common import GT_CASE_COLUMNS, read_csv, read_jsonl, unique_join, write_csv


def build_gt_cases(benchmarks_dir: str | Path, output_path: str | Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for benchmark_dir in sorted(Path(benchmarks_dir).iterdir()):
        if not benchmark_dir.is_dir() or benchmark_dir.name.startswith("_"):
            continue
        mapping_path = benchmark_dir / "input_scope_gt_map.csv"
        if not mapping_path.exists():
            continue
        task_rows = {row.get("case_id", ""): row for row in read_csv(benchmark_dir / "task_gt.csv")}
        official_rows = _official_rows_by_case(benchmark_dir / "official_gt.csv")
        evidence_rows = {
            str(row.get("case_id", "")): row for row in read_jsonl(benchmark_dir / "evidence_gt.jsonl")
        }
        for mapping in read_csv(mapping_path):
            if mapping.get("case_visibility", "visible").strip().lower() != "visible":
                continue
            case_id = mapping.get("expected_case_id", "").strip()
            if not case_id or case_id in seen:
                continue
            seen.add(case_id)
            task = task_rows.get(case_id, {})
            official = official_rows.get(case_id, {})
            evidence = evidence_rows.get(case_id, {})
            rows.append(_make_gt_case_row(mapping, task, official, evidence))
    rows.sort(key=lambda row: row["case_id"])
    write_csv(output_path, GT_CASE_COLUMNS, rows)
    return rows


def _make_gt_case_row(
    mapping: dict[str, str],
    task: dict[str, str],
    official: dict[str, str],
    evidence: dict[str, Any],
) -> dict[str, str]:
    trace = evidence.get("evidence_trace") or []
    files = evidence.get("files") or [
        item.get("file", "") for item in trace if isinstance(item, dict)
    ]
    benchmark_id = mapping.get("benchmark_id", "")
    modules = evidence.get("modules") or [
        item.get("module", "") for item in trace if isinstance(item, dict)
    ]
    signals = [item.get("signal_or_register", "") for item in trace if isinstance(item, dict)]
    notes = [
        evidence.get("hit_summary", ""),
        evidence.get("notes", ""),
        task.get("notes", ""),
    ]
    return {
        "case_id": mapping.get("expected_case_id", ""),
        "benchmark_id": mapping.get("benchmark_id", ""),
        "input_scope": _evaluation_scope_id(benchmark_id, mapping.get("input_scope", "")),
        "official_description": official.get("official_description", "")
        or task.get("official_description", "")
        or evidence.get("official_description", ""),
        "case_description": task.get("vulnerable_behavior_summary")
        or task.get("relevance_reason")
        or mapping.get("reason", ""),
        "gt_files": unique_join(_visible_file_paths(files, benchmark_id)),
        "gt_modules": unique_join(modules),
        "gt_signals_or_registers": unique_join(signals),
        "gt_evidence_notes": unique_join(notes),
        "case_doc_path": f"datasets/benchmarks/{benchmark_id}/cases/{mapping.get('expected_case_id', '')}.md",
    }


def _official_rows_by_case(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    rows: dict[str, dict[str, str]] = {}
    for row in read_csv(path):
        case_id = row.get("case_id", "").strip()
        if case_id:
            rows[case_id] = row
    return rows


def _visible_file_paths(files: list[Any], benchmark_id: str) -> list[str]:
    prefix = f"third_party/{benchmark_id}/"
    output: list[str] = []
    for file in files:
        text = str(file or "").replace("\\", "/").strip()
        if text.startswith(prefix):
            text = text[len(prefix) :]
        output.append(text)
    return output


def _evaluation_scope_id(benchmark_id: str, input_scope: str) -> str:
    if benchmark_id == "hackatdac18" and input_scope and not input_scope.startswith("h18_"):
        return f"h18_{input_scope}"
    return input_scope


def main() -> None:
    parser = argparse.ArgumentParser(description="Build unified GT case table.")
    parser.add_argument("--benchmarks-dir", default="datasets/benchmarks")
    parser.add_argument("--output", default="evaluation_results/gt_cases.csv")
    args = parser.parse_args()
    rows = build_gt_cases(args.benchmarks_dir, args.output)
    print(f"Wrote {len(rows)} GT cases to {args.output}")


if __name__ == "__main__":
    main()
