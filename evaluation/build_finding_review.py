from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from evaluation.common import (
    FINDING_REVIEW_COLUMNS,
    read_json,
    repetition_from_name,
    unique_join,
    write_csv,
)


def build_finding_review(
    batch_dir: str | Path,
    output_path: str | Path,
    model_family: str | None = None,
) -> list[dict[str, str]]:
    batch = Path(batch_dir).resolve()
    method_name = batch.parent.name
    rows: list[dict[str, str]] = []
    for final_answer in sorted(batch.glob("models/*/*/rep_*/final_answer.json")):
        current_model = final_answer.parents[2].name
        if model_family and current_model != model_family:
            continue
        input_scope = final_answer.parents[1].name
        repetition = repetition_from_name(final_answer.parent.name)
        run_id = f"{method_name}:{current_model}:{input_scope}:rep_{repetition}"
        answer = read_json(final_answer)
        for index, finding in enumerate(answer.get("findings") or [], start=1):
            rows.append(
                _finding_to_row(
                    finding=finding,
                    final_answer=final_answer,
                    method_name=method_name,
                    model_family=current_model,
                    input_scope=input_scope,
                    repetition=repetition,
                    run_id=run_id,
                    index=index,
                )
            )
    write_csv(output_path, FINDING_REVIEW_COLUMNS, rows)
    return rows


def _finding_to_row(
    *,
    finding: dict[str, Any],
    final_answer: Path,
    method_name: str,
    model_family: str,
    input_scope: str,
    repetition: str,
    run_id: str,
    index: int,
) -> dict[str, str]:
    locations = finding.get("affected_locations") or []
    evidence = finding.get("evidence") or []
    finding_id = str(finding.get("finding_id") or f"F{index}")
    return {
        "finding_uid": f"{method_name}:{model_family}:{input_scope}:rep_{repetition}:{finding_id}",
        "model_family": model_family,
        "method_name": method_name,
        "input_scope": input_scope,
        "repetition": repetition,
        "run_id": run_id,
        "final_answer_path": str(final_answer),
        "finding_id": finding_id,
        "model_reported_status": str(finding.get("status") or ""),
        "summary": str(finding.get("summary") or ""),
        "vulnerability_category": str(finding.get("vulnerability_category") or ""),
        "affected_locations": _flatten_locations(locations),
        "claimed_files": unique_join(
            [item.get("file", "") for item in locations if isinstance(item, dict)]
            + [item.get("file", "") for item in evidence if isinstance(item, dict)]
        ),
        "claimed_modules": unique_join(
            [item.get("module", "") for item in locations if isinstance(item, dict)]
            + [item.get("module", "") for item in evidence if isinstance(item, dict)]
        ),
        "claimed_signals_or_registers": unique_join(
            [item.get("signal_or_register", "") for item in locations if isinstance(item, dict)]
            + [item.get("object", "") for item in evidence if isinstance(item, dict)]
        ),
        "evidence_items": _flatten_evidence(evidence),
        "reasoning_summary": str(finding.get("reasoning_summary") or ""),
        "security_impact": str(finding.get("security_impact") or ""),
        "confidence": str(finding.get("confidence") or ""),
        "uncertainty_or_missing_evidence": str(finding.get("uncertainty_or_missing_evidence") or ""),
        "matched_case_id": "",
        "detection_match": "",
        "duplicate_of_finding_uid": "",
        "evidence_quality": "",
        "review_notes": "",
    }


def _flatten_locations(locations: list[Any]) -> str:
    parts: list[str] = []
    for item in locations:
        if not isinstance(item, dict):
            continue
        file = item.get("file") or ""
        line_start = item.get("line_start")
        line_end = item.get("line_end")
        line = ""
        if line_start is not None and line_start != "":
            line = f":{line_start}"
            if line_end is not None and line_end != "" and line_end != line_start:
                line += f"-{line_end}"
        module = item.get("module") or ""
        signal = item.get("signal_or_register") or ""
        parts.append(" | ".join(value for value in [f"{file}{line}", module, signal] if value))
    return "\n".join(parts)


def _flatten_evidence(evidence: list[Any]) -> str:
    parts: list[str] = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        file = item.get("file") or ""
        line_start = item.get("line_start")
        line_end = item.get("line_end")
        line = ""
        if line_start is not None and line_start != "":
            line = f":{line_start}"
            if line_end is not None and line_end != "" and line_end != line_start:
                line += f"-{line_end}"
        fields = [
            f"{file}{line}",
            item.get("module") or "",
            item.get("object") or "",
            item.get("evidence_type") or "",
            item.get("description") or "",
            item.get("supports_claim") or "",
        ]
        parts.append(" | ".join(str(value) for value in fields if value))
    return "\n".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build finding review draft from run outputs.")
    parser.add_argument("--batch-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--model-family", help="Optional model-family filter for per-model output.")
    args = parser.parse_args()
    rows = build_finding_review(args.batch_dir, args.output, model_family=args.model_family)
    print(f"Wrote {len(rows)} finding review rows to {args.output}")


if __name__ == "__main__":
    main()
