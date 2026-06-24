"""Evidence closure and baseline-compatible output normalization."""

from __future__ import annotations

from typing import Any

from method.proposed.models import (
    ClosureRecord,
    ClosureResult,
    InspectionRecord,
    MissingEvidenceRequest,
    ObligationAnalysisRecords,
)
from schemas.agent_output import AgentOutput


CORE_SLOTS = [
    "subject",
    "operation",
    "object",
    "expected_guard",
    "observed_behavior",
    "path",
    "impact",
    "rtl_evidence",
]


class EvidenceClosureChecker:
    """Check evidence-slot closure and normalize reports to AgentOutput."""

    def check(self, records: ObligationAnalysisRecords) -> ClosureResult:
        closure_records: list[ClosureRecord] = []
        for index, record in enumerate(records.inspection_records, start=1):
            closure_check = _closure_check(record)
            missing = [
                MissingEvidenceRequest(
                    obligation_id=record.obligation_id,
                    missing_slot=slot,
                    why_required=f"{slot} is required to support a permission vulnerability finding.",
                    suggested_source_to_check=_suggest_source(slot),
                )
                for slot, present in closure_check.items()
                if not present
            ]
            internal_verdict = _internal_verdict(record, missing)
            closure_records.append(
                ClosureRecord(
                    finding_id=f"F{index}",
                    obligation_id=record.obligation_id,
                    internal_verdict=internal_verdict,
                    closure_check=closure_check,
                    missing_evidence=missing,
                    verdict_reason=_verdict_reason(record, internal_verdict, missing),
                )
            )
        return ClosureResult(scope_id=records.scope_id, closure_records=closure_records)

    @staticmethod
    def to_agent_output(
        records: ObligationAnalysisRecords,
        closure: ClosureResult,
    ) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        records_by_obligation = {record.obligation_id: record for record in records.inspection_records}
        for closure_record in closure.closure_records:
            if closure_record.internal_verdict == "no_supported_finding":
                continue
            record = records_by_obligation.get(closure_record.obligation_id)
            if record is None:
                continue
            findings.append(_record_to_finding(record, closure_record, len(findings) + 1))

        output = {
            "analysis_summary": _analysis_summary(findings, records),
            "findings": findings,
            "no_finding_reason": "" if findings else "No supported permission-related finding was produced.",
            "global_uncertainty": _global_uncertainty(records, closure),
        }
        return AgentOutput.model_validate(output).model_dump()


def _closure_check(record: InspectionRecord) -> dict[str, bool]:
    slots = record.evidence_slots
    return {
        "subject": bool(slots.subject.strip()),
        "operation": bool(slots.operation.strip()),
        "object": bool(slots.object.strip()),
        "expected_guard": bool(slots.expected_guard.strip()),
        "observed_behavior": bool(slots.observed_behavior.strip()),
        "path": bool(slots.path.strip()),
        "impact": bool(slots.impact.strip()),
        "rtl_evidence": bool(slots.rtl_evidence),
    }


def _internal_verdict(
    record: InspectionRecord,
    missing: list[MissingEvidenceRequest],
) -> str:
    if record.inspection_status in {"obligation_satisfied", "not_applicable"}:
        return "no_supported_finding"
    if not missing and record.inspection_status == "candidate_violation":
        return "confirmed"
    if record.evidence_slots.rtl_evidence and record.inspection_status in {"candidate_violation", "inconclusive"}:
        return "possible"
    return "unsupported"


def _record_to_finding(
    record: InspectionRecord,
    closure_record: ClosureRecord,
    finding_index: int,
) -> dict[str, Any]:
    status = {
        "confirmed": "confirmed_finding",
        "possible": "potential_warning",
        "unsupported": "needs_more_evidence",
    }.get(closure_record.internal_verdict, "needs_more_evidence")
    confidence = {
        "confirmed": "high",
        "possible": "medium",
        "unsupported": "low",
    }.get(closure_record.internal_verdict, "low")
    evidence = [_normalize_evidence(item) for item in record.evidence_slots.rtl_evidence]
    return {
        "finding_id": f"F{finding_index}",
        "status": status,
        "summary": record.candidate_finding or record.evidence_slots.observed_behavior or "Permission-related issue candidate.",
        "vulnerability_category": _category(record),
        "affected_locations": [_evidence_to_location(item) for item in evidence],
        "evidence": evidence,
        "reasoning_summary": _reasoning_summary(record, closure_record),
        "security_impact": record.evidence_slots.impact or "Security impact is not fully established from visible evidence.",
        "confidence": confidence,
        "uncertainty_or_missing_evidence": _uncertainty(record, closure_record),
        "recommended_follow_up": _recommended_follow_up(closure_record),
    }


def _normalize_evidence(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "file": str(item.get("file", "")),
        "line_start": item.get("line_start"),
        "line_end": item.get("line_end"),
        "module": str(item.get("module", "")),
        "object": str(item.get("object", "")),
        "evidence_type": str(item.get("evidence_type", "unknown") or "unknown"),
        "description": str(item.get("description", "")),
        "supports_claim": str(item.get("supports_claim", "")),
    }


def _evidence_to_location(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "file": item["file"],
        "line_start": item.get("line_start"),
        "line_end": item.get("line_end"),
        "module": item.get("module", ""),
        "signal_or_register": item.get("object", ""),
    }


def _category(record: InspectionRecord) -> str:
    slots = record.evidence_slots
    pieces = [slots.operation, slots.object, "permission-related RTL security issue"]
    return " / ".join(piece for piece in pieces if piece)


def _reasoning_summary(record: InspectionRecord, closure_record: ClosureRecord) -> str:
    slots = record.evidence_slots
    parts = [
        f"Subject: {slots.subject}" if slots.subject else "",
        f"Operation: {slots.operation}" if slots.operation else "",
        f"Object: {slots.object}" if slots.object else "",
        f"Expected guard: {slots.expected_guard}" if slots.expected_guard else "",
        f"Observed behavior: {slots.observed_behavior}" if slots.observed_behavior else "",
        f"Path: {slots.path}" if slots.path else "",
        f"Closure verdict: {closure_record.verdict_reason}",
    ]
    return " ".join(part for part in parts if part).strip()


def _uncertainty(record: InspectionRecord, closure_record: ClosureRecord) -> str:
    missing = ", ".join(request.missing_slot for request in closure_record.missing_evidence)
    chunks = []
    if record.missing_or_uncertain_evidence:
        chunks.append(record.missing_or_uncertain_evidence)
    if missing:
        chunks.append(f"Missing evidence slots: {missing}.")
    return " ".join(chunks)


def _recommended_follow_up(closure_record: ClosureRecord) -> list[str]:
    return [
        f"Check {request.suggested_source_to_check or request.missing_slot} for obligation {request.obligation_id}."
        for request in closure_record.missing_evidence
    ]


def _analysis_summary(findings: list[dict[str, Any]], records: ObligationAnalysisRecords) -> str:
    if not findings:
        return "The proposed method did not produce a supported permission-related finding from the visible RTL evidence."
    return (
        f"The proposed method produced {len(findings)} finding(s) from "
        f"{len(records.obligations)} analysis obligation(s)."
    )


def _global_uncertainty(records: ObligationAnalysisRecords, closure: ClosureResult) -> str:
    missing_count = sum(len(record.missing_evidence) for record in closure.closure_records)
    if missing_count:
        return f"{missing_count} evidence slot(s) remained incomplete after closure checking."
    return "No closure-level missing evidence was recorded beyond the visible source scope limitations."


def _verdict_reason(
    record: InspectionRecord,
    verdict: str,
    missing: list[MissingEvidenceRequest],
) -> str:
    if verdict == "confirmed":
        return "All required core evidence slots are present for a candidate violation."
    if verdict == "possible":
        return "Related RTL evidence exists, but some core evidence slots remain incomplete."
    if verdict == "unsupported":
        return "The candidate lacks source evidence or key evidence slots."
    return f"Inspection status is {record.inspection_status}; no supported finding is emitted."


def _suggest_source(slot: str) -> str:
    suggestions = {
        "subject": "request source or interface signal",
        "operation": "read/write/reset/unlock condition",
        "object": "protected register, state, key, fuse, or memory object",
        "expected_guard": "lock/auth/privilege/access-control guard use site",
        "observed_behavior": "RTL assignment, condition, or state transition",
        "path": "module connection, port binding, bus path, or wrapper path",
        "impact": "security-sensitive consequence of the observed behavior",
        "rtl_evidence": "source file, module, signal, or code block",
    }
    return suggestions.get(slot, slot)

