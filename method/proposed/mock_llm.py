"""Deterministic proposed-method LLM substitute for local smoke tests."""

from __future__ import annotations

from pathlib import Path

from method.proposed.models import (
    AnalysisObligation,
    AnalysisObligationSet,
    EvidenceSlotRecord,
    FactLayer,
    InspectionRecord,
    ObligationAnalysisRecords,
    PermissionFactLayer,
)


class MockInitialVersionLLM:
    """Local deterministic implementation of the three LLM-assisted stages."""

    def semantic_label(self, static_facts: FactLayer, knowledge: str) -> PermissionFactLayer:
        security_facts = static_facts.csr_facts[:10]
        asset_candidates = []
        subject_candidates = []
        operation_candidates = []
        guard_candidates = []
        state_lifecycle_facts = []

        for fact in security_facts:
            lowered = fact.text.lower()
            if any(keyword in lowered for keyword in ["key", "secret", "fuse"]):
                asset_candidates.append(
                    {
                        "name": fact.object or "protected_object",
                        "file": fact.file,
                        "module": fact.module,
                        "signal_or_register": fact.object,
                        "reason": "Security-sensitive naming suggests a protected asset candidate.",
                        "source_evidence": fact.text,
                    }
                )
            if any(keyword in lowered for keyword in ["debug", "jtag", "dma", "bus", "req"]):
                subject_candidates.append(
                    {
                        "name": fact.object or "requester",
                        "interface_or_module": fact.module,
                        "possible_access_type": "request/control",
                        "source_evidence": fact.text,
                    }
                )
            if any(keyword in lowered for keyword in ["write", "read", "we", "rdata", "wdata"]):
                operation_candidates.append(
                    {
                        "operation_type": "read/write",
                        "signal_or_condition": fact.object,
                        "file": fact.file,
                        "module": fact.module,
                        "source_evidence": fact.text,
                    }
                )
            if any(keyword in lowered for keyword in ["lock", "auth", "priv", "access"]):
                guard_candidates.append(
                    {
                        "name": fact.object or "guard",
                        "guard_type": "lock/auth/privilege/access-control",
                        "used_in": [fact.text],
                        "possible_protected_targets": [],
                        "source_evidence": fact.text,
                    }
                )

        for reset in static_facts.reset_facts[:10]:
            state_lifecycle_facts.append(
                {
                    "state": reset.signal_or_condition,
                    "reset_value": "",
                    "set_condition": "",
                    "clear_condition": reset.signal_or_condition,
                    "use_sites": [],
                    "affected_objects_or_paths": [],
                    "source_evidence": reset.text_preview,
                }
            )

        asset_name = _first_name(asset_candidates, "protected_object")
        subject_name = _first_name(subject_candidates, "requester")
        path_candidates = []
        if asset_candidates or subject_candidates:
            path_candidates.append(
                {
                    "path_id": "P1",
                    "subject": subject_name,
                    "object": asset_name,
                    "path_nodes": [subject_name, asset_name],
                    "guards_on_path": [guard.get("name", "") for guard in guard_candidates],
                    "uncertain_links": [],
                    "source_evidence": "Heuristic candidate from security-relevant RTL facts.",
                }
            )

        return PermissionFactLayer(
            static_facts=static_facts,
            asset_candidates=asset_candidates,
            subject_candidates=subject_candidates,
            operation_candidates=operation_candidates,
            guard_candidates=guard_candidates,
            state_lifecycle_facts=state_lifecycle_facts,
            path_candidates=path_candidates,
            summary="Mock permission fact layer generated from security-relevant RTL keywords.",
        )

    def plan_obligations(
        self,
        permission_facts: PermissionFactLayer,
        knowledge: str,
    ) -> AnalysisObligationSet:
        asset = _first_name(permission_facts.asset_candidates, "protected_object")
        subject = _first_name(permission_facts.subject_candidates, "requester")
        path = ""
        if permission_facts.path_candidates:
            path = " -> ".join(permission_facts.path_candidates[0].get("path_nodes", []))
        return AnalysisObligationSet(
            scope_id="",
            obligations=[
                AnalysisObligation(
                    obligation_id="O1",
                    reason="Check whether a requester can access a protected object without an adequate permission guard.",
                    subject=subject,
                    operation="read/write/control",
                    object=asset,
                    expected_guard="lock, authorization, privilege, or access-control mediation",
                    candidate_path=path,
                    state_conditions_to_check=["reset/default/lifecycle state if relevant"],
                    required_evidence_slots=[
                        "subject",
                        "operation",
                        "object",
                        "expected_guard",
                        "observed_behavior",
                        "path",
                        "impact",
                        "rtl_evidence",
                    ],
                    files_or_modules_to_inspect=_candidate_files(permission_facts),
                    knowledge_used=["generic permission vulnerability knowledge"],
                    priority="medium",
                    uncertainty="Mock obligation planning uses heuristic facts only.",
                )
            ],
        )

    def inspect_obligations(
        self,
        obligations: AnalysisObligationSet,
        permission_facts: PermissionFactLayer,
        input_scope: Path,
        missing_evidence_requests: list[dict] | None = None,
    ) -> ObligationAnalysisRecords:
        records = []
        evidence = _first_evidence(permission_facts)
        for obligation in obligations.obligations:
            records.append(
                InspectionRecord(
                    obligation_id=obligation.obligation_id,
                    inspection_status="candidate_violation" if evidence else "inconclusive",
                    evidence_slots=EvidenceSlotRecord(
                        subject=obligation.subject,
                        operation=obligation.operation,
                        object=obligation.object,
                        expected_guard=obligation.expected_guard,
                        observed_behavior="A security-relevant access relation was identified in visible RTL facts.",
                        path=obligation.candidate_path,
                        state_condition=", ".join(obligation.state_conditions_to_check),
                        impact="Potential unintended access or modification of protected RTL state.",
                        rtl_evidence=[evidence] if evidence else [],
                    ),
                    missing_or_uncertain_evidence="Mock inspection should be replaced by a real LLM for experiments.",
                    candidate_finding="Possible permission-related access path requires review.",
                )
            )
        return ObligationAnalysisRecords(scope_id=obligations.scope_id, obligations=obligations.obligations, inspection_records=records)


def _first_name(candidates: list[dict], fallback: str) -> str:
    if not candidates:
        return fallback
    return str(candidates[0].get("name") or candidates[0].get("signal_or_register") or fallback)


def _candidate_files(permission_facts: PermissionFactLayer) -> list[str]:
    files = set()
    for collection in [
        permission_facts.asset_candidates,
        permission_facts.subject_candidates,
        permission_facts.operation_candidates,
        permission_facts.guard_candidates,
    ]:
        for item in collection:
            if item.get("file"):
                files.add(str(item["file"]))
    return sorted(files)[:10]


def _first_evidence(permission_facts: PermissionFactLayer) -> dict:
    for fact in permission_facts.static_facts.csr_facts:
        return {
            "file": fact.file,
            "line_start": fact.line_start,
            "line_end": fact.line_start,
            "module": fact.module,
            "object": fact.object,
            "evidence_type": fact.evidence_type or "unknown",
            "description": fact.text,
            "supports_claim": "This RTL line was classified as security-relevant by the fact extractor.",
        }
    return {}

