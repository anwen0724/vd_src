"""Data models for the proposed initial-version method."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class FileFact(BaseModel):
    path: str
    suffix: str = ""
    line_count: int = 0


class ModuleFact(BaseModel):
    name: str
    file: str
    line_start: int | None = None
    line_end: int | None = None


class InstanceFact(BaseModel):
    instance: str
    module_type: str
    file: str
    parent_module: str = ""
    line_start: int | None = None


class PortFact(BaseModel):
    name: str
    direction: str = ""
    width: str = ""
    file: str
    module: str = ""
    line_start: int | None = None


class SignalFact(BaseModel):
    name: str
    kind: str = ""
    width: str = ""
    file: str
    module: str = ""
    line_start: int | None = None


class AssignmentFact(BaseModel):
    target: str = ""
    expression: str = ""
    file: str
    module: str = ""
    line_start: int | None = None
    text: str = ""


class AlwaysBlockFact(BaseModel):
    file: str
    module: str = ""
    line_start: int | None = None
    line_end: int | None = None
    header: str = ""
    text_preview: str = ""


class ResetFact(BaseModel):
    file: str
    module: str = ""
    line_start: int | None = None
    signal_or_condition: str = ""
    text_preview: str = ""


class CSRFacts(BaseModel):
    file: str
    module: str = ""
    line_start: int | None = None
    object: str = ""
    evidence_type: str = ""
    text: str = ""


class FactLayer(BaseModel):
    """Static facts extracted from the raw RTL source scope."""

    files: list[FileFact] = Field(default_factory=list)
    modules: list[ModuleFact] = Field(default_factory=list)
    instances: list[InstanceFact] = Field(default_factory=list)
    ports: list[PortFact] = Field(default_factory=list)
    signals: list[SignalFact] = Field(default_factory=list)
    assignments: list[AssignmentFact] = Field(default_factory=list)
    always_blocks: list[AlwaysBlockFact] = Field(default_factory=list)
    reset_facts: list[ResetFact] = Field(default_factory=list)
    csr_facts: list[CSRFacts] = Field(default_factory=list)


class PermissionSemanticLabels(BaseModel):
    """LLM-produced semantic labels without deterministic static facts."""

    asset_candidates: list[dict[str, Any]] = Field(default_factory=list)
    subject_candidates: list[dict[str, Any]] = Field(default_factory=list)
    operation_candidates: list[dict[str, Any]] = Field(default_factory=list)
    guard_candidates: list[dict[str, Any]] = Field(default_factory=list)
    state_lifecycle_facts: list[dict[str, Any]] = Field(default_factory=list)
    path_candidates: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""


class PermissionFactLayer(BaseModel):
    """Permission-oriented fact layer consumed by obligation planning."""

    static_facts: FactLayer = Field(default_factory=FactLayer)
    asset_candidates: list[dict[str, Any]] = Field(default_factory=list)
    subject_candidates: list[dict[str, Any]] = Field(default_factory=list)
    operation_candidates: list[dict[str, Any]] = Field(default_factory=list)
    guard_candidates: list[dict[str, Any]] = Field(default_factory=list)
    state_lifecycle_facts: list[dict[str, Any]] = Field(default_factory=list)
    path_candidates: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""


class AnalysisObligation(BaseModel):
    obligation_id: str
    reason: str
    subject: str = ""
    operation: str = ""
    object: str = ""
    expected_guard: str = ""
    candidate_path: str = ""
    state_conditions_to_check: list[str] = Field(default_factory=list)
    required_evidence_slots: list[str] = Field(default_factory=list)
    files_or_modules_to_inspect: list[str] = Field(default_factory=list)
    knowledge_used: list[str] = Field(default_factory=list)
    priority: Literal["high", "medium", "low"] = "medium"
    uncertainty: str = ""


class AnalysisObligationSet(BaseModel):
    scope_id: str = ""
    obligations: list[AnalysisObligation] = Field(default_factory=list)


class EvidenceSlotRecord(BaseModel):
    subject: str = ""
    operation: str = ""
    object: str = ""
    expected_guard: str = ""
    observed_behavior: str = ""
    path: str = ""
    state_condition: str = ""
    impact: str = ""
    rtl_evidence: list[dict[str, Any]] = Field(default_factory=list)


class InspectionRecord(BaseModel):
    obligation_id: str
    inspection_status: Literal[
        "candidate_violation",
        "obligation_satisfied",
        "inconclusive",
        "not_applicable",
    ]
    evidence_slots: EvidenceSlotRecord = Field(default_factory=EvidenceSlotRecord)
    missing_or_uncertain_evidence: str = ""
    candidate_finding: str = ""
    notes: str = ""


class ObligationAnalysisRecords(BaseModel):
    scope_id: str = ""
    obligations: list[AnalysisObligation] = Field(default_factory=list)
    inspection_records: list[InspectionRecord] = Field(default_factory=list)
    tool_observations: list[dict[str, Any]] = Field(default_factory=list)


class MissingEvidenceRequest(BaseModel):
    obligation_id: str
    missing_slot: str
    why_required: str
    suggested_source_to_check: str = ""


class ClosureRecord(BaseModel):
    finding_id: str
    obligation_id: str
    internal_verdict: Literal[
        "confirmed",
        "possible",
        "unsupported",
        "no_supported_finding",
    ]
    closure_check: dict[str, bool] = Field(default_factory=dict)
    missing_evidence: list[MissingEvidenceRequest] = Field(default_factory=list)
    verdict_reason: str = ""


class ClosureResult(BaseModel):
    scope_id: str = ""
    closure_records: list[ClosureRecord] = Field(default_factory=list)

    def missing_requests(self) -> list[dict[str, Any]]:
        requests: list[dict[str, Any]] = []
        for record in self.closure_records:
            requests.extend(request.model_dump() for request in record.missing_evidence)
        return requests


class ProposedPipelineConfig(BaseModel):
    scope_id: str
    input_scope_path: Path
    knowledge_base_path: Path | None = None
    output_dir: Path
    max_closure_iterations: int = 1

    model_config = ConfigDict(arbitrary_types_allowed=True)
