from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


EvidenceRole = Literal[
    "access_entry",
    "permission_state",
    "guard_logic",
    "protected_resource",
    "lifecycle_behavior",
    "debug_or_test_control",
    "violation",
    "impact",
]


class LLMEvidenceRef(BaseModel):
    snippet_id: str
    evidence_role: EvidenceRole
    description: str
    supports_claim: str


class LLMFinding(BaseModel):
    summary: str
    evidence: list[LLMEvidenceRef] = Field(default_factory=list)
    reasoning_summary: str
    security_impact: str
    confidence: Literal["high", "medium", "low"] = "medium"
    uncertainty_or_missing_evidence: str = ""


class LLMChainAnalysis(BaseModel):
    chain_id: str
    has_finding: bool
    finding: LLMFinding | None = None
    no_finding_reason: str = ""

