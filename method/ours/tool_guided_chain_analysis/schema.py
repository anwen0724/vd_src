from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ToolAction(BaseModel):
    tool: Literal["read_around", "search_in_file"]
    file: str
    line_start: int | None = None
    line_end: int | None = None
    query: str | None = None
    reason: str = ""


class ToolActionRequest(BaseModel):
    chain_id: str
    actions: list[ToolAction] = Field(default_factory=list)


class ToolEvidence(BaseModel):
    file: str
    line_start: int
    line_end: int
    module: str = ""
    object: str = ""
    evidence_role: Literal[
        "access_entry",
        "permission_state",
        "guard_logic",
        "protected_resource",
        "lifecycle_behavior",
        "debug_or_test_control",
        "violation",
        "impact",
    ]
    description: str
    supports_claim: str


class ToolFinding(BaseModel):
    summary: str
    evidence: list[ToolEvidence] = Field(default_factory=list)
    reasoning_summary: str
    security_impact: str
    confidence: Literal["high", "medium", "low"] = "medium"
    uncertainty_or_missing_evidence: str = ""


class ToolChainAnalysis(BaseModel):
    chain_id: str
    has_finding: bool
    finding: ToolFinding | None = None
    no_finding_reason: str = ""

