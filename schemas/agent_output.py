"""Structured output schema for baseline security analysis results."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class AffectedLocation(BaseModel):
    file: str
    line_start: int | None = None
    line_end: int | None = None
    module: str = ""
    signal_or_register: str = ""


class Evidence(BaseModel):
    file: str
    line_start: int | None = None
    line_end: int | None = None
    module: str = ""
    object: str = ""
    evidence_type: str = ""
    description: str = ""
    supports_claim: str = ""


class Finding(BaseModel):
    finding_id: str
    status: Literal["confirmed_finding", "potential_warning", "needs_more_evidence"]
    summary: str
    vulnerability_category: str
    affected_locations: list[AffectedLocation]
    evidence: list[Evidence]
    reasoning_summary: str
    security_impact: str
    confidence: Literal["high", "medium", "low"]
    uncertainty_or_missing_evidence: str
    recommended_follow_up: list[str] = []


class AgentOutput(BaseModel):
    analysis_summary: str
    findings: list[Finding]
    no_finding_reason: str
    global_uncertainty: str
