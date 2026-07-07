from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ChainContextAnalysisConfig:
    schema_version: str = "0.1"
    max_chains: int | None = None
    require_violation_evidence: bool = True

