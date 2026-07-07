from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolGuidedChainAnalysisConfig:
    schema_version: str = "0.1"
    max_chains: int | None = None
    max_tool_calls_per_chain: int = 32
    read_around_before: int = 10
    read_around_after: int = 18
    max_tool_result_chars: int = 5000
    require_violation_evidence: bool = True
