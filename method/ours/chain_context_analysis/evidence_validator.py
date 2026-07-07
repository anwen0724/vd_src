from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import ChainContextAnalysisConfig
from .schema import LLMChainAnalysis


def validate_chain_finding(
    analysis: LLMChainAnalysis,
    chain: dict[str, Any],
    repo_root: str | Path,
    finding_id: str,
    config: ChainContextAnalysisConfig,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    diagnostics = {"chain_id": analysis.chain_id, "status": "not_checked", "discard_reason": "", "invalid_snippet_ids": []}
    if not analysis.has_finding:
        diagnostics["status"] = "no_finding"
        return None, diagnostics
    if analysis.finding is None:
        diagnostics["status"] = "discarded"
        diagnostics["discard_reason"] = "missing_finding_body"
        return None, diagnostics
    snippets = {snippet.get("snippet_id"): snippet for snippet in chain.get("source_snippets", [])}
    evidence = []
    for item in analysis.finding.evidence:
        snippet = snippets.get(item.snippet_id)
        if not snippet:
            diagnostics["invalid_snippet_ids"].append(item.snippet_id)
            continue
        path = Path(repo_root) / str(snippet.get("file", ""))
        start = int(snippet.get("line_start", 0))
        end = int(snippet.get("line_end", 0))
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if start < 1 or end < start or end > len(lines):
            continue
        evidence.append(
            {
                "file": snippet.get("file", ""),
                "line_start": start,
                "line_end": end,
                "module": _module_from_nodes(chain, snippet),
                "object": _object_from_nodes(chain, snippet),
                "evidence_type": item.evidence_role,
                "description": item.description,
                "supports_claim": item.supports_claim,
            }
        )
    if not evidence:
        diagnostics["status"] = "discarded"
        diagnostics["discard_reason"] = "no_valid_evidence"
        return None, diagnostics
    violation = [item for item in evidence if item["evidence_type"] == "violation"]
    if config.require_violation_evidence and not violation:
        diagnostics["status"] = "discarded"
        diagnostics["discard_reason"] = "missing_violation_evidence"
        return None, diagnostics
    loc_source = violation[0] if violation else evidence[0]
    finding = {
        "finding_id": finding_id,
        "status": "confirmed_finding",
        "summary": analysis.finding.summary,
        "vulnerability_category": "permission_related_vulnerability",
        "affected_locations": [
            {
                "file": loc_source["file"],
                "line_start": loc_source["line_start"],
                "line_end": loc_source["line_end"],
                "module": loc_source["module"],
                "signal_or_register": loc_source["object"],
            }
        ],
        "evidence": evidence,
        "reasoning_summary": analysis.finding.reasoning_summary,
        "security_impact": analysis.finding.security_impact,
        "confidence": analysis.finding.confidence,
        "uncertainty_or_missing_evidence": analysis.finding.uncertainty_or_missing_evidence,
        "recommended_follow_up": [],
        "source_chain_ids": [analysis.chain_id],
    }
    diagnostics["status"] = "accepted"
    return finding, diagnostics


def _module_from_nodes(chain: dict[str, Any], snippet: dict[str, Any]) -> str:
    nodes = {node.get("node_id"): node for node in chain.get("nodes", [])}
    for node_id in snippet.get("node_ids", []) or []:
        node = nodes.get(node_id)
        if node and node.get("module"):
            return str(node.get("module"))
    return ""


def _object_from_nodes(chain: dict[str, Any], snippet: dict[str, Any]) -> str:
    nodes = {node.get("node_id"): node for node in chain.get("nodes", [])}
    for node_id in snippet.get("node_ids", []) or []:
        node = nodes.get(node_id)
        if node and node.get("name"):
            return str(node.get("name"))
    return ""

