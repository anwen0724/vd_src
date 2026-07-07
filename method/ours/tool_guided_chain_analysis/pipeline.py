from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import ToolGuidedChainAnalysisConfig
from .controlled_tools import allowed_files_for_chain, execute_actions
from .llm_json import invoke_json
from .prompt_builder import build_action_prompt, build_synthesis_prompt
from .schema import ToolActionRequest, ToolChainAnalysis
from .writer import write_outputs


def run_tool_guided_chain_analysis(
    chain_graphs_path: str | Path,
    repo_root: str | Path,
    output_dir: str | Path,
    chat_model: Any,
    config: ToolGuidedChainAnalysisConfig,
) -> dict[str, Any]:
    doc = json.loads(Path(chain_graphs_path).read_text(encoding="utf-8"))
    graph_id = str(doc.get("graph_id", ""))
    chains = list(doc.get("chains", []))
    if config.max_chains is not None:
        chains = chains[: config.max_chains]
    findings: list[dict[str, Any]] = []
    trace_records: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {
        "graph_id": graph_id,
        "chain_count": len(chains),
        "analyzed_chain_count": 0,
        "llm_call_count": 0,
        "tool_call_count": 0,
        "final_finding_count": 0,
        "discarded_finding_count": 0,
        "no_finding_count": 0,
        "per_chain": [],
    }
    for chain in chains:
        chain_id = str(chain.get("chain_id", ""))
        allowed_files = allowed_files_for_chain(chain)
        action_req, action_diag = invoke_json(
            chat_model,
            build_action_prompt(chain, allowed_files, config.max_tool_calls_per_chain),
            ToolActionRequest,
        )
        diagnostics["llm_call_count"] += int(action_diag.get("llm_calls", 0))
        row: dict[str, Any] = {"chain_id": chain_id, "action_llm": action_diag}
        diagnostics["analyzed_chain_count"] += 1
        if action_req is None or action_req.chain_id != chain_id:
            row["status"] = "action_planning_failed"
            diagnostics["discarded_finding_count"] += 1
            diagnostics["per_chain"].append(row)
            continue
        observations, trace = execute_actions(chain_id, action_req.actions, allowed_files, repo_root, config)
        trace_records.extend(trace)
        diagnostics["tool_call_count"] += len(trace)
        analysis, synth_diag = invoke_json(chat_model, build_synthesis_prompt(chain, observations), ToolChainAnalysis)
        diagnostics["llm_call_count"] += int(synth_diag.get("llm_calls", 0))
        row["synthesis_llm"] = synth_diag
        row["tool_call_count"] = len(trace)
        if analysis is None or analysis.chain_id != chain_id:
            row["status"] = "synthesis_failed"
            diagnostics["discarded_finding_count"] += 1
            diagnostics["per_chain"].append(row)
            continue
        finding, validation = _validate_analysis(analysis, repo_root, f"F-{len(findings)+1:03d}", config)
        row["evidence_validation"] = validation
        if finding is None:
            if validation.get("status") == "no_finding":
                diagnostics["no_finding_count"] += 1
            else:
                diagnostics["discarded_finding_count"] += 1
            row["status"] = validation.get("status")
        else:
            findings.append(finding)
            row["status"] = "accepted"
        diagnostics["per_chain"].append(row)
    diagnostics["final_finding_count"] = len(findings)
    write_outputs(output_dir, graph_id, findings, diagnostics, trace_records)
    return {
        "graph_id": graph_id,
        "chain_count": len(chains),
        "llm_call_count": diagnostics["llm_call_count"],
        "tool_call_count": diagnostics["tool_call_count"],
        "final_finding_count": len(findings),
        "discarded_finding_count": diagnostics["discarded_finding_count"],
        "output_dir": str(output_dir),
    }


def _validate_analysis(
    analysis: ToolChainAnalysis,
    repo_root: str | Path,
    finding_id: str,
    config: ToolGuidedChainAnalysisConfig,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    diagnostics = {"chain_id": analysis.chain_id, "status": "not_checked", "discard_reason": ""}
    if not analysis.has_finding:
        diagnostics["status"] = "no_finding"
        return None, diagnostics
    if analysis.finding is None:
        diagnostics["status"] = "discarded"
        diagnostics["discard_reason"] = "missing_finding_body"
        return None, diagnostics
    evidence = []
    for item in analysis.finding.evidence:
        path = Path(repo_root) / item.file
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if item.line_start < 1 or item.line_end < item.line_start or item.line_end > len(lines):
            continue
        evidence.append(
            {
                "file": item.file,
                "line_start": item.line_start,
                "line_end": item.line_end,
                "module": item.module,
                "object": item.object,
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
    loc = violation[0] if violation else evidence[0]
    finding = {
        "finding_id": finding_id,
        "status": "confirmed_finding",
        "summary": analysis.finding.summary,
        "vulnerability_category": "permission_related_vulnerability",
        "affected_locations": [
            {
                "file": loc["file"],
                "line_start": loc["line_start"],
                "line_end": loc["line_end"],
                "module": loc["module"],
                "signal_or_register": loc["object"],
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

