from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import ChainContextAnalysisConfig
from .evidence_validator import validate_chain_finding
from .llm_runner import analyze_chain_plain_json
from .prompt_builder import build_prompt
from .writer import write_outputs


def run_chain_context_analysis(
    contexts_path: str | Path,
    repo_root: str | Path,
    output_dir: str | Path,
    chat_model: Any,
    config: ChainContextAnalysisConfig,
) -> dict[str, Any]:
    doc = json.loads(Path(contexts_path).read_text(encoding="utf-8"))
    graph_id = str(doc.get("graph_id", ""))
    chains = list(doc.get("chains", []))
    if config.max_chains is not None:
        chains = chains[: config.max_chains]
    findings: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {
        "graph_id": graph_id,
        "chain_count": len(chains),
        "analyzed_chain_count": 0,
        "llm_call_count": 0,
        "final_finding_count": 0,
        "discarded_finding_count": 0,
        "no_finding_count": 0,
        "per_chain": [],
    }
    for chain in chains:
        prompt = build_prompt(chain)
        analysis, llm_diag = analyze_chain_plain_json(chat_model, prompt)
        diagnostics["analyzed_chain_count"] += 1
        diagnostics["llm_call_count"] += int(llm_diag.get("llm_calls", 0))
        row = {"chain_id": chain.get("chain_id"), "llm": llm_diag}
        if analysis is None:
            row["status"] = "llm_failed"
            diagnostics["discarded_finding_count"] += 1
            diagnostics["per_chain"].append(row)
            continue
        if analysis.chain_id != chain.get("chain_id"):
            row["status"] = "chain_id_mismatch"
            diagnostics["discarded_finding_count"] += 1
            diagnostics["per_chain"].append(row)
            continue
        finding, ev_diag = validate_chain_finding(
            analysis,
            chain,
            repo_root,
            finding_id=f"F-{len(findings)+1:03d}",
            config=config,
        )
        row["evidence_validation"] = ev_diag
        if finding is None:
            if ev_diag.get("status") == "no_finding":
                diagnostics["no_finding_count"] += 1
            else:
                diagnostics["discarded_finding_count"] += 1
            row["status"] = ev_diag.get("status")
        else:
            findings.append(finding)
            row["status"] = "accepted"
        diagnostics["per_chain"].append(row)
    diagnostics["final_finding_count"] = len(findings)
    write_outputs(output_dir, graph_id, findings, diagnostics)
    return {
        "graph_id": graph_id,
        "chain_count": len(chains),
        "llm_call_count": diagnostics["llm_call_count"],
        "final_finding_count": len(findings),
        "discarded_finding_count": diagnostics["discarded_finding_count"],
        "output_dir": str(output_dir),
    }

