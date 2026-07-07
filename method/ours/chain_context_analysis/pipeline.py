from __future__ import annotations

import json
import time
from datetime import datetime
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
    started_at = _now_iso()
    started = time.monotonic()
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
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "started_at": started_at,
        "completed_at": "",
        "elapsed_seconds": 0.0,
        "final_finding_count": 0,
        "discarded_finding_count": 0,
        "no_finding_count": 0,
        "per_chain": [],
    }
    for index, chain in enumerate(chains, start=1):
        chain_started_at = _now_iso()
        chain_started = time.monotonic()
        chain_id = chain.get("chain_id")
        print(
            f"[chain-context][{index}/{len(chains)}] START graph={graph_id} chain={chain_id}",
            flush=True,
        )
        prompt = build_prompt(chain)
        analysis, llm_diag = analyze_chain_plain_json(chat_model, prompt)
        diagnostics["analyzed_chain_count"] += 1
        diagnostics["llm_call_count"] += int(llm_diag.get("llm_calls", 0))
        diagnostics["input_tokens"] += int(llm_diag.get("input_tokens", 0) or 0)
        diagnostics["output_tokens"] += int(llm_diag.get("output_tokens", 0) or 0)
        diagnostics["total_tokens"] += int(llm_diag.get("total_tokens", 0) or 0)
        row = {
            "chain_id": chain.get("chain_id"),
            "started_at": chain_started_at,
            "completed_at": "",
            "elapsed_seconds": 0.0,
            "llm": llm_diag,
        }
        if analysis is None:
            row["status"] = "llm_failed"
            diagnostics["discarded_finding_count"] += 1
            _finalize_chain_row(row, chain_started)
            diagnostics["per_chain"].append(row)
            _print_chain_done(index, len(chains), graph_id, chain_id, row, llm_diag)
            continue
        if analysis.chain_id != chain.get("chain_id"):
            row["status"] = "chain_id_mismatch"
            diagnostics["discarded_finding_count"] += 1
            _finalize_chain_row(row, chain_started)
            diagnostics["per_chain"].append(row)
            _print_chain_done(index, len(chains), graph_id, chain_id, row, llm_diag)
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
        _finalize_chain_row(row, chain_started)
        diagnostics["per_chain"].append(row)
        _print_chain_done(index, len(chains), graph_id, chain_id, row, llm_diag)
    diagnostics["final_finding_count"] = len(findings)
    diagnostics["completed_at"] = _now_iso()
    diagnostics["elapsed_seconds"] = time.monotonic() - started
    write_outputs(output_dir, graph_id, findings, diagnostics)
    return {
        "graph_id": graph_id,
        "chain_count": len(chains),
        "llm_call_count": diagnostics["llm_call_count"],
        "input_tokens": diagnostics["input_tokens"],
        "output_tokens": diagnostics["output_tokens"],
        "total_tokens": diagnostics["total_tokens"],
        "started_at": diagnostics["started_at"],
        "completed_at": diagnostics["completed_at"],
        "elapsed_seconds": diagnostics["elapsed_seconds"],
        "final_finding_count": len(findings),
        "discarded_finding_count": diagnostics["discarded_finding_count"],
        "output_dir": str(output_dir),
    }


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def _finalize_chain_row(row: dict[str, Any], started: float) -> None:
    row["completed_at"] = _now_iso()
    row["elapsed_seconds"] = time.monotonic() - started


def _print_chain_done(
    index: int,
    total: int,
    graph_id: str,
    chain_id: Any,
    row: dict[str, Any],
    llm_diag: dict[str, Any],
) -> None:
    print(
        "[chain-context][{index}/{total}] {status} graph={graph_id} chain={chain_id} "
        "seconds={seconds:.1f} tokens={tokens} llm={llm_status}".format(
            index=index,
            total=total,
            status=str(row.get("status", "")).upper(),
            graph_id=graph_id,
            chain_id=chain_id,
            seconds=float(row.get("elapsed_seconds", 0.0) or 0.0),
            tokens=int(llm_diag.get("total_tokens", 0) or 0),
            llm_status=str(llm_diag.get("status", "")),
        ),
        flush=True,
    )
