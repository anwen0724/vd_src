import json
from types import SimpleNamespace

from method.ours.chain_context_analysis.config import ChainContextAnalysisConfig
from method.ours.chain_context_analysis.pipeline import run_chain_context_analysis


class FakeChat:
    def invoke(self, _messages):
        return SimpleNamespace(
            content=json.dumps(
                {
                    "chain_id": "CHAIN-0001",
                    "has_finding": True,
                    "finding": {
                        "summary": "Missing guard.",
                        "evidence": [
                            {
                                "snippet_id": "SNIP-0001",
                                "evidence_role": "violation",
                                "description": "Assignment lacks a guard.",
                                "supports_claim": "The snippet shows a direct assignment.",
                            }
                        ],
                        "reasoning_summary": "The chain has a direct unguarded assignment.",
                        "security_impact": "Unauthorized read.",
                        "confidence": "medium",
                        "uncertainty_or_missing_evidence": "",
                    },
                    "no_finding_reason": "",
                }
            ),
            usage_metadata={"input_tokens": 100, "output_tokens": 25, "total_tokens": 125},
        )


class FakeChatNoViolation:
    def invoke(self, _messages):
        return SimpleNamespace(
            content=json.dumps(
                {
                    "chain_id": "CHAIN-0001",
                    "has_finding": True,
                    "finding": {
                        "summary": "Suspicious permission state.",
                        "evidence": [
                            {
                                "snippet_id": "SNIP-0001",
                                "evidence_role": "permission_state",
                                "description": "The snippet shows a permission-related signal.",
                                "supports_claim": "The signal is part of the checked chain.",
                            }
                        ],
                        "reasoning_summary": "The chain may be unsafe, but no violation evidence is marked.",
                        "security_impact": "Potential unauthorized read.",
                        "confidence": "low",
                        "uncertainty_or_missing_evidence": "No explicit violation evidence.",
                    },
                    "no_finding_reason": "",
                }
            ),
            usage_metadata={"input_tokens": 80, "output_tokens": 20, "total_tokens": 100},
        )


def test_chain_context_analysis_pipeline(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.sv").write_text("module a;\nassign rdata = secret;\nendmodule\n", encoding="utf-8")
    contexts = tmp_path / "permission_chain_contexts.json"
    contexts.write_text(
        json.dumps(
            {
                "graph_id": "g",
                "schema_version": "0.1",
                "chains": [
                    {
                        "chain_id": "CHAIN-0001",
                        "seed_targets": [],
                        "nodes": [{"node_id": "signal:a.rdata", "name": "rdata", "module": "a"}],
                        "edges": [],
                        "source_locations": [],
                        "source_snippets": [
                            {
                                "snippet_id": "SNIP-0001",
                                "file": "a.sv",
                                "line_start": 2,
                                "line_end": 2,
                                "node_ids": ["signal:a.rdata"],
                                "edge_ids": [],
                                "code": "2: assign rdata = secret;",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    summary = run_chain_context_analysis(contexts, repo, out, FakeChat(), ChainContextAnalysisConfig())
    assert summary["final_finding_count"] == 1
    assert summary["elapsed_seconds"] >= 0
    assert summary["total_tokens"] == 125
    final_answer = json.loads((out / "final_answer.json").read_text(encoding="utf-8"))
    assert final_answer["findings"][0]["affected_locations"][0]["file"] == "a.sv"
    raw_findings = json.loads((out / "raw_llm_findings.json").read_text(encoding="utf-8"))
    assert raw_findings["raw_llm_findings"][0]["status"] == "accepted"
    assert raw_findings["raw_llm_findings"][0]["raw_llm_analysis"]["finding"]["summary"] == "Missing guard."
    diagnostics = json.loads((out / "module3B_analysis_diagnostics.json").read_text(encoding="utf-8"))
    assert diagnostics["elapsed_seconds"] >= 0
    assert diagnostics["input_tokens"] == 100
    assert diagnostics["output_tokens"] == 25
    assert diagnostics["total_tokens"] == 125
    assert diagnostics["per_chain"][0]["elapsed_seconds"] >= 0
    assert diagnostics["per_chain"][0]["started_at"]
    assert diagnostics["per_chain"][0]["completed_at"]
    assert diagnostics["per_chain"][0]["llm"]["token_usage_source"] == "api"
    output = capsys.readouterr().out
    assert "[chain-context][1/1] START graph=g chain=CHAIN-0001" in output
    assert "[chain-context][1/1] ACCEPTED graph=g chain=CHAIN-0001" in output
    assert "tokens=125" in output


def test_chain_context_analysis_keeps_raw_discarded_finding(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.sv").write_text("module a;\nassign rdata = secret;\nendmodule\n", encoding="utf-8")
    contexts = tmp_path / "permission_chain_contexts.json"
    contexts.write_text(
        json.dumps(
            {
                "graph_id": "g",
                "schema_version": "0.1",
                "chains": [
                    {
                        "chain_id": "CHAIN-0001",
                        "seed_targets": [],
                        "nodes": [{"node_id": "signal:a.rdata", "name": "rdata", "module": "a"}],
                        "edges": [],
                        "source_locations": [],
                        "source_snippets": [
                            {
                                "snippet_id": "SNIP-0001",
                                "file": "a.sv",
                                "line_start": 2,
                                "line_end": 2,
                                "node_ids": ["signal:a.rdata"],
                                "edge_ids": [],
                                "code": "2: assign rdata = secret;",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    summary = run_chain_context_analysis(contexts, repo, out, FakeChatNoViolation(), ChainContextAnalysisConfig())

    assert summary["final_finding_count"] == 0
    assert summary["raw_llm_finding_count"] == 1
    final_answer = json.loads((out / "final_answer.json").read_text(encoding="utf-8"))
    assert final_answer["findings"] == []
    raw_findings = json.loads((out / "raw_llm_findings.json").read_text(encoding="utf-8"))
    raw_record = raw_findings["raw_llm_findings"][0]
    assert raw_record["status"] == "discarded"
    assert raw_record["discard_reason"] == "missing_violation_evidence"
    assert raw_record["raw_llm_analysis"]["finding"]["summary"] == "Suspicious permission state."
