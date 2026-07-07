import json

from langchain_core.messages import AIMessage

from method.ours.chain_context_analysis.config import ChainContextAnalysisConfig
from method.ours.chain_context_analysis.pipeline import run_chain_context_analysis


class FakeChat:
    def invoke(self, _messages):
        return AIMessage(
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
            )
        )


def test_chain_context_analysis_pipeline(tmp_path):
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
    final_answer = json.loads((out / "final_answer.json").read_text(encoding="utf-8"))
    assert final_answer["findings"][0]["affected_locations"][0]["file"] == "a.sv"
