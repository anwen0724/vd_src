import json

from langchain_core.messages import AIMessage

from method.ours.tool_guided_chain_analysis.config import ToolGuidedChainAnalysisConfig
from method.ours.tool_guided_chain_analysis.pipeline import run_tool_guided_chain_analysis


class FakeChat:
    def __init__(self):
        self.calls = 0

    def invoke(self, _messages):
        self.calls += 1
        if self.calls == 1:
            return AIMessage(
                content=json.dumps(
                    {
                        "chain_id": "CHAIN-0001",
                        "actions": [
                            {
                                "tool": "read_around",
                                "file": "a.sv",
                                "line_start": 2,
                                "line_end": 2,
                                "reason": "inspect assignment",
                            }
                        ],
                    }
                )
            )
        return AIMessage(
            content=json.dumps(
                {
                    "chain_id": "CHAIN-0001",
                    "has_finding": True,
                    "finding": {
                        "summary": "Missing guard.",
                        "evidence": [
                            {
                                "file": "a.sv",
                                "line_start": 2,
                                "line_end": 2,
                                "module": "a",
                                "object": "rdata",
                                "evidence_role": "violation",
                                "description": "No guard.",
                                "supports_claim": "Direct assignment.",
                            }
                        ],
                        "reasoning_summary": "The read data is assigned directly.",
                        "security_impact": "Unauthorized read.",
                        "confidence": "medium",
                        "uncertainty_or_missing_evidence": "",
                    },
                    "no_finding_reason": "",
                }
            )
        )


def test_tool_guided_pipeline_writes_trace_and_answer(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.sv").write_text("module a;\nassign rdata = secret;\nendmodule\n", encoding="utf-8")
    chains = tmp_path / "permission_chain_graphs.json"
    chains.write_text(
        json.dumps(
            {
                "graph_id": "g",
                "schema_version": "0.1",
                "chains": [
                    {
                        "chain_id": "CHAIN-0001",
                        "seed_targets": [],
                        "nodes": [],
                        "edges": [],
                        "source_locations": [
                            {
                                "loc_id": "LOC-0001",
                                "file": "a.sv",
                                "line_start": 2,
                                "line_end": 2,
                                "node_ids": [],
                                "edge_ids": [],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    summary = run_tool_guided_chain_analysis(chains, repo, out, FakeChat(), ToolGuidedChainAnalysisConfig())
    assert summary["final_finding_count"] == 1
    assert summary["tool_call_count"] == 1
    assert (out / "tool_trace.jsonl").read_text(encoding="utf-8")
