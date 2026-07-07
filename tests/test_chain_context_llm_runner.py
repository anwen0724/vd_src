import json
from types import SimpleNamespace

from method.ours.chain_context_analysis.llm_runner import analyze_chain_plain_json


class FakeClaudeBlocks:
    def invoke(self, _messages):
        return SimpleNamespace(
            content=[
                {"type": "thinking", "thinking": "internal reasoning that should be ignored"},
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "chain_id": "CHAIN-0001",
                            "has_finding": False,
                            "finding": None,
                            "no_finding_reason": "No violation evidence.",
                        }
                    ),
                },
            ],
            usage_metadata={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        )


class FakeInvalidJson:
    def invoke(self, _messages):
        return SimpleNamespace(content="not json", usage_metadata={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})


def test_analyze_chain_plain_json_accepts_claude_content_blocks():
    analysis, diagnostics = analyze_chain_plain_json(FakeClaudeBlocks(), "prompt")

    assert analysis is not None
    assert analysis.chain_id == "CHAIN-0001"
    assert analysis.has_finding is False
    assert diagnostics["status"] == "ok"
    assert diagnostics["raw_response_excerpt"].startswith("{")
    assert "internal reasoning" not in diagnostics["raw_response_excerpt"]


def test_analyze_chain_plain_json_records_json_extract_failure():
    analysis, diagnostics = analyze_chain_plain_json(FakeInvalidJson(), "prompt")

    assert analysis is None
    assert diagnostics["status"] == "failed"
    assert diagnostics["failure_stage"] == "json_extract"
    assert diagnostics["raw_response_excerpt"] == "not json"
