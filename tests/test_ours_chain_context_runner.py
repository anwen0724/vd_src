from __future__ import annotations

import json
from pathlib import Path

from langchain_core.messages import AIMessage

from runtime import ours_chain_context_runner as runner_module
from runtime.ours_chain_context_runner import OursChainContextRunConfig, OursChainContextRunner


class FakeChat:
    def invoke(self, _messages):
        return AIMessage(
            content=json.dumps(
                {
                    "chain_id": "CHAIN-0001",
                    "has_finding": False,
                    "finding": None,
                    "no_finding_reason": "No violation evidence in the provided context.",
                }
            )
        )


def test_ours_chain_context_runner_writes_metadata_and_pipeline_outputs(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "top.sv").write_text("module top; endmodule\n", encoding="utf-8")
    contexts = tmp_path / "contexts.json"
    contexts.write_text(
        json.dumps(
            {
                "graph_id": "scope",
                "schema_version": "0.1",
                "chains": [
                    {
                        "chain_id": "CHAIN-0001",
                        "seed_targets": [],
                        "nodes": [],
                        "edges": [],
                        "source_locations": [],
                        "source_snippets": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(runner_module, "create_chat_model", lambda _config: FakeChat())

    record = OursChainContextRunner(project_root=tmp_path).run(
        OursChainContextRunConfig(
            run_id="rep_1",
            provider="deepseek",
            model="deepseek-v4-pro",
            context_path=str(contexts),
            repo_path=str(repo),
            output_dir="runs/ours_chain_context/test",
        )
    )

    run_dir = Path(record.run_dir)
    assert (run_dir / "final_answer.json").exists()
    assert (run_dir / "final_findings.json").exists()
    assert (run_dir / "module3B_analysis_diagnostics.json").exists()
    metadata = json.loads(Path(record.run_metadata_path).read_text(encoding="utf-8"))
    assert metadata["method_name"] == "ours_chain_context"
    assert metadata["context_path"] == str(contexts)
    assert metadata["repo_path"] == str(repo)
    assert metadata["elapsed_seconds"] >= 0
    assert metadata["summary"]["elapsed_seconds"] >= 0
