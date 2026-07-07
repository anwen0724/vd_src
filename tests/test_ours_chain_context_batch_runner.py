from __future__ import annotations

import json
from pathlib import Path

import yaml

from runtime import ours_chain_context_batch_runner as batch_module
from runtime.ours_chain_context_batch_runner import OursChainContextBatchRunner


def test_ours_chain_context_batch_runner_resolves_context_and_repo_paths(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scope_id = "hackatdac21__h21_access_lock_scope"
    repo = tmp_path / "datasets" / "agent_inputs" / "hackatdac21" / "h21_access_lock_scope"
    repo.mkdir(parents=True)
    context_file = tmp_path / "runs" / "module3B_permission_chain_contexts" / scope_id / "permission_chain_contexts.json"
    context_file.parent.mkdir(parents=True)
    context_file.write_text(json.dumps({"graph_id": scope_id, "chains": []}), encoding="utf-8")
    config_path = tmp_path / "configs" / "ours_chain_context.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        yaml.safe_dump(
            {
                "batch_id": "ours_test",
                "method_name": "ours_chain_context",
                "context_root": "runs/module3B_permission_chain_contexts",
                "output_root": "runs/ours_chain_context",
                "repetitions": 1,
                "temperature": 0.2,
                "max_tokens": 8192,
                "models": [{"model_id": "deepseek", "provider": "deepseek", "model": "deepseek-v4-pro"}],
                "input_scopes": [
                    {
                        "scope_id": scope_id,
                        "path": "datasets/agent_inputs/hackatdac21/h21_access_lock_scope",
                    }
                ],
            },
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    captured = []

    class FakeRunner:
        def __init__(self, project_root):
            self.project_root = project_root

        def run(self, config):
            captured.append(config)
            run_dir = tmp_path / config.output_dir / config.run_id
            run_dir.mkdir(parents=True)
            return batch_module.OursChainContextRunRecord(
                run_id=config.run_id,
                run_dir=str(run_dir),
                final_answer_path=str(run_dir / "final_answer.md"),
                final_findings_path=str(run_dir / "final_answer.json"),
                diagnostics_path=str(run_dir / "diagnostics.json"),
                run_metadata_path=str(run_dir / "run_metadata.json"),
            )

    monkeypatch.setattr(batch_module, "OursChainContextRunner", FakeRunner)

    batch_dir = OursChainContextBatchRunner(project_root=tmp_path).run_from_config(config_path)

    assert len(captured) == 1
    run_config = captured[0]
    assert Path(run_config.context_path) == context_file
    assert Path(run_config.repo_path) == repo
    assert "experiments" not in str(run_config.repo_path)
    status_rows = [
        json.loads(line)
        for line in (batch_dir / "batch_status.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert status_rows[0]["status"] == "success"
    assert status_rows[0]["context_path"] == str(context_file)
    assert status_rows[0]["elapsed_seconds"] >= 0


def test_ours_chain_context_configs_use_agent_inputs() -> None:
    src_root = Path(__file__).resolve().parents[1]
    for config_name in [
        "ours_chain_context_deepseek.yaml",
        "ours_chain_context_gpt.yaml",
        "ours_chain_context_gemini.yaml",
        "ours_chain_context_claude.yaml",
    ]:
        config_path = src_root / "configs" / config_name
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))

        assert raw["method_name"] == "ours_chain_context"
        assert raw["context_root"] == "runs/analysis_semantic_dedup_contexts_1049"
        assert raw["output_root"] == "runs/ours_chain_context"
        assert len(raw["input_scopes"]) == 15
        assert all(str(scope["path"]).startswith("datasets/agent_inputs/") for scope in raw["input_scopes"])
        assert all("experiments" not in str(scope["path"]) for scope in raw["input_scopes"])


def test_ours_chain_context_deepseek_config_points_to_existing_inputs_and_contexts() -> None:
    src_root = Path(__file__).resolve().parents[1]
    runner = OursChainContextBatchRunner(project_root=src_root)
    config = runner.load_config(src_root / "configs" / "ours_chain_context_deepseek.yaml")

    runner._validate_config(config)


def test_ours_chain_context_claude_config_uses_claude_provider() -> None:
    src_root = Path(__file__).resolve().parents[1]
    raw = yaml.safe_load((src_root / "configs" / "ours_chain_context_claude.yaml").read_text(encoding="utf-8"))

    assert raw["batch_id"] == "ours_chain_context_claude"
    assert len(raw["models"]) == 1
    assert raw["models"][0]["provider"] == "claude"
    assert raw["models"][0]["model_id"]
    assert raw["models"][0]["model"]
