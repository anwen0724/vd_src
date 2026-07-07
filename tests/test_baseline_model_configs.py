from __future__ import annotations

from pathlib import Path

import yaml

from runtime.baseline_batch_runner import BaselineBatchRunner


def test_baseline_claude_and_gemini_configs_are_loadable() -> None:
    src_root = Path(__file__).resolve().parents[1]
    runner = BaselineBatchRunner(project_root=src_root)

    for config_name, provider in [
        ("baseline_hackatdac_claude.yaml", "claude"),
        ("baseline_hackatdac_gemini.yaml", "gemini"),
    ]:
        config_path = src_root / "configs" / config_name
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        config = runner.load_config(config_path)

        assert raw["method_name"] == "langchain_read_search"
        assert raw["output_root"] == "runs/baseline"
        assert raw["models"][0]["provider"] == provider
        assert len(raw["input_scopes"]) == 15
        assert all(str(scope["path"]).startswith("datasets/agent_inputs/") for scope in raw["input_scopes"])
        assert all("experiments" not in str(scope["path"]) for scope in raw["input_scopes"])
        runner._validate_config(config)
