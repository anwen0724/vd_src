"""Preflight checks before running the baseline Hack@DAC pilot."""

from __future__ import annotations

import csv
import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from llm.env import get_first_env
    from runtime.baseline_batch_runner import BaselineBatchRunner

    runner = BaselineBatchRunner(project_root=project_root)
    config_path = project_root / "configs/baseline_hackatdac_deepseek_gpt_pilot.yaml"
    cfg = runner.load_config(config_path)
    runner._validate_config(cfg)

    print("CONFIG_OK")
    print(f"batch_id={cfg.batch_id}")
    print(f"method_name={cfg.method_name}")
    print(f"repetitions={cfg.repetitions}")
    print(f"max_steps={cfg.max_steps}")
    print(f"max_tokens={cfg.max_tokens}")
    print(f"total_runs={len(cfg.models) * len(cfg.input_scopes) * cfg.repetitions}")

    print("MODELS")
    for model in cfg.models:
        print(f"- {model.model_id}: provider={model.provider}, model={model.model}")

    print("INPUT_SCOPES")
    for scope in cfg.input_scopes:
        scope_path = project_root / scope.path
        file_count = sum(1 for path in scope_path.rglob("*") if path.is_file())
        print(f"- {scope.scope_id}: files={file_count}, path={scope.path}")

    print("GT_MAPS")
    for benchmark in ["hackatdac18", "hackatdac19", "hackatdac21"]:
        gt_path = project_root / "datasets" / "benchmarks" / benchmark / "input_scope_gt_map.csv"
        rows = list(csv.DictReader(gt_path.open("r", encoding="utf-8-sig", newline="")))
        print(f"- {benchmark}: rows={len(rows)}, exists={gt_path.exists()}")

    print("ENV")
    checks = {
        "OPENAI_API_KEY": get_first_env("V3_OPENAI_API_KEY", "OPENAI_API_KEY"),
        "OPENAI_BASE_URL": get_first_env("V3_OPENAI_BASE_URL", "OPENAI_BASE_URL"),
        "DEEPSEEK_API_KEY": get_first_env("V3_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"),
        "DEEPSEEK_BASE_URL": get_first_env("V3_DEEPSEEK_BASE_URL", "DEEPSEEK_BASE_URL"),
    }
    for name, value in checks.items():
        print(f"- {name}: {'set' if value else 'missing'}")
    if any(value is None for value in checks.values()):
        raise RuntimeError("Missing required API environment variable.")

    import langchain_openai  # noqa: F401
    import pydantic  # noqa: F401
    import yaml  # noqa: F401

    print("DEPS_OK")
    print("PREFLIGHT_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
