"""Run the baseline Hack@DAC pilot batch."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the baseline Hack@DAC pilot batch.")
    parser.add_argument(
        "--config",
        default="configs/baseline_hackatdac_deepseek_gpt_pilot.yaml",
        help="Batch config path relative to src/.",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from runtime.baseline_batch_runner import BaselineBatchRunner

    config_path = project_root / args.config
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    print(f"[baseline] project_root = {project_root}", flush=True)
    print(f"[baseline] config       = {config_path}", flush=True)
    print("[baseline] starting batch run...", flush=True)

    output_dir = BaselineBatchRunner(project_root=project_root).run_from_config(config_path)

    print("[baseline] batch run finished.", flush=True)
    print(f"[baseline] output_dir   = {output_dir}", flush=True)
    print(f"[baseline] status_file  = {output_dir / 'batch_status.jsonl'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
