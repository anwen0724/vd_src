"""Run the proposed-method Hack@DAC pilot batch."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the proposed-method Hack@DAC pilot batch.")
    parser.add_argument(
        "--config",
        default="configs/proposed_hackatdac_gpt_pilot.yaml",
        help="Batch config path relative to src/.",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from runtime.proposed_batch_runner import ProposedBatchRunner

    config_path = project_root / args.config
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    print(f"[proposed] project_root = {project_root}", flush=True)
    print(f"[proposed] config       = {config_path}", flush=True)
    print("[proposed] starting batch run...", flush=True)

    output_dir = ProposedBatchRunner(project_root=project_root).run_from_config(config_path)

    print("[proposed] batch run finished.", flush=True)
    print(f"[proposed] output_dir   = {output_dir}", flush=True)
    print(f"[proposed] status_file  = {output_dir / 'batch_status.jsonl'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
