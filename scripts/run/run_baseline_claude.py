from __future__ import annotations

import sys
from pathlib import Path


SRC_ROOT = Path(__file__).resolve().parents[2]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from runtime.baseline_batch_runner import BaselineBatchRunner


CONFIG = SRC_ROOT / "configs" / "baseline_hackatdac_claude.yaml"


def main() -> int:
    print(f"[baseline-claude] project_root={SRC_ROOT}", flush=True)
    print(f"[baseline-claude] config={CONFIG}", flush=True)
    batch_dir = BaselineBatchRunner(project_root=SRC_ROOT).run_from_config(CONFIG)
    print(f"[baseline-claude] batch_dir={batch_dir}", flush=True)
    print(f"[baseline-claude] status_file={batch_dir / 'batch_status.jsonl'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
