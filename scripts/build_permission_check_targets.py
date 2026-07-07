from __future__ import annotations

import argparse
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from method.ours.permission_check_targets.builder import build_permission_check_targets
from method.ours.permission_check_targets.config import PermissionTargetConfig
from method.ours.permission_check_targets.writer import write_permission_target_outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build module-2.1 permission check targets.")
    parser.add_argument("--graph", required=True, help="Path to rtl_structure_graph.json.")
    parser.add_argument("--out", required=True, help="Output directory.")
    parser.add_argument("--max-targets-per-repo", type=int, default=160)
    parser.add_argument("--max-targets-per-module", type=int, default=80)
    parser.add_argument("--max-accesses-per-target", type=int, default=12)
    parser.add_argument("--max-source-locs-per-target", type=int, default=16)
    args = parser.parse_args(argv)

    config = PermissionTargetConfig(
        max_targets_per_repo=args.max_targets_per_repo,
        max_targets_per_module=args.max_targets_per_module,
        max_accesses_per_target=args.max_accesses_per_target,
        max_source_locs_per_target=args.max_source_locs_per_target,
    )
    result = build_permission_check_targets(args.graph, config)
    write_permission_target_outputs(result.targets, result.diagnostics, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
