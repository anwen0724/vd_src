from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from method.ours.permission_check_targets.builder import build_permission_check_targets
from method.ours.permission_check_targets.config import PermissionTargetConfig
from method.ours.permission_check_targets.writer import write_permission_target_outputs


DEFAULT_GRAPHS_ROOT = SRC_ROOT / "runs" / "module1_rtl_structure_graphs"
DEFAULT_OUT_ROOT = SRC_ROOT / "runs" / "module2_1_permission_check_targets"


def run_batch(
    graphs_root: str | Path = DEFAULT_GRAPHS_ROOT,
    out_root: str | Path = DEFAULT_OUT_ROOT,
    selected_scopes: list[str] | None = None,
    config: PermissionTargetConfig | None = None,
) -> dict[str, Any]:
    root = Path(graphs_root)
    output_root = Path(out_root)
    output_root.mkdir(parents=True, exist_ok=True)
    active_config = config or PermissionTargetConfig()
    selected = set(selected_scopes or [])
    runs: list[dict[str, Any]] = []

    for graph_path in sorted(root.glob("*/rtl_structure_graph.json")):
        scope_id = graph_path.parent.name
        if selected and scope_id not in selected:
            continue
        scope_out = output_root / scope_id
        try:
            result = build_permission_check_targets(graph_path, active_config)
            targets_path, diagnostics_path = write_permission_target_outputs(
                result.targets,
                result.diagnostics,
                scope_out,
            )
            runs.append(
                {
                    "scope_id": scope_id,
                    "graph_path": str(graph_path),
                    "output_dir": str(scope_out),
                    "targets_path": str(targets_path),
                    "diagnostics_path": str(diagnostics_path),
                    "status": "success",
                    "target_count": len(result.targets.targets),
                }
            )
            print(f"[ok] {scope_id} -> {scope_out}", flush=True)
        except Exception as exc:  # pragma: no cover - exercised by manual failure cases.
            runs.append(
                {
                    "scope_id": scope_id,
                    "graph_path": str(graph_path),
                    "output_dir": str(scope_out),
                    "status": "failed",
                    "error": str(exc),
                }
            )
            print(f"[failed] {scope_id}: {exc}", flush=True)

    manifest = {
        "graphs_root": str(root),
        "out_root": str(output_root),
        "total_scopes": len(runs),
        "successful_scopes": sum(1 for run in runs if run["status"] == "success"),
        "failed_scopes": sum(1 for run in runs if run["status"] == "failed"),
        "runs": runs,
    }
    manifest_path = output_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[manifest] {manifest_path}", flush=True)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch build module-2.1 permission check targets.")
    parser.add_argument("--graphs-root", default=str(DEFAULT_GRAPHS_ROOT))
    parser.add_argument("--out-root", default=str(DEFAULT_OUT_ROOT))
    parser.add_argument("--scope", action="append", default=None)
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
    manifest = run_batch(args.graphs_root, args.out_root, args.scope, config)
    return 1 if manifest["failed_scopes"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
