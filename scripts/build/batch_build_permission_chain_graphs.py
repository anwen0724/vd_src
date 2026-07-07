from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[2]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from method.ours.permission_chain_graphs.config import PermissionChainGraphConfig
from method.ours.permission_chain_graphs.pipeline import build_permission_chain_graphs


DEFAULT_GRAPHS_ROOT = SRC_ROOT / "runs" / "module1_rtl_structure_graphs"
DEFAULT_TARGETS_ROOT = SRC_ROOT / "runs" / "module2_1_permission_check_targets"
DEFAULT_EXPERIMENTS_ROOT = SRC_ROOT.parent / "experiments"
DEFAULT_OUT_ROOT = SRC_ROOT / "runs" / "module2_chain_graphs"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch build graph-only permission chain artifacts.")
    parser.add_argument("--graphs-root", default=str(DEFAULT_GRAPHS_ROOT))
    parser.add_argument("--targets-root", default=str(DEFAULT_TARGETS_ROOT))
    parser.add_argument("--experiments-root", default=str(DEFAULT_EXPERIMENTS_ROOT))
    parser.add_argument("--out-root", default=str(DEFAULT_OUT_ROOT))
    parser.add_argument("--max-chains-per-repo", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=4)
    args = parser.parse_args(argv)

    graphs_root = Path(args.graphs_root)
    targets_root = Path(args.targets_root)
    experiments_root = Path(args.experiments_root)
    out_root = Path(args.out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    manifest = []
    for graph_dir in sorted(path for path in graphs_root.iterdir() if path.is_dir()):
        scope = graph_dir.name
        graph = graph_dir / "rtl_structure_graph.json"
        targets = targets_root / scope / "permission_check_targets.json"
        out = out_root / scope
        try:
            summary = build_permission_chain_graphs(
                graph_path=graph,
                targets_path=targets,
                repo_root=resolve_repo_root(scope, experiments_root),
                output_dir=out,
                config=PermissionChainGraphConfig(
                    max_chains_per_repo=args.max_chains_per_repo,
                    max_depth=args.max_depth,
                ),
            )
            summary["scope"] = scope
            summary["status"] = "ok"
            manifest.append(summary)
            print(
                "[ok] {scope}: chains={chain_count} nodes={node_count} edges={edge_count} source_locations={source_location_count} invalid_locs={invalid_source_location_count}".format(
                    **summary
                ),
                flush=True,
            )
        except Exception as exc:  # pragma: no cover - batch failure path
            manifest.append({"scope": scope, "status": "failed", "error": str(exc)})
            print(f"[failed] {scope}: {exc}", flush=True)
    (out_root / "manifest.json").write_text(json.dumps({"runs": manifest}, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if all(item["status"] == "ok" for item in manifest) else 1


def resolve_repo_root(scope: str, experiments_root: Path) -> Path:
    if "__" not in scope:
        raise ValueError(f"Cannot resolve repo root for scope: {scope}")
    benchmark, case_name = scope.split("__", 1)
    return experiments_root / f"baseline_{benchmark}" / "agent_input" / case_name


if __name__ == "__main__":
    raise SystemExit(main())
