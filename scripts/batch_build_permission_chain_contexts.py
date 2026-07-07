from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from method.ours.permission_chain_contexts.config import PermissionChainContextConfig
from method.ours.permission_chain_contexts.pipeline import build_permission_chain_contexts


DEFAULT_CHAIN_ROOT = SRC_ROOT / "runs" / "module2_chain_graphs"
DEFAULT_EXPERIMENTS_ROOT = SRC_ROOT.parent / "experiments"
DEFAULT_OUT_ROOT = SRC_ROOT / "runs" / "module2B_permission_chain_contexts"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch build Scheme B permission chain contexts.")
    parser.add_argument("--chain-root", default=str(DEFAULT_CHAIN_ROOT))
    parser.add_argument("--experiments-root", default=str(DEFAULT_EXPERIMENTS_ROOT))
    parser.add_argument("--out-root", default=str(DEFAULT_OUT_ROOT))
    parser.add_argument("--max-snippets-per-chain", type=int, default=80)
    args = parser.parse_args(argv)
    out_root = Path(args.out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    manifest = []
    for repo_dir in sorted(path for path in Path(args.chain_root).iterdir() if path.is_dir()):
        scope = repo_dir.name
        try:
            summary = build_permission_chain_contexts(
                chain_graphs_path=repo_dir / "permission_chain_graphs.json",
                repo_root=resolve_repo_root(scope, Path(args.experiments_root)),
                output_dir=out_root / scope,
                config=PermissionChainContextConfig(max_snippets_per_chain=args.max_snippets_per_chain),
            )
            summary["scope"] = scope
            summary["status"] = "ok"
            manifest.append(summary)
            print(
                "[ok] {scope}: chains={chain_count} snippets={snippet_count} invalid_snippets={invalid_snippet_count}".format(
                    **summary
                ),
                flush=True,
            )
        except Exception as exc:  # pragma: no cover
            manifest.append({"scope": scope, "status": "failed", "error": str(exc)})
            print(f"[failed] {scope}: {exc}", flush=True)
    (out_root / "manifest.json").write_text(json.dumps({"runs": manifest}, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if all(item["status"] == "ok" for item in manifest) else 1


def resolve_repo_root(scope: str, experiments_root: Path) -> Path:
    benchmark, case_name = scope.split("__", 1)
    return experiments_root / f"baseline_{benchmark}" / "agent_input" / case_name


if __name__ == "__main__":
    raise SystemExit(main())

