from __future__ import annotations

import argparse
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from method.ours.permission_chain_contexts.config import PermissionChainContextConfig
from method.ours.permission_chain_contexts.pipeline import build_permission_chain_contexts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build Scheme B permission chain contexts for one repo.")
    parser.add_argument("--chain-graphs", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-snippets-per-chain", type=int, default=80)
    args = parser.parse_args(argv)
    summary = build_permission_chain_contexts(
        chain_graphs_path=args.chain_graphs,
        repo_root=args.repo_root,
        output_dir=args.out,
        config=PermissionChainContextConfig(max_snippets_per_chain=args.max_snippets_per_chain),
    )
    print(
        "[ok] {graph_id}: chains={chain_count} snippets={snippet_count} invalid_snippets={invalid_snippet_count}".format(
            **summary
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

