from __future__ import annotations

import argparse
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from scripts.evaluate_chain_graph_coverage import evaluate_coverage, print_summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate Scheme B chain context snippet coverage.")
    parser.add_argument("--context-root", default=str(SRC_ROOT / "runs" / "module2B_permission_chain_contexts"))
    parser.add_argument("--gt-csv", default=str(SRC_ROOT / "evaluation_results" / "gt_cases.csv"))
    parser.add_argument("--gt-root", default=str(SRC_ROOT / "datasets" / "benchmarks"))
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    # Reuse the evaluator by creating a source-location view from source_snippets in memory.
    results = evaluate_context_coverage(Path(args.context_root), Path(args.gt_csv), Path(args.gt_root))
    out = Path(args.out) if args.out else Path(args.context_root) / "coverage_summary.json"
    import json

    out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print_summary(results)
    return 0


def evaluate_context_coverage(context_root: Path, gt_csv: Path, gt_root: Path):
    import json
    import tempfile

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        for repo_dir in context_root.iterdir():
            if not repo_dir.is_dir():
                continue
            path = repo_dir / "permission_chain_contexts.json"
            if not path.exists():
                continue
            doc = json.loads(path.read_text(encoding="utf-8"))
            chains = []
            for chain in doc.get("chains", []):
                chains.append(
                    {
                        "chain_id": chain.get("chain_id"),
                        "source_locations": [
                            {
                                "loc_id": snippet.get("snippet_id"),
                                "file": snippet.get("file"),
                                "line_start": snippet.get("line_start"),
                                "line_end": snippet.get("line_end"),
                                "node_ids": snippet.get("node_ids", []),
                                "edge_ids": snippet.get("edge_ids", []),
                            }
                            for snippet in chain.get("source_snippets", [])
                        ],
                    }
                )
            out_dir = temp_root / repo_dir.name
            out_dir.mkdir()
            (out_dir / "permission_chain_graphs.json").write_text(
                json.dumps({"graph_id": doc.get("graph_id"), "schema_version": doc.get("schema_version"), "chains": chains}),
                encoding="utf-8",
            )
        return evaluate_coverage(temp_root, gt_csv, gt_root)


if __name__ == "__main__":
    raise SystemExit(main())
