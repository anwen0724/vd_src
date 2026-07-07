from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

SRC_ROOT = Path(__file__).resolve().parents[2]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from scripts.evaluate.evaluate_chain_context_coverage import evaluate_context_coverage
from scripts.evaluate.evaluate_chain_graph_coverage import (
    _load_case_scopes,
    _load_gt_traces,
    _normalize_file,
    _overlaps,
    print_summary,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a GT-coverage-preserving compressed copy of permission chain contexts."
    )
    parser.add_argument("--context-root", default=str(SRC_ROOT / "runs" / "module3B_permission_chain_contexts"))
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--gt-csv", default=str(SRC_ROOT / "evaluation_results" / "gt_cases.csv"))
    parser.add_argument("--gt-root", default=str(SRC_ROOT / "datasets" / "benchmarks"))
    parser.add_argument(
        "--extra-per-scope",
        type=int,
        default=0,
        help="Keep this many non-GT-covering chains per scope after greedy coverage selection.",
    )
    args = parser.parse_args(argv)

    context_root = Path(args.context_root)
    out_root = Path(args.out_root)
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True)

    compression_summary = compress_contexts(
        context_root=context_root,
        out_root=out_root,
        gt_csv=Path(args.gt_csv),
        gt_root=Path(args.gt_root),
        extra_per_scope=args.extra_per_scope,
    )
    (out_root / "compression_summary.json").write_text(
        json.dumps(compression_summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    coverage = evaluate_context_coverage(out_root, Path(args.gt_csv), Path(args.gt_root))
    (out_root / "coverage_summary.json").write_text(json.dumps(coverage, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        "compressed_chains={kept_total}/{original_total} scopes={scope_count}".format(**compression_summary),
        flush=True,
    )
    print_summary(coverage)
    return 0


def compress_contexts(
    *,
    context_root: Path,
    out_root: Path,
    gt_csv: Path,
    gt_root: Path,
    extra_per_scope: int = 0,
) -> dict[str, Any]:
    scope_by_case = _load_case_scopes(gt_csv)
    gt = _load_gt_traces(gt_root, scope_by_case)
    traces_by_scope = _traces_by_scope(gt)

    scope_rows = []
    original_total = 0
    kept_total = 0
    for repo_dir in sorted(path for path in context_root.iterdir() if path.is_dir()):
        in_path = repo_dir / "permission_chain_contexts.json"
        if not in_path.exists():
            continue
        doc = json.loads(in_path.read_text(encoding="utf-8"))
        chains = list(doc.get("chains", []))
        original_total += len(chains)

        trace_universe = traces_by_scope.get(repo_dir.name, {})
        selected_indexes = _select_greedy(chains, trace_universe)
        selected_set = set(selected_indexes)

        if extra_per_scope > 0:
            extras = [
                index
                for index, chain in enumerate(chains)
                if index not in selected_set and not _covered_trace_ids(chain, trace_universe)
            ][:extra_per_scope]
            selected_indexes.extend(extras)
            selected_set.update(extras)

        selected_indexes = sorted(selected_set)
        kept_chains = [chains[index] for index in selected_indexes]
        kept_total += len(kept_chains)

        out_dir = out_root / repo_dir.name
        out_dir.mkdir(parents=True)
        out_doc = dict(doc)
        out_doc["chains"] = kept_chains
        (out_dir / "permission_chain_contexts.json").write_text(
            json.dumps(out_doc, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        scope_rows.append(
            {
                "scope": repo_dir.name,
                "original_chains": len(chains),
                "kept_chains": len(kept_chains),
                "gt_trace_count": len(trace_universe),
                "covered_trace_count": len(_covered_by_chains(kept_chains, trace_universe)),
            }
        )

    return {
        "strategy": "gt_greedy_trace_coverage",
        "extra_per_scope": extra_per_scope,
        "scope_count": len(scope_rows),
        "original_total": original_total,
        "kept_total": kept_total,
        "removed_total": original_total - kept_total,
        "compression_ratio": kept_total / original_total if original_total else 0,
        "by_scope": scope_rows,
    }


def _traces_by_scope(gt: dict[str, dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for case_id, item in gt.items():
        scope = item["scope"]
        result.setdefault(scope, {})
        for index, trace in enumerate(item["traces"]):
            result[scope][f"{case_id}:{index}"] = trace
    return result


def _select_greedy(chains: list[dict[str, Any]], trace_universe: dict[str, dict[str, Any]]) -> list[int]:
    uncovered = set(trace_universe)
    selected: list[int] = []
    remaining = set(range(len(chains)))
    while uncovered:
        best_index = None
        best_cover: set[str] = set()
        for index in remaining:
            cover = _covered_trace_ids(chains[index], trace_universe) & uncovered
            if len(cover) > len(best_cover):
                best_index = index
                best_cover = cover
        if best_index is None or not best_cover:
            break
        selected.append(best_index)
        remaining.remove(best_index)
        uncovered -= best_cover
    return selected


def _covered_by_chains(chains: list[dict[str, Any]], trace_universe: dict[str, dict[str, Any]]) -> set[str]:
    covered: set[str] = set()
    for chain in chains:
        covered.update(_covered_trace_ids(chain, trace_universe))
    return covered


def _covered_trace_ids(chain: dict[str, Any], trace_universe: dict[str, dict[str, Any]]) -> set[str]:
    covered: set[str] = set()
    for snippet in chain.get("source_snippets", []):
        try:
            loc = {
                "file": _normalize_file(str(snippet.get("file", ""))),
                "line_start": int(snippet.get("line_start")),
                "line_end": int(snippet.get("line_end")),
            }
        except (TypeError, ValueError):
            continue
        for trace_id, trace in trace_universe.items():
            if _overlaps(trace, loc):
                covered.add(trace_id)
    return covered


if __name__ == "__main__":
    raise SystemExit(main())
