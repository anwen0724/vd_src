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

from scripts.analysis.compress_chain_contexts_semantic import KEYWORDS, _richness_score


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Globally compress deduplicated permission chain contexts by information gain and diversity."
    )
    parser.add_argument("--context-root", default="runs/analysis_semantic_dedup_contexts_1049")
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--target-total", type=int, default=800)
    args = parser.parse_args(argv)

    summary = compress_global_diverse(
        context_root=Path(args.context_root),
        out_root=Path(args.out_root),
        target_total=args.target_total,
    )
    print(
        "global_diverse_chains={kept_total}/{original_total} target={target_total} scopes={scope_count}".format(
            **summary
        ),
        flush=True,
    )
    for row in summary["by_scope"]:
        print("{scope}: original={original_chains} kept={kept_chains}".format(**row), flush=True)
    return 0


def compress_global_diverse(*, context_root: Path, out_root: Path, target_total: int = 800) -> dict[str, Any]:
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True)

    candidates = []
    docs: dict[str, dict[str, Any]] = {}
    for repo_dir in sorted(path for path in context_root.iterdir() if path.is_dir()):
        path = repo_dir / "permission_chain_contexts.json"
        if not path.exists():
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        docs[repo_dir.name] = doc
        for index, chain in enumerate(doc.get("chains", [])):
            candidates.append(_candidate(repo_dir.name, index, chain))

    selected = _select(candidates, min(target_total, len(candidates)))
    selected_by_scope: dict[str, set[int]] = {}
    for item in selected:
        selected_by_scope.setdefault(item["scope"], set()).add(item["index"])

    rows = []
    kept_total = 0
    for scope, doc in sorted(docs.items()):
        chains = list(doc.get("chains", []))
        kept = [chain for index, chain in enumerate(chains) if index in selected_by_scope.get(scope, set())]
        kept_total += len(kept)
        out_dir = out_root / scope
        out_dir.mkdir(parents=True)
        out_doc = dict(doc)
        out_doc["chains"] = kept
        (out_dir / "permission_chain_contexts.json").write_text(
            json.dumps(out_doc, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        rows.append({"scope": scope, "original_chains": len(chains), "kept_chains": len(kept)})

    summary = {
        "strategy": "global_information_gain_diversity_pruning",
        "target_total": target_total,
        "scope_count": len(docs),
        "original_total": len(candidates),
        "kept_total": kept_total,
        "removed_total": len(candidates) - kept_total,
        "compression_ratio": kept_total / len(candidates) if candidates else 0,
        "by_scope": rows,
    }
    (out_root / "global_diverse_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return summary


def _select(candidates: list[dict[str, Any]], target_total: int) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    selected_snippets: set[tuple[str, int, int]] = set()
    selected_nodes: set[str] = set()
    selected_edges: set[str] = set()
    selected_modules: set[str] = set()
    selected_keywords: set[str] = set()
    remaining = sorted(candidates, key=lambda item: (-item["richness"], item["scope"], item["index"]))

    while remaining and len(selected) < target_total:
        best_pos = 0
        best_score = None
        for pos, item in enumerate(remaining):
            new_snippets = len(item["snippets"] - selected_snippets)
            new_nodes = len(item["nodes"] - selected_nodes)
            new_edges = len(item["edges"] - selected_edges)
            new_modules = len(item["modules"] - selected_modules)
            new_keywords = len(item["keywords"] - selected_keywords)
            snippet_overlap = _overlap_ratio(item["snippets"], selected_snippets)
            node_overlap = _overlap_ratio(item["nodes"], selected_nodes)
            score = (
                item["richness"]
                + new_snippets * 6.0
                + new_nodes * 1.0
                + new_edges * 0.8
                + new_modules * 3.0
                + new_keywords * 2.0
                - snippet_overlap * 12.0
                - node_overlap * 4.0
            )
            key = (score, new_snippets, new_nodes, item["richness"], -item["index"])
            if best_score is None or key > best_score:
                best_score = key
                best_pos = pos
        chosen = remaining.pop(best_pos)
        selected.append(chosen)
        selected_snippets.update(chosen["snippets"])
        selected_nodes.update(chosen["nodes"])
        selected_edges.update(chosen["edges"])
        selected_modules.update(chosen["modules"])
        selected_keywords.update(chosen["keywords"])
    return selected


def _candidate(scope: str, index: int, chain: dict[str, Any]) -> dict[str, Any]:
    nodes = _node_ids(chain)
    edges = _edge_ids(chain)
    modules = _modules(chain)
    snippets = _snippet_set(chain)
    keywords = _keywords(chain)
    return {
        "scope": scope,
        "index": index,
        "chain": chain,
        "richness": _richness_score(chain),
        "nodes": nodes,
        "edges": edges,
        "modules": modules,
        "snippets": snippets,
        "keywords": keywords,
    }


def _node_ids(chain: dict[str, Any]) -> set[str]:
    return {
        str(node.get("node_id", ""))
        for node in chain.get("nodes", [])
        if isinstance(node, dict) and node.get("node_id")
    }


def _edge_ids(chain: dict[str, Any]) -> set[str]:
    ids = set()
    for edge in chain.get("edges", []):
        if not isinstance(edge, dict):
            continue
        if edge.get("edge_id"):
            ids.add(str(edge["edge_id"]))
        else:
            ids.add(f"{edge.get('src','')}->{edge.get('dst','')}:{edge.get('type','')}")
    return ids


def _modules(chain: dict[str, Any]) -> set[str]:
    modules = set()
    for node in chain.get("nodes", []):
        if isinstance(node, dict) and node.get("module"):
            modules.add(str(node["module"]))
    return modules


def _snippet_set(chain: dict[str, Any]) -> set[tuple[str, int, int]]:
    snippets = set()
    for snippet in chain.get("source_snippets", []):
        try:
            snippets.add(
                (
                    str(snippet.get("file", "")),
                    int(snippet.get("line_start", 0) or 0),
                    int(snippet.get("line_end", 0) or 0),
                )
            )
        except (TypeError, ValueError):
            pass
    return snippets


def _keywords(chain: dict[str, Any]) -> set[str]:
    text = json.dumps(chain, ensure_ascii=False).lower()
    return {keyword for keyword in KEYWORDS if keyword in text}


def _overlap_ratio(left: set[Any], selected: set[Any]) -> float:
    if not left or not selected:
        return 0.0
    return len(left & selected) / len(left)


if __name__ == "__main__":
    raise SystemExit(main())
