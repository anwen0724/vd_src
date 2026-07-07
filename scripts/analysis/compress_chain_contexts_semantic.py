from __future__ import annotations

import argparse
import json
import math
import shutil
from pathlib import Path
from typing import Any


KEYWORDS = {
    "access",
    "auth",
    "cfg",
    "control",
    "crypto",
    "csr",
    "debug",
    "dma",
    "fuse",
    "jtag",
    "key",
    "lock",
    "permission",
    "pmp",
    "priv",
    "protect",
    "reglock",
    "reset",
    "secret",
    "secure",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compress permission chain contexts without GT using semantic-richness ranking and diversity."
    )
    parser.add_argument("--context-root", default="runs/module3B_permission_chain_contexts")
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--target-total", type=int, default=800)
    parser.add_argument("--min-per-scope", type=int, default=20)
    args = parser.parse_args(argv)

    summary = compress_semantic_contexts(
        context_root=Path(args.context_root),
        out_root=Path(args.out_root),
        target_total=args.target_total,
        min_per_scope=args.min_per_scope,
    )
    print(
        "semantic_compressed_chains={kept_total}/{original_total} target={target_total} scopes={scope_count}".format(
            **summary
        ),
        flush=True,
    )
    for row in summary["by_scope"]:
        print(
            "{scope}: original={original_chains} dedup={semantic_dedup_chains} kept={kept_chains}".format(**row),
            flush=True,
        )
    return 0


def compress_semantic_contexts(
    *,
    context_root: Path,
    out_root: Path,
    target_total: int = 800,
    min_per_scope: int = 20,
) -> dict[str, Any]:
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True)

    scope_docs: list[dict[str, Any]] = []
    original_total = 0
    semantic_dedup_total = 0
    for repo_dir in sorted(path for path in context_root.iterdir() if path.is_dir()):
        in_path = repo_dir / "permission_chain_contexts.json"
        if not in_path.exists():
            continue
        doc = json.loads(in_path.read_text(encoding="utf-8"))
        chains = list(doc.get("chains", []))
        original_total += len(chains)
        deduped = _semantic_deduplicate(chains)
        semantic_dedup_total += len(deduped)
        scope_docs.append({"scope": repo_dir.name, "doc": doc, "original": len(chains), "chains": deduped})

    budgets = _allocate_budgets(scope_docs, target_total=target_total, min_per_scope=min_per_scope)
    kept_total = 0
    rows = []
    for item in scope_docs:
        scope = item["scope"]
        chains = item["chains"]
        budget = budgets.get(scope, len(chains))
        kept = _select_diverse(chains, budget)
        kept_total += len(kept)

        out_dir = out_root / scope
        out_dir.mkdir(parents=True)
        out_doc = dict(item["doc"])
        out_doc["chains"] = kept
        (out_dir / "permission_chain_contexts.json").write_text(
            json.dumps(out_doc, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        rows.append(
            {
                "scope": scope,
                "original_chains": item["original"],
                "semantic_dedup_chains": len(chains),
                "kept_chains": len(kept),
                "budget": budget,
            }
        )

    summary = {
        "strategy": "semantic_richest_duplicate_representative_then_diverse_selection",
        "target_total": target_total,
        "min_per_scope": min_per_scope,
        "scope_count": len(scope_docs),
        "original_total": original_total,
        "semantic_dedup_total": semantic_dedup_total,
        "kept_total": kept_total,
        "removed_total": original_total - kept_total,
        "compression_ratio": kept_total / original_total if original_total else 0,
        "by_scope": rows,
    }
    (out_root / "semantic_compression_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return summary


def _semantic_deduplicate(chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best_by_signature: dict[tuple[tuple[str, int, int], ...], tuple[float, int, dict[str, Any]]] = {}
    for index, chain in enumerate(chains):
        signature = _snippet_signature(chain)
        score = _richness_score(chain)
        existing = best_by_signature.get(signature)
        if existing is None or score > existing[0] or (score == existing[0] and index < existing[1]):
            best_by_signature[signature] = (score, index, chain)
    return [item[2] for item in sorted(best_by_signature.values(), key=lambda value: value[1])]


def _allocate_budgets(
    scope_docs: list[dict[str, Any]],
    *,
    target_total: int,
    min_per_scope: int,
) -> dict[str, int]:
    total_available = sum(len(item["chains"]) for item in scope_docs)
    if total_available <= target_total:
        return {item["scope"]: len(item["chains"]) for item in scope_docs}

    scope_count = len(scope_docs)
    min_total = min_per_scope * scope_count
    if min_total > target_total:
        min_per_scope = max(1, target_total // max(1, scope_count))
        min_total = min_per_scope * scope_count

    remaining_target = target_total - min_total
    capacities = {item["scope"]: max(0, len(item["chains"]) - min_per_scope) for item in scope_docs}
    total_capacity = sum(capacities.values())
    budgets = {item["scope"]: min(min_per_scope, len(item["chains"])) for item in scope_docs}
    if remaining_target <= 0 or total_capacity <= 0:
        return budgets

    fractional: list[tuple[str, float]] = []
    allocated = 0
    for item in scope_docs:
        scope = item["scope"]
        share = remaining_target * capacities[scope] / total_capacity
        whole = math.floor(share)
        budgets[scope] += whole
        allocated += whole
        fractional.append((scope, share - whole))

    leftover = remaining_target - allocated
    for scope, _fraction in sorted(fractional, key=lambda pair: pair[1], reverse=True):
        if leftover <= 0:
            break
        if budgets[scope] < min_per_scope + capacities[scope]:
            budgets[scope] += 1
            leftover -= 1
    return budgets


def _select_diverse(chains: list[dict[str, Any]], budget: int) -> list[dict[str, Any]]:
    if len(chains) <= budget:
        return chains
    scored = sorted(
        ((index, chain, _richness_score(chain), _snippet_set(chain)) for index, chain in enumerate(chains)),
        key=lambda item: (-item[2], item[0]),
    )
    selected: list[tuple[int, dict[str, Any], float, set[tuple[str, int, int]]]] = []
    selected_snippets: set[tuple[str, int, int]] = set()
    remaining = scored.copy()
    while remaining and len(selected) < budget:
        best_pos = 0
        best_key = None
        for pos, item in enumerate(remaining):
            index, _chain, score, snippets = item
            new_snippets = len(snippets - selected_snippets)
            overlap = _max_jaccard(snippets, [chosen[3] for chosen in selected])
            key = (new_snippets, -overlap, score, -index)
            if best_key is None or key > best_key:
                best_key = key
                best_pos = pos
        chosen = remaining.pop(best_pos)
        selected.append(chosen)
        selected_snippets.update(chosen[3])
    return [item[1] for item in sorted(selected, key=lambda value: value[0])]


def _richness_score(chain: dict[str, Any]) -> float:
    snippets = chain.get("source_snippets", [])
    nodes = chain.get("nodes", [])
    edges = chain.get("edges", [])
    seed_targets = chain.get("seed_targets", [])
    files = {str(snippet.get("file", "")) for snippet in snippets if snippet.get("file")}
    modules = {
        str(node.get("module", ""))
        for node in nodes
        if isinstance(node, dict) and node.get("module")
    }
    text = json.dumps(chain, ensure_ascii=False).lower()
    keyword_hits = sum(1 for keyword in KEYWORDS if keyword in text)
    code_chars = sum(len(str(snippet.get("code", ""))) for snippet in snippets)
    loc_span = sum(
        max(0, int(snippet.get("line_end", 0) or 0) - int(snippet.get("line_start", 0) or 0) + 1)
        for snippet in snippets
    )
    return (
        len(snippets) * 3.0
        + len(files) * 4.0
        + len(nodes) * 0.5
        + len(edges) * 0.4
        + len(modules) * 2.0
        + len(seed_targets) * 2.0
        + keyword_hits * 2.5
        + min(code_chars / 500.0, 8.0)
        + min(loc_span / 20.0, 5.0)
    )


def _max_jaccard(left: set[tuple[str, int, int]], others: list[set[tuple[str, int, int]]]) -> float:
    if not left or not others:
        return 0.0
    best = 0.0
    for right in others:
        union = len(left | right)
        if union == 0:
            continue
        best = max(best, len(left & right) / union)
    return best


def _snippet_set(chain: dict[str, Any]) -> set[tuple[str, int, int]]:
    return set(_snippet_signature(chain))


def _snippet_signature(chain: dict[str, Any]) -> tuple[tuple[str, int, int], ...]:
    ranges = []
    for snippet in chain.get("source_snippets", []):
        try:
            ranges.append(
                (
                    str(snippet.get("file", "")),
                    int(snippet.get("line_start", 0) or 0),
                    int(snippet.get("line_end", 0) or 0),
                )
            )
        except (TypeError, ValueError):
            pass
    return tuple(sorted(ranges))


if __name__ == "__main__":
    raise SystemExit(main())
