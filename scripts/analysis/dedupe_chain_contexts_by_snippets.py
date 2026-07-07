from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deduplicate permission chain contexts by source snippet ranges.")
    parser.add_argument("--context-root", default="runs/module3B_permission_chain_contexts")
    parser.add_argument("--out-root", required=True)
    args = parser.parse_args(argv)

    summary = dedupe_contexts(Path(args.context_root), Path(args.out_root))
    print(
        "deduped_chains={kept_total}/{original_total} scopes={scope_count}".format(**summary),
        flush=True,
    )
    return 0


def dedupe_contexts(context_root: Path, out_root: Path) -> dict[str, Any]:
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True)

    rows = []
    original_total = 0
    kept_total = 0
    for repo_dir in sorted(path for path in context_root.iterdir() if path.is_dir()):
        in_path = repo_dir / "permission_chain_contexts.json"
        if not in_path.exists():
            continue
        doc = json.loads(in_path.read_text(encoding="utf-8"))
        kept = []
        seen = set()
        for chain in doc.get("chains", []):
            signature = _snippet_signature(chain)
            if signature in seen:
                continue
            seen.add(signature)
            kept.append(chain)
        out_dir = out_root / repo_dir.name
        out_dir.mkdir(parents=True)
        out_doc = dict(doc)
        out_doc["chains"] = kept
        (out_dir / "permission_chain_contexts.json").write_text(
            json.dumps(out_doc, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        original_total += len(doc.get("chains", []))
        kept_total += len(kept)
        rows.append({"scope": repo_dir.name, "original_chains": len(doc.get("chains", [])), "kept_chains": len(kept)})

    summary = {
        "strategy": "dedupe_by_source_snippet_ranges",
        "scope_count": len(rows),
        "original_total": original_total,
        "kept_total": kept_total,
        "removed_total": original_total - kept_total,
        "compression_ratio": kept_total / original_total if original_total else 0,
        "by_scope": rows,
    }
    (out_root / "dedupe_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


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
