from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

SRC_ROOT = Path(__file__).resolve().parents[2]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


DEFAULT_CHAIN_ROOT = SRC_ROOT / "runs" / "module2_chain_graphs"
DEFAULT_GT_CSV = SRC_ROOT / "evaluation_results" / "gt_cases.csv"
DEFAULT_GT_ROOT = SRC_ROOT / "datasets" / "benchmarks"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate chain graph source-location coverage against GT evidence.")
    parser.add_argument("--chain-root", default=str(DEFAULT_CHAIN_ROOT))
    parser.add_argument("--gt-csv", default=str(DEFAULT_GT_CSV))
    parser.add_argument("--gt-root", default=str(DEFAULT_GT_ROOT))
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)

    results = evaluate_coverage(Path(args.chain_root), Path(args.gt_csv), Path(args.gt_root))
    out = Path(args.out) if args.out else Path(args.chain_root) / "coverage_summary.json"
    out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print_summary(results)
    return 0


def evaluate_coverage(chain_root: Path, gt_csv: Path, gt_root: Path) -> dict[str, Any]:
    scope_by_case = _load_case_scopes(gt_csv)
    gt = _load_gt_traces(gt_root, scope_by_case)
    locs_by_scope = _load_chain_locations(chain_root)
    case_results = []
    for case_id, info in sorted(gt.items()):
        scope = info["scope"]
        traces = info["traces"]
        locs = locs_by_scope.get(scope, [])
        covered = set()
        hit_chains = set()
        for index, trace in enumerate(traces):
            for loc in locs:
                if _overlaps(trace, loc):
                    covered.add(index)
                    hit_chains.add(loc["chain_id"])
                    break
        case_results.append(
            {
                "case_id": case_id,
                "scope": scope,
                "trace_count": len(traces),
                "covered_trace_count": len(covered),
                "weak_covered": bool(covered),
                "strict_covered": bool(traces) and len(covered) == len(traces),
                "hit_chains": sorted(hit_chains)[:20],
            }
        )
    by_scope = defaultdict(lambda: {"cases": 0, "weak": 0, "strict": 0, "traces": 0, "covered_traces": 0})
    for row in case_results:
        item = by_scope[row["scope"]]
        item["cases"] += 1
        item["weak"] += int(row["weak_covered"])
        item["strict"] += int(row["strict_covered"])
        item["traces"] += row["trace_count"]
        item["covered_traces"] += row["covered_trace_count"]
    return {
        "total_cases": len(case_results),
        "weak_covered_cases": sum(row["weak_covered"] for row in case_results),
        "strict_covered_cases": sum(row["strict_covered"] for row in case_results),
        "covered_traces": sum(row["covered_trace_count"] for row in case_results),
        "total_traces": sum(row["trace_count"] for row in case_results),
        "by_scope": dict(sorted(by_scope.items())),
        "cases": case_results,
    }


def _load_case_scopes(gt_csv: Path) -> dict[str, str]:
    result = {}
    with gt_csv.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            result[row["case_id"]] = _scope_to_dir(row["benchmark_id"], row["input_scope"])
    return result


def _load_gt_traces(gt_root: Path, scope_by_case: dict[str, str]) -> dict[str, dict[str, Any]]:
    result = {}
    for path in gt_root.glob("*/evidence_gt.jsonl"):
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            case_id = obj.get("case_id")
            if case_id not in scope_by_case:
                continue
            traces = []
            for item in obj.get("evidence_trace", []) or []:
                try:
                    traces.append(
                        {
                            "file": _normalize_file(item.get("file", "")),
                            "line_start": int(item.get("line_start")),
                            "line_end": int(item.get("line_end")),
                        }
                    )
                except (TypeError, ValueError):
                    pass
            result[case_id] = {"scope": scope_by_case[case_id], "traces": traces}
    return result


def _load_chain_locations(chain_root: Path) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for repo_dir in chain_root.iterdir():
        if not repo_dir.is_dir():
            continue
        path = repo_dir / "permission_chain_graphs.json"
        if not path.exists():
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        for chain in doc.get("chains", []):
            for loc in chain.get("source_locations", []):
                try:
                    result[repo_dir.name].append(
                        {
                            "chain_id": chain.get("chain_id"),
                            "file": _normalize_file(loc.get("file", "")),
                            "line_start": int(loc.get("line_start")),
                            "line_end": int(loc.get("line_end")),
                        }
                    )
                except (TypeError, ValueError):
                    pass
    return result


def _scope_to_dir(benchmark: str, input_scope: str) -> str:
    scope = input_scope
    if benchmark == "hackatdac18" and scope.startswith("h18_"):
        scope = scope.removeprefix("h18_")
    return f"{benchmark}__{scope}"


def _normalize_file(path: str) -> str:
    value = str(path).replace("\\", "/").lstrip("./")
    parts = value.split("/")
    if len(parts) >= 3 and parts[0] == "third_party" and parts[1].startswith("hackatdac"):
        return "/".join(parts[2:])
    return value


def _overlaps(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return left["file"] == right["file"] and max(left["line_start"], right["line_start"]) <= min(
        left["line_end"], right["line_end"]
    )


def print_summary(results: dict[str, Any]) -> None:
    print(
        "total_cases={total_cases} weak={weak_covered_cases} strict={strict_covered_cases} trace={covered_traces}/{total_traces}".format(
            **results
        ),
        flush=True,
    )
    for scope, item in results["by_scope"].items():
        print(
            f"{scope}: cases={item['cases']} weak={item['weak']} strict={item['strict']} trace={item['covered_traces']}/{item['traces']}",
            flush=True,
        )


if __name__ == "__main__":
    raise SystemExit(main())
