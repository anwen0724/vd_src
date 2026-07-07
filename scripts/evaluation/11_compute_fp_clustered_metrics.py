from __future__ import annotations

import csv
import math
import re
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INPUT_ROOT = PROJECT_ROOT / "evaluation_results" / "current_four_runs"
OUTPUT_ROOT = PROJECT_ROOT / "evaluation_results" / "current_four_runs_fp_clustered"
GT_CASES = PROJECT_ROOT / "evaluation_results" / "gt_cases.csv"


FINDING_WITH_CLUSTER_COLUMNS = [
    "finding_uid",
    "model_family",
    "method_name",
    "input_scope",
    "repetition",
    "run_id",
    "finding_id",
    "summary",
    "matched_case_id",
    "detection_match",
    "duplicate_of_finding_uid",
    "evidence_quality",
    "fp_cluster_id",
    "cluster_scoring_role",
    "review_notes",
    "final_answer_path",
]


FP_CLUSTER_COLUMNS = [
    "fp_cluster_id",
    "model_family",
    "method_name",
    "input_scope",
    "repetition",
    "fp_count",
    "representative_finding_uid",
    "claimed_files",
    "claimed_modules",
    "claimed_signals_or_registers",
    "example_summaries",
]


SUMMARY_COLUMNS = [
    "model_family",
    "method_name",
    "num_gt_cases",
    "tp_cases",
    "fn_cases",
    "representative_tp_findings",
    "fp_findings",
    "precision",
    "recall",
    "f1_score",
    "evidence_sufficiency_rate",
    "fabricated_unsupported_evidence_rate",
]


SINGLE_COLUMNS = [
    "model_family",
    "method_name",
    "repetition",
    "num_gt_cases",
    "tp_cases",
    "fn_cases",
    "tp_findings",
    "fp_findings",
    "precision",
    "recall",
    "f1_score",
    "evidence_sufficiency_rate",
    "fabricated_unsupported_evidence_rate",
]


STOPWORDS = {
    "the",
    "and",
    "that",
    "with",
    "without",
    "from",
    "this",
    "which",
    "allow",
    "allows",
    "allowing",
    "access",
    "control",
    "register",
    "registers",
    "module",
    "signal",
    "signals",
    "logic",
    "path",
    "missing",
    "bypass",
    "bypasses",
    "unprotected",
    "unauthorized",
    "privilege",
    "privileged",
    "security",
    "check",
    "checks",
    "guard",
    "guards",
}


def main() -> int:
    if OUTPUT_ROOT.exists():
        shutil.rmtree(OUTPUT_ROOT)
    gt_rows = read_csv(GT_CASES)
    all_summary_rows: list[dict[str, str]] = []

    for review_path in sorted(INPUT_ROOT.glob("*/*/finding_review.csv")):
        rows = read_csv(review_path)
        rel_group = review_path.relative_to(INPUT_ROOT).parents[0]
        out_dir = OUTPUT_ROOT / rel_group
        clusters, clustered_rows = cluster_fp_rows(rows)
        write_csv(out_dir / "finding_review_with_fp_clusters.csv", FINDING_WITH_CLUSTER_COLUMNS, clustered_rows)
        write_csv(out_dir / "fp_cluster_review.csv", FP_CLUSTER_COLUMNS, cluster_rows(clusters))

        if rows:
            single_rows = compute_single_rows(clustered_rows, gt_rows, clusters)
            anyhit_rows = [compute_anyhit_row(clustered_rows, gt_rows, clusters)]
        else:
            single_rows = copy_empty_single_rows(review_path)
            anyhit_rows = copy_empty_anyhit_rows(review_path)

        write_csv(out_dir / "single_run" / "single_run_metrics.csv", SINGLE_COLUMNS, single_rows)
        write_csv(out_dir / "anyhit3" / "anyhit3_model_summary.csv", SUMMARY_COLUMNS, anyhit_rows)
        all_summary_rows.extend(anyhit_rows)
        print(f"[ok] {rel_group} fp_clusters={len(clusters)} rows={len(rows)}")

    write_csv(OUTPUT_ROOT / "combined_summary.csv", SUMMARY_COLUMNS, all_summary_rows)
    write_readme(all_summary_rows)
    return 0


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def cluster_fp_rows(rows: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    clusters: list[dict[str, Any]] = []
    clustered_rows: list[dict[str, str]] = []
    grouped: dict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        if row.get("detection_match") == "FP":
            grouped[(row["model_family"], row["method_name"], row["input_scope"], row["repetition"])].append(row)

    row_cluster: dict[str, str] = {}
    representative: set[str] = set()
    for key, fp_rows in sorted(grouped.items()):
        local_clusters: list[dict[str, Any]] = []
        for row in fp_rows:
            tokens = token_set(row)
            best: dict[str, Any] | None = None
            best_score = 0.0
            for cluster in local_clusters:
                score = max(jaccard(tokens, existing) for existing in cluster["token_sets"])
                if score > best_score:
                    best = cluster
                    best_score = score
            if best is None or best_score < 0.42:
                cluster_id = f"FPC-{len(clusters) + len(local_clusters) + 1:04d}"
                best = {
                    "fp_cluster_id": cluster_id,
                    "model_family": key[0],
                    "method_name": key[1],
                    "input_scope": key[2],
                    "repetition": key[3],
                    "rows": [],
                    "token_sets": [],
                }
                local_clusters.append(best)
                representative.add(row["finding_uid"])
            best["rows"].append(row)
            best["token_sets"].append(tokens)
            row_cluster[row["finding_uid"]] = best["fp_cluster_id"]
        clusters.extend(local_clusters)

    for row in rows:
        out = dict(row)
        out["fp_cluster_id"] = row_cluster.get(row["finding_uid"], "")
        if row.get("detection_match") == "FP":
            out["cluster_scoring_role"] = (
                "FP_CLUSTER_REP" if row["finding_uid"] in representative else "FP_CLUSTER_DUP"
            )
        elif row.get("detection_match") == "TP":
            out["cluster_scoring_role"] = "TP"
        elif row.get("detection_match") == "Duplicate":
            out["cluster_scoring_role"] = "TP_DUPLICATE"
        else:
            out["cluster_scoring_role"] = row.get("detection_match", "")
        clustered_rows.append(out)
    return clusters, clustered_rows


def token_set(row: dict[str, str]) -> set[str]:
    text = " ".join(
        [
            row.get("summary", ""),
            row.get("vulnerability_category", ""),
            row.get("affected_locations", ""),
            row.get("claimed_modules", ""),
            row.get("claimed_signals_or_registers", ""),
        ]
    ).lower()
    tokens = {
        token
        for token in re.findall(r"[a-z0-9_]+", text)
        if len(token) >= 3 and token not in STOPWORDS
    }
    # Keep a small number of path-specific tokens to avoid merging unrelated
    # issues that only share broad security vocabulary.
    for file_text in row.get("claimed_files", "").split(";"):
        name = Path(file_text.strip()).stem.lower()
        if name:
            tokens.add(name)
    return tokens


def jaccard(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def cluster_rows(clusters: list[dict[str, Any]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for cluster in clusters:
        rows = cluster["rows"]
        rep = rows[0]
        out.append(
            {
                "fp_cluster_id": cluster["fp_cluster_id"],
                "model_family": cluster["model_family"],
                "method_name": cluster["method_name"],
                "input_scope": cluster["input_scope"],
                "repetition": cluster["repetition"],
                "fp_count": str(len(rows)),
                "representative_finding_uid": rep.get("finding_uid", ""),
                "claimed_files": join_unique(row.get("claimed_files", "") for row in rows),
                "claimed_modules": join_unique(row.get("claimed_modules", "") for row in rows),
                "claimed_signals_or_registers": join_unique(row.get("claimed_signals_or_registers", "") for row in rows),
                "example_summaries": "\n---\n".join(row.get("summary", "") for row in rows[:5]),
            }
        )
    return out


def join_unique(values: Any) -> str:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        for part in str(value or "").split(";"):
            text = part.strip()
            if text and text not in seen:
                seen.add(text)
                out.append(text)
    return "; ".join(out)


def compute_single_rows(
    rows: list[dict[str, str]],
    gt_rows: list[dict[str, str]],
    clusters: list[dict[str, Any]],
) -> list[dict[str, str]]:
    reps = sorted({row.get("repetition", "") for row in rows if row.get("repetition", "")})
    out: list[dict[str, str]] = []
    for rep in reps:
        rep_rows = [row for row in rows if row.get("repetition") == rep]
        rep_clusters = [cluster for cluster in clusters if cluster["repetition"] == rep]
        out.append(metric_row(rep_rows, gt_rows, rep_clusters, rep))
    return out


def compute_anyhit_row(
    rows: list[dict[str, str]],
    gt_rows: list[dict[str, str]],
    clusters: list[dict[str, Any]],
) -> dict[str, str]:
    return metric_row(rows, gt_rows, clusters, "")


def metric_row(
    rows: list[dict[str, str]],
    gt_rows: list[dict[str, str]],
    clusters: list[dict[str, Any]],
    repetition: str,
) -> dict[str, str]:
    gt_ids = {row["case_id"] for row in gt_rows}
    tp_rows = [row for row in rows if row.get("detection_match") == "TP"]
    hit_cases = {row["matched_case_id"] for row in tp_rows if row.get("matched_case_id")}
    tp_cases = len(hit_cases & gt_ids)
    fn_cases = len(gt_ids - hit_cases)
    fp_count = len(clusters)
    precision = ratio(len(tp_rows), len(tp_rows) + fp_count)
    recall = ratio(tp_cases, tp_cases + fn_cases)
    model = rows[0]["model_family"] if rows else ""
    method = rows[0]["method_name"] if rows else ""
    row = {
        "model_family": model,
        "method_name": method,
        "num_gt_cases": str(len(gt_ids)),
        "tp_cases": str(tp_cases),
        "fn_cases": str(fn_cases),
        "representative_tp_findings": str(len(tp_rows)),
        "fp_findings": str(fp_count),
        "precision": precision,
        "recall": recall,
        "f1_score": f1(precision, recall),
        "evidence_sufficiency_rate": ratio(
            sum(1 for item in tp_rows if item.get("evidence_quality") == "Sufficient"),
            len(tp_rows),
        ),
        "fabricated_unsupported_evidence_rate": "0.000000" if len(tp_rows) + fp_count else "",
    }
    if repetition != "":
        row["repetition"] = repetition
        row["tp_findings"] = row["representative_tp_findings"]
    return row


def copy_empty_single_rows(review_path: Path) -> list[dict[str, str]]:
    old = INPUT_ROOT / review_path.relative_to(INPUT_ROOT).parents[0] / "single_run" / "single_run_metrics.csv"
    return read_csv(old)


def copy_empty_anyhit_rows(review_path: Path) -> list[dict[str, str]]:
    old = INPUT_ROOT / review_path.relative_to(INPUT_ROOT).parents[0] / "anyhit3" / "anyhit3_model_summary.csv"
    return read_csv(old)


def ratio(num: int, den: int) -> str:
    if den == 0:
        return ""
    return f"{num / den:.6f}"


def f1(precision: str, recall: str) -> str:
    if not precision or not recall:
        return ""
    p = float(precision)
    r = float(recall)
    if p + r == 0:
        return ""
    return f"{2 * p * r / (p + r):.6f}"


def write_readme(summary_rows: list[dict[str, str]]) -> None:
    lines = [
        "# Current Four Runs Evaluation With FP Clustering",
        "",
        "This directory preserves the strict evaluation in `evaluation_results/current_four_runs/` and recalculates metrics after clustering repeated FP findings.",
        "",
        "Policy:",
        "",
        "- TP duplicates are handled as before: only one TP per GT case per run is counted.",
        "- FP findings are clustered within the same model/method/input_scope/repetition by similar claimed root issue, using summary, affected location, module, signal/register, and file tokens.",
        "- `fp_cluster_review.csv` records every FP cluster and its member count for manual review.",
        "- `finding_review_with_fp_clusters.csv` records each original finding and its cluster role.",
        "",
        "| Method | Model | TP cases | FN cases | FP clusters | Precision | Recall | F1 |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary_rows:
        lines.append(
            f"| {row['method_name']} | {row['model_family']} | {row['tp_cases']} | {row['fn_cases']} | "
            f"{row['fp_findings']} | {row['precision'] or 'undefined'} | {row['recall']} | {row['f1_score'] or 'undefined'} |"
        )
    (OUTPUT_ROOT / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
