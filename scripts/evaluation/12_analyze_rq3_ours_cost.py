from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
RUNS_ROOT = ROOT / "runs"
OUTPUT_ROOT = ROOT / "evaluation_results" / "rq3_ours_cost_analysis"
DATA_DIR = OUTPUT_ROOT / "data"
FIGURE_DIR = OUTPUT_ROOT / "figures"

CONTEXT_ROOT = RUNS_ROOT / "analysis_semantic_dedup_contexts_1049"
GRAPH_ROOT = RUNS_ROOT / "module1_rtl_structure_graphs"
OURS_RUN_ROOT = RUNS_ROOT / "ours_chain_context"

MODEL_RUNS = {
    "claude_sonnet_4-6": OURS_RUN_ROOT / "ours_chain_context_claude",
    "gemini_3.1_pro_preview": OURS_RUN_ROOT / "ours_chain_context_gemini",
}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_batch_status(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def benchmark_from_scope(scope_id: str) -> str:
    if "hackatdac18" in scope_id:
        return "Hack@DAC18"
    if "hackatdac19" in scope_id:
        return "Hack@DAC19"
    if "hackatdac21" in scope_id:
        return "Hack@DAC21"
    return "Unknown"


def graph_stats(scope_id: str) -> dict[str, Any]:
    graph_path = GRAPH_ROOT / scope_id / "rtl_structure_graph.json"
    graph = load_json(graph_path)
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    type_counts: dict[str, int] = {}
    files: set[str] = set()
    max_line_by_file: dict[str, int] = {}
    for node in nodes:
        node_type = node.get("type", "")
        type_counts[node_type] = type_counts.get(node_type, 0) + 1
        loc = node.get("loc") or {}
        file_name = loc.get("file")
        line_end = loc.get("line_end") or loc.get("line_start")
        if file_name:
            files.add(file_name)
            if isinstance(line_end, int):
                max_line_by_file[file_name] = max(max_line_by_file.get(file_name, 0), line_end)

    graph_nodes = len(nodes)
    graph_edges = len(edges)
    return {
        "scope_id": scope_id,
        "benchmark": benchmark_from_scope(scope_id),
        "rtl_files": len(files),
        "graph_loc_approx": sum(max_line_by_file.values()),
        "graph_modules": type_counts.get("Module", 0),
        "graph_instances": type_counts.get("Instance", 0),
        "graph_signals": type_counts.get("Signal", 0),
        "graph_statements": type_counts.get("Statement", 0) + type_counts.get("Stmt", 0),
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
        "graph_scale_nodes_edges": graph_nodes + graph_edges,
    }


def context_stats(scope_id: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    context_path = CONTEXT_ROOT / scope_id / "permission_chain_contexts.json"
    context_doc = load_json(context_path)
    chains = context_doc.get("chains", [])

    chain_stats: dict[str, dict[str, Any]] = {}
    total_snippets = 0
    total_chain_nodes = 0
    total_chain_edges = 0
    total_source_chars = 0

    for chain in chains:
        chain_id = chain.get("chain_id", "")
        snippets = chain.get("source_snippets") or []
        nodes = chain.get("nodes") or []
        edges = chain.get("edges") or []
        snippet_chars = 0
        snippet_files: set[str] = set()
        for snippet in snippets:
            text = snippet.get("text") or snippet.get("source") or snippet.get("code") or ""
            snippet_chars += len(text)
            loc = snippet.get("loc") or {}
            if loc.get("file"):
                snippet_files.add(loc["file"])

        row = {
            "scope_id": scope_id,
            "chain_id": chain_id,
            "chain_nodes": len(nodes),
            "chain_edges": len(edges),
            "chain_scale_nodes_edges": len(nodes) + len(edges),
            "source_snippet_count": len(snippets),
            "source_snippet_files": len(snippet_files),
            "source_snippet_chars": snippet_chars,
        }
        chain_stats[chain_id] = row
        total_snippets += len(snippets)
        total_chain_nodes += len(nodes)
        total_chain_edges += len(edges)
        total_source_chars += snippet_chars

    context_count = len(chains)
    return (
        {
            "scope_id": scope_id,
            "context_count": context_count,
            "source_snippet_count": total_snippets,
            "context_chain_nodes": total_chain_nodes,
            "context_chain_edges": total_chain_edges,
            "context_scale_nodes_edges": total_chain_nodes + total_chain_edges,
            "source_snippet_chars": total_source_chars,
            "context_file_mb": context_path.stat().st_size / (1024 * 1024),
            "avg_chain_nodes": total_chain_nodes / context_count if context_count else 0,
            "avg_chain_edges": total_chain_edges / context_count if context_count else 0,
            "avg_source_snippets": total_snippets / context_count if context_count else 0,
        },
        chain_stats,
    )


def collect_scope_and_chain_rows() -> tuple[pd.DataFrame, pd.DataFrame]:
    graph_context_rows: dict[str, dict[str, Any]] = {}
    chain_context_rows: dict[tuple[str, str], dict[str, Any]] = {}

    for context_dir in sorted(CONTEXT_ROOT.iterdir()):
        if not context_dir.is_dir():
            continue
        scope_id = context_dir.name
        scope_context_stats, chain_stats = context_stats(scope_id)
        graph_context_rows[scope_id] = {**graph_stats(scope_id), **scope_context_stats}
        for chain_id, row in chain_stats.items():
            chain_context_rows[(scope_id, chain_id)] = row

    scope_rows: list[dict[str, Any]] = []
    chain_rows: list[dict[str, Any]] = []

    for model_id, run_dir in MODEL_RUNS.items():
        batch_path = run_dir / "batch_status.jsonl"
        for record in read_batch_status(batch_path):
            scope_id = record["scope_id"]
            metadata_path = Path(record["run_dir"]) / "run_metadata.json"
            diagnostics_path = Path(record["run_dir"]) / "module3B_analysis_diagnostics.json"
            metadata = load_json(metadata_path)
            summary = metadata.get("summary", {})

            scope_rows.append(
                {
                    **graph_context_rows[scope_id],
                    "model_id": model_id,
                    "provider": record.get("provider", ""),
                    "model": record.get("model", ""),
                    "status": record.get("status", ""),
                    "runtime_seconds": record.get("elapsed_seconds") or summary.get("elapsed_seconds", 0),
                    "llm_call_count": summary.get("llm_call_count", 0),
                    "input_tokens": summary.get("input_tokens", 0),
                    "output_tokens": summary.get("output_tokens", 0),
                    "total_tokens": summary.get("total_tokens", 0),
                    "final_finding_count": summary.get("final_finding_count", 0),
                    "raw_llm_finding_count": summary.get("raw_llm_finding_count", 0),
                    "discarded_finding_count": summary.get("discarded_finding_count", 0),
                }
            )

            diagnostics = load_json(diagnostics_path)
            for chain_record in diagnostics.get("per_chain", []):
                chain_id = chain_record.get("chain_id", "")
                llm = chain_record.get("llm") or {}
                context_row = chain_context_rows.get((scope_id, chain_id), {})
                chain_rows.append(
                    {
                        **context_row,
                        "benchmark": benchmark_from_scope(scope_id),
                        "model_id": model_id,
                        "provider": record.get("provider", ""),
                        "model": record.get("model", ""),
                        "status": chain_record.get("status", ""),
                        "llm_status": llm.get("status", ""),
                        "failure_stage": llm.get("failure_stage", ""),
                        "elapsed_seconds": chain_record.get("elapsed_seconds", llm.get("elapsed_seconds", 0)),
                        "llm_calls": llm.get("llm_calls", 0),
                        "input_tokens": llm.get("input_tokens", 0),
                        "output_tokens": llm.get("output_tokens", 0),
                        "total_tokens": llm.get("total_tokens", 0),
                        "token_usage_source": llm.get("token_usage_source", ""),
                        "has_raw_finding": bool((chain_record.get("raw_llm_analysis") or {}).get("has_finding")),
                    }
                )

    return pd.DataFrame(scope_rows), pd.DataFrame(chain_rows)


def corr_value(df: pd.DataFrame, x: str, y: str, method: str) -> float:
    sub = df[[x, y]].dropna()
    if len(sub) < 2 or sub[x].nunique() < 2 or sub[y].nunique() < 2:
        return float("nan")
    return float(sub[x].corr(sub[y], method=method))


def build_correlation_summary(scope_df: pd.DataFrame, chain_df: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []

    scope_pairs = [
        ("graph_scale_nodes_edges", "context_count", "repo scale vs generated context count"),
        ("graph_nodes", "context_count", "graph nodes vs generated context count"),
        ("graph_edges", "context_count", "graph edges vs generated context count"),
        ("graph_loc_approx", "context_count", "approx LOC vs generated context count"),
        ("context_count", "runtime_seconds", "context count vs scope runtime"),
        ("source_snippet_count", "runtime_seconds", "source snippets vs scope runtime"),
        ("context_count", "total_tokens", "context count vs scope total tokens"),
        ("source_snippet_count", "total_tokens", "source snippets vs scope total tokens"),
    ]
    for model_id in ["all", *MODEL_RUNS.keys()]:
        data = scope_df if model_id == "all" else scope_df[scope_df["model_id"] == model_id]
        for x, y, label in scope_pairs:
            pair_data = data
            if model_id == "all" and y == "context_count":
                pair_data = data.drop_duplicates("scope_id")
            rows.append(
                {
                    "level": "scope",
                    "model_id": model_id,
                    "analysis": label,
                    "x": x,
                    "y": y,
                    "n": len(pair_data[[x, y]].dropna()),
                    "pearson": corr_value(pair_data, x, y, "pearson"),
                    "spearman": corr_value(pair_data, x, y, "spearman"),
                }
            )

    chain_pairs = [
        ("input_tokens", "elapsed_seconds", "chain input tokens vs chain runtime"),
        ("total_tokens", "elapsed_seconds", "chain total tokens vs chain runtime"),
        ("source_snippet_count", "elapsed_seconds", "chain snippets vs chain runtime"),
        ("chain_scale_nodes_edges", "elapsed_seconds", "chain graph scale vs chain runtime"),
    ]
    for model_id in ["all", *MODEL_RUNS.keys()]:
        data = chain_df if model_id == "all" else chain_df[chain_df["model_id"] == model_id]
        for x, y, label in chain_pairs:
            rows.append(
                {
                    "level": "chain",
                    "model_id": model_id,
                    "analysis": label,
                    "x": x,
                    "y": y,
                    "n": len(data[[x, y]].dropna()),
                    "pearson": corr_value(data, x, y, "pearson"),
                    "spearman": corr_value(data, x, y, "spearman"),
                }
            )

    return pd.DataFrame(rows)


def add_fit_line(ax: plt.Axes, x: pd.Series, y: pd.Series) -> None:
    sub = pd.DataFrame({"x": x, "y": y}).replace([np.inf, -np.inf], np.nan).dropna()
    if len(sub) < 2 or sub["x"].nunique() < 2:
        return
    coef = np.polyfit(sub["x"], sub["y"], 1)
    xs = np.linspace(sub["x"].min(), sub["x"].max(), 100)
    ax.plot(xs, coef[0] * xs + coef[1], color="red", linewidth=1.6, alpha=0.85)


def annotate_corr(ax: plt.Axes, df: pd.DataFrame, x: str, y: str) -> None:
    pearson = corr_value(df, x, y, "pearson")
    spearman = corr_value(df, x, y, "spearman")
    text = f"Pearson r={pearson:.3f}\nSpearman rho={spearman:.3f}"
    ax.text(
        0.03,
        0.97,
        text,
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=9,
        bbox={"boxstyle": "round,pad=0.3", "facecolor": "white", "edgecolor": "#cccccc", "alpha": 0.9},
    )


def scatter_scope(
    df: pd.DataFrame,
    x: str,
    y: str,
    title: str,
    xlabel: str,
    ylabel: str,
    path: Path,
    color_by: str = "benchmark",
) -> None:
    fig, ax = plt.subplots(figsize=(7.2, 5.0), dpi=160)
    for label, group in df.groupby(color_by):
        ax.scatter(group[x], group[y], label=label, s=42, alpha=0.82, edgecolors="none")
    add_fit_line(ax, df[x], df[y])
    annotate_corr(ax, df, x, y)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(True, linewidth=0.4, alpha=0.25)
    ax.legend(fontsize=8, frameon=True)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def scatter_chain(
    df: pd.DataFrame,
    x: str,
    y: str,
    title: str,
    xlabel: str,
    ylabel: str,
    path: Path,
    color_by: str = "benchmark",
) -> None:
    fig, ax = plt.subplots(figsize=(7.2, 5.0), dpi=160)
    for label, group in df.groupby(color_by):
        ax.scatter(group[x], group[y], label=label, s=14, alpha=0.45, edgecolors="none")
    add_fit_line(ax, df[x], df[y])
    annotate_corr(ax, df, x, y)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(True, linewidth=0.4, alpha=0.25)
    ax.legend(fontsize=8, frameon=True, markerscale=1.4)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def write_outputs(scope_df: pd.DataFrame, chain_df: pd.DataFrame, corr_df: pd.DataFrame) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)

    for model_id in MODEL_RUNS:
        safe_model = model_id.replace("/", "_")
        scope_df[scope_df["model_id"] == model_id].to_csv(DATA_DIR / f"scope_level_ours_{safe_model}.csv", index=False)
        chain_df[chain_df["model_id"] == model_id].to_csv(DATA_DIR / f"chain_level_ours_{safe_model}.csv", index=False)

    scope_df.to_csv(DATA_DIR / "scope_level_ours_combined.csv", index=False)
    chain_df.to_csv(DATA_DIR / "chain_level_ours_combined.csv", index=False)
    corr_df.to_csv(DATA_DIR / "correlation_summary.csv", index=False)

    unique_scope = (
        scope_df.sort_values(["model_id", "scope_id"])
        .drop_duplicates("scope_id")
        .sort_values("scope_id")
        .reset_index(drop=True)
    )
    scatter_scope(
        unique_scope,
        "graph_scale_nodes_edges",
        "context_count",
        "Repo Graph Scale vs Generated Context Count",
        "Repo Graph Scale (Nodes + Edges)",
        "Generated Permission Context Count",
        FIGURE_DIR / "repo_scale_vs_context_count.png",
    )

    for model_id in MODEL_RUNS:
        model_scope = scope_df[scope_df["model_id"] == model_id]
        model_chain = chain_df[chain_df["model_id"] == model_id]
        prefix = "claude" if "claude" in model_id else "gemini"
        scatter_scope(
            model_scope,
            "context_count",
            "runtime_seconds",
            f"{model_id}: Context Count vs Runtime",
            "Generated Permission Context Count",
            "Runtime (s)",
            FIGURE_DIR / f"{prefix}_context_count_vs_runtime.png",
        )
        scatter_scope(
            model_scope,
            "source_snippet_count",
            "runtime_seconds",
            f"{model_id}: Source Snippets vs Runtime",
            "Source Snippet Count",
            "Runtime (s)",
            FIGURE_DIR / f"{prefix}_snippet_count_vs_runtime.png",
        )
        scatter_scope(
            model_scope,
            "context_count",
            "total_tokens",
            f"{model_id}: Context Count vs Total Tokens",
            "Generated Permission Context Count",
            "Total Tokens",
            FIGURE_DIR / f"{prefix}_context_count_vs_total_tokens.png",
        )
        scatter_chain(
            model_chain,
            "input_tokens",
            "elapsed_seconds",
            f"{model_id}: Chain Input Tokens vs LLM Runtime",
            "Input Tokens per Chain",
            "LLM Runtime per Chain (s)",
            FIGURE_DIR / f"{prefix}_chain_input_tokens_vs_runtime.png",
        )

    scatter_scope(
        scope_df,
        "context_count",
        "runtime_seconds",
        "Combined: Context Count vs Runtime",
        "Generated Permission Context Count",
        "Runtime (s)",
        FIGURE_DIR / "combined_context_count_vs_runtime.png",
        color_by="model_id",
    )
    scatter_scope(
        scope_df,
        "source_snippet_count",
        "runtime_seconds",
        "Combined: Source Snippets vs Runtime",
        "Source Snippet Count",
        "Runtime (s)",
        FIGURE_DIR / "combined_snippet_count_vs_runtime.png",
        color_by="model_id",
    )
    scatter_chain(
        chain_df,
        "input_tokens",
        "elapsed_seconds",
        "Combined: Chain Input Tokens vs LLM Runtime",
        "Input Tokens per Chain",
        "LLM Runtime per Chain (s)",
        FIGURE_DIR / "combined_chain_input_tokens_vs_runtime.png",
        color_by="model_id",
    )


def fmt_seconds(seconds: float) -> str:
    hours = seconds / 3600
    return f"{seconds:.1f}s ({hours:.2f}h)"


def write_readme(scope_df: pd.DataFrame, chain_df: pd.DataFrame, corr_df: pd.DataFrame) -> None:
    unique_scope = scope_df.drop_duplicates("scope_id")
    lines: list[str] = []
    lines.append("# RQ3 Ours Cost Analysis")
    lines.append("")
    lines.append("本目录只分析 ours 方法的执行开销，不包含 baseline。")
    lines.append("")
    lines.append("## 数据范围")
    lines.append("")
    lines.append(f"- input scope 数量：{unique_scope['scope_id'].nunique()}")
    lines.append(f"- permission context 总数：{int(unique_scope['context_count'].sum())}")
    lines.append(f"- source snippet 总数：{int(unique_scope['source_snippet_count'].sum())}")
    lines.append("")
    lines.append("## 模型运行汇总")
    lines.append("")
    lines.append("| model | scopes | chains | runtime | input tokens | output tokens | total tokens |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for model_id, group in scope_df.groupby("model_id"):
        lines.append(
            "| "
            + " | ".join(
                [
                    model_id,
                    str(group["scope_id"].nunique()),
                    str(int(group["llm_call_count"].sum())),
                    fmt_seconds(float(group["runtime_seconds"].sum())),
                    str(int(group["input_tokens"].sum())),
                    str(int(group["output_tokens"].sum())),
                    str(int(group["total_tokens"].sum())),
                ]
            )
            + " |"
        )
    lines.append("")
    lines.append("## 关键相关性")
    lines.append("")
    selected = corr_df[
        (
            (corr_df["analysis"].isin(
                [
                    "repo scale vs generated context count",
                    "context count vs scope runtime",
                    "source snippets vs scope runtime",
                    "context count vs scope total tokens",
                    "source snippets vs scope total tokens",
                    "chain input tokens vs chain runtime",
                ]
            ))
        )
    ]
    lines.append("| level | model | analysis | n | Pearson | Spearman |")
    lines.append("|---|---|---|---:|---:|---:|")
    for _, row in selected.iterrows():
        pearson = "" if math.isnan(row["pearson"]) else f"{row['pearson']:.3f}"
        spearman = "" if math.isnan(row["spearman"]) else f"{row['spearman']:.3f}"
        lines.append(
            f"| {row['level']} | {row['model_id']} | {row['analysis']} | {int(row['n'])} | {pearson} | {spearman} |"
        )
    lines.append("")
    lines.append("## 生成文件")
    lines.append("")
    lines.append("- `data/`：scope-level、chain-level 和相关性 CSV。")
    lines.append("- `figures/`：repo scale/context count/runtime/token 关系散点图。")
    lines.append("")
    lines.append("## 解释口径")
    lines.append("")
    lines.append(
        "repo scale 与 context count 的关系用于观察模块1/2是否把仓库规模直接转化为 LLM 输入规模；"
        "context count、snippet count 与 runtime/tokens 的关系用于解释模块3的主要开销来源。"
    )
    lines.append(
        "当前结果显示，模块3运行时间和 token 数量与 context 数量、source snippet 数量高度相关，"
        "因此 RQ3 更适合表述为：执行开销主要由被选中的权限链路上下文规模驱动，而不是由原始 repo 总规模单独决定。"
    )
    (OUTPUT_ROOT / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    scope_df, chain_df = collect_scope_and_chain_rows()
    corr_df = build_correlation_summary(scope_df, chain_df)
    write_outputs(scope_df, chain_df, corr_df)
    write_readme(scope_df, chain_df, corr_df)
    print(f"Wrote RQ3 ours cost analysis to: {OUTPUT_ROOT}")
    print(f"Scope rows: {len(scope_df)}")
    print(f"Chain rows: {len(chain_df)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
