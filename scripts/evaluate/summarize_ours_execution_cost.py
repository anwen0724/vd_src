from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

SRC_ROOT = Path(__file__).resolve().parents[2]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


SCOPE_FIELDS = [
    "batch_id",
    "model_id",
    "provider",
    "model",
    "scope_id",
    "repetition",
    "run_dir",
    "chain_count",
    "analyzed_chain_count",
    "llm_call_count",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "elapsed_seconds",
    "diagnostics_elapsed_seconds",
    "final_finding_count",
    "discarded_finding_count",
    "no_finding_count",
    "estimated_cost_usd",
]

CHAIN_FIELDS = [
    "batch_id",
    "model_id",
    "provider",
    "model",
    "scope_id",
    "repetition",
    "chain_id",
    "status",
    "elapsed_seconds",
    "llm_status",
    "llm_elapsed_seconds",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "token_usage_source",
    "estimated_cost_usd",
]


def summarize_execution_cost(
    batch_root: str | Path,
    output_dir: str | Path,
    price_table_path: str | Path | None = None,
) -> tuple[Path, Path]:
    batch_root = Path(batch_root).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    price_table = _load_price_table(price_table_path)

    scope_rows: list[dict[str, Any]] = []
    chain_rows: list[dict[str, Any]] = []
    for run_dir in sorted((batch_root / "models").glob("*/*/rep_*")):
        metadata_path = run_dir / "run_metadata.json"
        diagnostics_path = run_dir / "module3B_analysis_diagnostics.json"
        if not metadata_path.exists() or not diagnostics_path.exists():
            continue

        metadata = _read_json(metadata_path)
        diagnostics = _read_json(diagnostics_path)
        model_id = run_dir.parent.parent.name
        scope_id = run_dir.parent.name
        repetition = run_dir.name
        provider = str(metadata.get("provider", ""))
        model = str(metadata.get("model", ""))

        input_tokens = _int(diagnostics.get("input_tokens"))
        output_tokens = _int(diagnostics.get("output_tokens"))
        scope_rows.append(
            {
                "batch_id": batch_root.name,
                "model_id": model_id,
                "provider": provider,
                "model": model,
                "scope_id": scope_id,
                "repetition": repetition,
                "run_dir": str(run_dir),
                "chain_count": _int(diagnostics.get("chain_count")),
                "analyzed_chain_count": _int(diagnostics.get("analyzed_chain_count")),
                "llm_call_count": _int(diagnostics.get("llm_call_count")),
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": _int(diagnostics.get("total_tokens")),
                "elapsed_seconds": _float(metadata.get("elapsed_seconds")),
                "diagnostics_elapsed_seconds": _float(diagnostics.get("elapsed_seconds")),
                "final_finding_count": _int(diagnostics.get("final_finding_count")),
                "discarded_finding_count": _int(diagnostics.get("discarded_finding_count")),
                "no_finding_count": _int(diagnostics.get("no_finding_count")),
                "estimated_cost_usd": _estimate_cost(model, input_tokens, output_tokens, price_table),
            }
        )

        for chain in diagnostics.get("per_chain", []):
            if not isinstance(chain, dict):
                continue
            llm = chain.get("llm", {})
            if not isinstance(llm, dict):
                llm = {}
            chain_input_tokens = _int(llm.get("input_tokens"))
            chain_output_tokens = _int(llm.get("output_tokens"))
            chain_rows.append(
                {
                    "batch_id": batch_root.name,
                    "model_id": model_id,
                    "provider": provider,
                    "model": model,
                    "scope_id": scope_id,
                    "repetition": repetition,
                    "chain_id": str(chain.get("chain_id", "")),
                    "status": str(chain.get("status", "")),
                    "elapsed_seconds": _float(chain.get("elapsed_seconds")),
                    "llm_status": str(llm.get("status", "")),
                    "llm_elapsed_seconds": _float(llm.get("elapsed_seconds")),
                    "input_tokens": chain_input_tokens,
                    "output_tokens": chain_output_tokens,
                    "total_tokens": _int(llm.get("total_tokens")),
                    "token_usage_source": str(llm.get("token_usage_source", "")),
                    "estimated_cost_usd": _estimate_cost(
                        model,
                        chain_input_tokens,
                        chain_output_tokens,
                        price_table,
                    ),
                }
            )

    scope_csv = output_dir / f"{batch_root.name}_scope_cost.csv"
    chain_csv = output_dir / f"{batch_root.name}_chain_cost.csv"
    _write_csv(scope_csv, SCOPE_FIELDS, scope_rows)
    _write_csv(chain_csv, CHAIN_FIELDS, chain_rows)
    return scope_csv, chain_csv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize ours chain-context execution cost.")
    parser.add_argument("--batch-root", required=True, help="One runs/ours_chain_context/<batch_id> directory.")
    parser.add_argument("--out-dir", default=str(SRC_ROOT / "results" / "ours_execution_cost"))
    parser.add_argument(
        "--price-table",
        default=None,
        help="Optional JSON price table keyed by model with input_per_million/output_per_million.",
    )
    args = parser.parse_args(argv)
    scope_csv, chain_csv = summarize_execution_cost(args.batch_root, args.out_dir, args.price_table)
    print(f"[ok] scope_csv={scope_csv}", flush=True)
    print(f"[ok] chain_csv={chain_csv}", flush=True)
    return 0


def _load_price_table(path: str | Path | None) -> dict[str, dict[str, float]]:
    if path is None:
        return {}
    raw = _read_json(Path(path))
    if not isinstance(raw, dict):
        return {}
    table: dict[str, dict[str, float]] = {}
    for model, prices in raw.items():
        if isinstance(prices, dict):
            table[str(model)] = {
                "input_per_million": _float(prices.get("input_per_million")),
                "output_per_million": _float(prices.get("output_per_million")),
            }
    return table


def _estimate_cost(
    model: str,
    input_tokens: int,
    output_tokens: int,
    price_table: dict[str, dict[str, float]],
) -> str:
    prices = price_table.get(model)
    if not prices:
        return ""
    cost = (
        input_tokens / 1_000_000 * prices.get("input_per_million", 0.0)
        + output_tokens / 1_000_000 * prices.get("output_per_million", 0.0)
    )
    return f"{cost:.8f}"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


if __name__ == "__main__":
    raise SystemExit(main())
