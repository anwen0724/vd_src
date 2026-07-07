from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from llm.langchain_models import LangChainModelConfig, create_chat_model
from method.ours.tool_guided_chain_analysis.config import ToolGuidedChainAnalysisConfig
from method.ours.tool_guided_chain_analysis.pipeline import run_tool_guided_chain_analysis


DEFAULT_CHAIN_ROOT = SRC_ROOT / "runs" / "module2_chain_graphs"
DEFAULT_EXPERIMENTS_ROOT = SRC_ROOT.parent / "experiments"
DEFAULT_OUT_ROOT = SRC_ROOT / "runs" / "module3A_tool_guided_chain_analysis"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch run Scheme A tool-guided chain analysis.")
    parser.add_argument("--chain-root", default=str(DEFAULT_CHAIN_ROOT))
    parser.add_argument("--experiments-root", default=str(DEFAULT_EXPERIMENTS_ROOT))
    parser.add_argument("--out-root", default=str(DEFAULT_OUT_ROOT))
    parser.add_argument("--provider", default="deepseek", choices=["gpt", "claude", "deepseek", "qwen"])
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--max-chains", type=int, default=None)
    parser.add_argument("--max-tool-calls-per-chain", type=int, default=32)
    args = parser.parse_args(argv)
    chat_model = create_chat_model(
        LangChainModelConfig(
            provider=args.provider,
            model=args.model,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
        )
    )
    out_root = Path(args.out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    manifest = []
    for repo_dir in sorted(path for path in Path(args.chain_root).iterdir() if path.is_dir()):
        scope = repo_dir.name
        try:
            summary = run_tool_guided_chain_analysis(
                chain_graphs_path=repo_dir / "permission_chain_graphs.json",
                repo_root=resolve_repo_root(scope, Path(args.experiments_root)),
                output_dir=out_root / scope,
                chat_model=chat_model,
                config=ToolGuidedChainAnalysisConfig(
                    max_chains=args.max_chains,
                    max_tool_calls_per_chain=args.max_tool_calls_per_chain,
                ),
            )
            summary["scope"] = scope
            summary["status"] = "ok"
            manifest.append(summary)
            print(
                "[ok] {scope}: chains={chain_count} llm_calls={llm_call_count} tool_calls={tool_call_count} final_findings={final_finding_count} discarded={discarded_finding_count}".format(
                    **summary
                ),
                flush=True,
            )
        except Exception as exc:  # pragma: no cover
            manifest.append({"scope": scope, "status": "failed", "error": str(exc)})
            print(f"[failed] {scope}: {exc}", flush=True)
    (out_root / "manifest.json").write_text(json.dumps({"runs": manifest}, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if all(item["status"] == "ok" for item in manifest) else 1


def resolve_repo_root(scope: str, experiments_root: Path) -> Path:
    benchmark, case_name = scope.split("__", 1)
    return experiments_root / f"baseline_{benchmark}" / "agent_input" / case_name


if __name__ == "__main__":
    raise SystemExit(main())

