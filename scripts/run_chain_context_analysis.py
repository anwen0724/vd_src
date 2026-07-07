from __future__ import annotations

import argparse
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from llm.langchain_models import LangChainModelConfig, create_chat_model
from method.ours.chain_context_analysis.config import ChainContextAnalysisConfig
from method.ours.chain_context_analysis.pipeline import run_chain_context_analysis


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Scheme B no-tool chain-context analysis.")
    parser.add_argument("--contexts", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--provider", default="deepseek", choices=["gpt", "claude", "deepseek", "qwen"])
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--max-chains", type=int, default=None)
    args = parser.parse_args(argv)
    chat_model = create_chat_model(
        LangChainModelConfig(
            provider=args.provider,
            model=args.model,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
        )
    )
    summary = run_chain_context_analysis(
        contexts_path=args.contexts,
        repo_root=args.repo_root,
        output_dir=args.out,
        chat_model=chat_model,
        config=ChainContextAnalysisConfig(max_chains=args.max_chains),
    )
    print(
        "[ok] {graph_id}: chains={chain_count} llm_calls={llm_call_count} final_findings={final_finding_count} discarded={discarded_finding_count}".format(
            **summary
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

