from __future__ import annotations

import sys
from pathlib import Path

import yaml


SRC_ROOT = Path(__file__).resolve().parents[2]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from llm.env import get_first_env, load_project_env
from llm.langchain_models import LangChainModelConfig, create_chat_model


CONFIG = SRC_ROOT / "configs" / "ours_chain_context_gemini.yaml"
PROMPT = "Reply with exactly one word: OK"


def main() -> int:
    load_project_env()
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    model_cfg = cfg["models"][0]
    provider = str(model_cfg["provider"])
    model = str(model_cfg["model"])
    api_key = get_first_env("V3_GEMINI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY")
    base_url = get_first_env("V3_GEMINI_BASE_URL", "GEMINI_BASE_URL")

    print(f"[live-test] config={CONFIG}", flush=True)
    print(f"[live-test] provider={provider}", flush=True)
    print(f"[live-test] model={model}", flush=True)
    print(f"[live-test] api_key={'set' if api_key else 'missing'}", flush=True)
    print(f"[live-test] base_url={'set' if base_url else 'missing'}", flush=True)
    if not api_key:
        raise RuntimeError("Missing Gemini API key in src/.env or process environment.")

    chat_model = create_chat_model(
        LangChainModelConfig(
            provider=provider,
            model=model,
            temperature=float(cfg.get("temperature", 0.2)),
            max_tokens=64,
            request_timeout=float(cfg.get("request_timeout") or 120),
        )
    )
    response = chat_model.invoke(PROMPT)
    text = str(getattr(response, "content", "") or "").strip()
    print(f"[live-test] response={text[:200]}", flush=True)
    if not text:
        raise RuntimeError("Gemini returned an empty response.")
    print("[live-test] OK", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
