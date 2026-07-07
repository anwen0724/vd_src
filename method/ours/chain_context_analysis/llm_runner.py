from __future__ import annotations

import json
import re
from typing import Any

from langchain_core.messages import HumanMessage

from .schema import LLMChainAnalysis


def analyze_chain_plain_json(chat_model: Any, prompt: str) -> tuple[LLMChainAnalysis | None, dict[str, Any]]:
    diagnostics: dict[str, Any] = {"llm_calls": 1, "status": "not_started", "error": ""}
    try:
        raw = chat_model.invoke([HumanMessage(content=prompt + "\n\nReturn only JSON. Do not wrap in Markdown.")])
        content = getattr(raw, "content", raw)
        payload = _extract_json_object(str(content))
        diagnostics["status"] = "ok"
        return LLMChainAnalysis.model_validate(payload), diagnostics
    except Exception as exc:  # pragma: no cover - provider exceptions vary
        diagnostics["status"] = "failed"
        diagnostics["error"] = str(exc)
        return None, diagnostics


def _extract_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end <= start:
            raise
        return json.loads(cleaned[start : end + 1])

