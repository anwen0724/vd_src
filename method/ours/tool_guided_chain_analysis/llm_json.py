from __future__ import annotations

import json
import re
from typing import Any, TypeVar

from langchain_core.messages import HumanMessage
from pydantic import BaseModel

ModelT = TypeVar("ModelT", bound=BaseModel)


def invoke_json(chat_model: Any, prompt: str, schema: type[ModelT]) -> tuple[ModelT | None, dict[str, Any]]:
    diagnostics = {"llm_calls": 1, "status": "not_started", "error": ""}
    try:
        raw = chat_model.invoke([HumanMessage(content=prompt + "\n\nReturn only JSON. Do not wrap in Markdown.")])
        text = str(getattr(raw, "content", raw))
        payload = _extract_json_object(text)
        diagnostics["status"] = "ok"
        return schema.model_validate(payload), diagnostics
    except Exception as exc:  # pragma: no cover
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

