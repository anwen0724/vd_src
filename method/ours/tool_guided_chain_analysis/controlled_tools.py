from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import ToolGuidedChainAnalysisConfig
from .schema import ToolAction


FORBIDDEN_PATH_PARTS = {"gt_cases", "evidence_gt", "case", "cases", "scoring", "finding_review"}


def allowed_files_for_chain(chain: dict[str, Any]) -> list[str]:
    files = {str(loc.get("file", "")) for loc in chain.get("source_locations", []) if loc.get("file")}
    return sorted(files)


def execute_actions(
    chain_id: str,
    actions: list[ToolAction],
    allowed_files: list[str],
    repo_root: str | Path,
    config: ToolGuidedChainAnalysisConfig,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    observations = []
    trace = []
    allowed = set(allowed_files)
    for action in actions[: config.max_tool_calls_per_chain]:
        record = {
            "chain_id": chain_id,
            "tool": action.tool,
            "file": action.file,
            "line_start": action.line_start,
            "line_end": action.line_end,
            "query": action.query,
            "reason": action.reason,
            "status": "not_started",
            "result_summary": "",
        }
        if action.file not in allowed or _forbidden_path(action.file):
            record["status"] = "denied"
            record["result_summary"] = "File is outside chain allowlist or forbidden."
            trace.append(record)
            observations.append(record)
            continue
        path = Path(repo_root) / action.file
        if not path.exists():
            record["status"] = "error"
            record["result_summary"] = "File does not exist."
            trace.append(record)
            observations.append(record)
            continue
        if action.tool == "read_around":
            content = _read_around(path, action.line_start, action.line_end, config)
        else:
            content = _search_file(path, action.query or "", config)
        record["status"] = "ok"
        record["content"] = content
        record["result_summary"] = content[:300]
        trace.append({k: v for k, v in record.items() if k != "content"})
        observations.append(record)
    return observations, trace


def _forbidden_path(file: str) -> bool:
    lowered = file.lower().replace("\\", "/")
    return any(part in lowered for part in FORBIDDEN_PATH_PARTS)


def _read_around(path: Path, line_start: int | None, line_end: int | None, config: ToolGuidedChainAnalysisConfig) -> str:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    start = max(1, int(line_start or 1) - config.read_around_before)
    end = min(len(lines), int(line_end or line_start or 1) + config.read_around_after)
    text = "\n".join(f"{idx}: {line}" for idx, line in enumerate(lines[start - 1 : end], start=start))
    return _trim(text, config.max_tool_result_chars)


def _search_file(path: Path, query: str, config: ToolGuidedChainAnalysisConfig) -> str:
    if not query:
        return ""
    matches = []
    needle = query.lower()
    for idx, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        if needle in line.lower():
            matches.append(f"{idx}: {line.strip()}")
        if len(matches) >= 100:
            break
    return _trim("\n".join(matches), config.max_tool_result_chars)


def _trim(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n[TRUNCATED]"


def trace_jsonl(records: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(record, ensure_ascii=False) for record in records)

