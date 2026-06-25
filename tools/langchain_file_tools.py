"""LangChain tool wrappers for read/search-only file tools."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Callable

from tools.file_tools import ReadSearchTools


def build_langchain_file_tools(file_tools: ReadSearchTools):
    """Build LangChain tools backed by safe read/search-only file tools."""

    try:
        from langchain_core.tools import tool
    except ModuleNotFoundError:  # pragma: no cover - fallback for unit tests without LangChain installed.
        tool = _local_tool

    @tool
    def list_dir(path: str = ".") -> str:
        """List one directory level under the current input scope."""

        result = file_tools.list_dir(path=path)
        return json.dumps(asdict(result), ensure_ascii=False)

    @tool
    def read_file(path: str, offset: int | None = None, limit: int | None = None) -> str:
        """Read a file under the current input scope."""

        result = file_tools.read_file(path=path, offset=offset, limit=limit)
        return json.dumps(asdict(result), ensure_ascii=False)

    @tool
    def search_text(
        query: str | None = None,
        path: str = ".",
        case_sensitive: bool = False,
        pattern: str | None = None,
    ) -> str:
        """Search plain text under the current input scope."""

        effective_query = query or pattern
        if not effective_query:
            return json.dumps(
                {
                    "tool": "search_text",
                    "status": "error",
                    "content": "",
                    "path": path,
                    "error": "Missing search query. Use query or pattern.",
                    "truncated": False,
                },
                ensure_ascii=False,
            )

        result = file_tools.search_text(
            query=effective_query,
            path=path,
            case_sensitive=case_sensitive,
        )
        return json.dumps(asdict(result), ensure_ascii=False)

    return [list_dir, read_file, search_text]


class _LocalTool:
    def __init__(self, func: Callable[..., str]) -> None:
        self.func = func
        self.name = func.__name__

    def invoke(self, args: dict[str, Any]) -> str:
        return self.func(**args)


def _local_tool(func: Callable[..., str]) -> _LocalTool:
    return _LocalTool(func)
