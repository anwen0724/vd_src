"""Read/search-only file tools for source-code analysis."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ToolResult:
    """Result returned by read/search-only tools."""

    tool: str
    status: str
    content: str
    path: str | None = None
    error: str | None = None
    truncated: bool = False


class ToolAccessDenied(Exception):
    """Raised when a requested path is outside the input scope."""


class ReadSearchTools:
    """Safe read/search-only tools bound to one input-scope root."""

    def __init__(self, root: str | Path, max_file_chars: int = 20_000) -> None:
        self.root = Path(root).resolve()
        self.max_file_chars = max_file_chars
        if not self.root.exists():
            raise FileNotFoundError(f"Input scope root does not exist: {self.root}")
        if not self.root.is_dir():
            raise NotADirectoryError(f"Input scope root is not a directory: {self.root}")

    def list_dir(self, path: str = ".") -> ToolResult:
        """List one directory level under the input-scope root."""

        try:
            target = self._resolve_inside_root(path)
            if not target.exists():
                return self._error("list_dir", path, "Path does not exist")
            if not target.is_dir():
                return self._error("list_dir", path, "Path is not a directory")

            entries = []
            for child in sorted(target.iterdir(), key=lambda item: item.name.lower()):
                suffix = "/" if child.is_dir() else ""
                entries.append(f"{child.name}{suffix}")

            return ToolResult(
                tool="list_dir",
                status="ok",
                path=self._relative_display_path(target),
                content="\n".join(entries),
            )
        except ToolAccessDenied as exc:
            return self._denied("list_dir", path, str(exc))
        except OSError as exc:
            return self._error("list_dir", path, str(exc))

    def read_file(self, path: str) -> ToolResult:
        """Read one file under the input-scope root."""

        try:
            target = self._resolve_inside_root(path)
            if not target.exists():
                return self._error("read_file", path, "Path does not exist")
            if not target.is_file():
                return self._error("read_file", path, "Path is not a file")

            text = target.read_text(encoding="utf-8", errors="replace")
            truncated = len(text) > self.max_file_chars
            if truncated:
                text = text[: self.max_file_chars]
                text += "\n\n[TRUNCATED: file content exceeded max_file_chars]"

            return ToolResult(
                tool="read_file",
                status="ok",
                path=self._relative_display_path(target),
                content=text,
                truncated=truncated,
            )
        except ToolAccessDenied as exc:
            return self._denied("read_file", path, str(exc))
        except OSError as exc:
            return self._error("read_file", path, str(exc))

    def search_text(
        self,
        query: str,
        path: str = ".",
        case_sensitive: bool = False,
        max_matches: int = 200,
    ) -> ToolResult:
        """Search plain text under the input-scope root."""

        try:
            target = self._resolve_inside_root(path)
            if not target.exists():
                return self._error("search_text", path, "Path does not exist")

            if target.is_file():
                files = [target]
            elif target.is_dir():
                files = [item for item in target.rglob("*") if item.is_file()]
            else:
                return self._error("search_text", path, "Path is neither file nor directory")

            needle = query if case_sensitive else query.lower()
            matches: list[str] = []

            for file_path in sorted(files):
                if len(matches) >= max_matches:
                    break
                try:
                    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue

                for line_number, line in enumerate(lines, start=1):
                    haystack = line if case_sensitive else line.lower()
                    if needle in haystack:
                        rel = self._relative_display_path(file_path)
                        matches.append(f"{rel}:{line_number}: {line.strip()}")
                        if len(matches) >= max_matches:
                            break

            truncated = len(matches) >= max_matches
            content = "\n".join(matches)
            if truncated:
                content += "\n[TRUNCATED: search results exceeded max_matches]"

            return ToolResult(
                tool="search_text",
                status="ok",
                path=self._relative_display_path(target),
                content=content,
                truncated=truncated,
            )
        except ToolAccessDenied as exc:
            return self._denied("search_text", path, str(exc))
        except OSError as exc:
            return self._error("search_text", path, str(exc))

    def _resolve_inside_root(self, path: str) -> Path:
        target = (self.root / path).resolve()
        if not target.is_relative_to(self.root):
            raise ToolAccessDenied("Path is outside input scope")
        return target

    def _relative_display_path(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix() or "."

    @staticmethod
    def _denied(tool: str, path: str, error: str) -> ToolResult:
        return ToolResult(tool=tool, status="denied", path=path, content="", error=error)

    @staticmethod
    def _error(tool: str, path: str, error: str) -> ToolResult:
        return ToolResult(tool=tool, status="error", path=path, content="", error=error)
