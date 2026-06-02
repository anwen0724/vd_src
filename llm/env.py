"""Environment helpers for LLM clients."""

from __future__ import annotations

import os
from pathlib import Path


_ENV_LOADED = False


def load_project_env() -> None:
    """Load variables from src/.env once.

    Existing process environment variables take precedence over values in .env.
    """

    global _ENV_LOADED
    if _ENV_LOADED:
        return

    env_path = Path(__file__).resolve().parents[1] / ".env"
    if env_path.exists():
        _load_dotenv_file(env_path)

    _ENV_LOADED = True


def get_env(name: str, default: str | None = None) -> str | None:
    """Read an environment variable."""

    load_project_env()
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value


def get_first_env(*names: str, default: str | None = None) -> str | None:
    """Read the first non-empty environment variable from a list of names."""

    for name in names:
        value = get_env(name)
        if value is not None:
            return value
    return default


def require_env(name: str) -> str:
    """Read a required environment variable."""

    value = get_env(name)
    if value is None:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _load_dotenv_file(path: Path) -> None:
    """Load a simple KEY=VALUE .env file without adding a runtime dependency."""

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        if key:
            os.environ.setdefault(key, value)
