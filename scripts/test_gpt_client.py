"""Smoke test for GPTClient."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from llm import GPTClient, GPTClientConfig

    client = GPTClient(
        GPTClientConfig(
            model="gpt-5.5",
            temperature=0.2,
            max_tokens=256,
        )
    )
    response = client.generate("Answer briefly: what is 2 + 2?")
    print(response.encode("unicode_escape").decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
