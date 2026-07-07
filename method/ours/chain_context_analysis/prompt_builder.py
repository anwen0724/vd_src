from __future__ import annotations

import json
from typing import Any


PROMPT = """You are analyzing a SystemVerilog RTL permission-security chain context.

You are given one permission chain context. It already contains the graph nodes, graph edges, source locations, and deterministic source snippets extracted from the RTL repository.

Use only source_snippets as source-code evidence. Do not request additional files. Do not infer evidence from graph nodes alone.

Decide whether the chain context supports a permission-related vulnerability finding.

A finding requires concrete source-code evidence for a violation such as missing guard, bypassed lock/auth/privilege check, unsafe reset or debug behavior, sensitive readback, or incorrect protection state update.

Return only valid JSON:
{
  "chain_id": "string",
  "has_finding": true,
  "finding": {
    "summary": "string",
    "evidence": [
      {
        "snippet_id": "string",
        "evidence_role": "access_entry | permission_state | guard_logic | protected_resource | lifecycle_behavior | debug_or_test_control | violation | impact",
        "description": "string",
        "supports_claim": "string"
      }
    ],
    "reasoning_summary": "string",
    "security_impact": "string",
    "confidence": "high | medium | low",
    "uncertainty_or_missing_evidence": "string"
  },
  "no_finding_reason": "string"
}

[Permission Chain Context]
"""


def build_prompt(chain: dict[str, Any]) -> str:
    return PROMPT + json.dumps(chain, ensure_ascii=False, indent=2)

