from __future__ import annotations

import json
from typing import Any


def build_action_prompt(chain: dict[str, Any], allowed_files: list[str], max_actions: int) -> str:
    reduced = _strip_large_attrs(chain)
    return f"""You are planning controlled source inspection for an RTL permission chain graph.

You are given a graph-only permission chain. It is not source code.
Choose source reads/searches needed to inspect whether the chain supports a permission-related vulnerability.

Allowed files:
{json.dumps(allowed_files, ensure_ascii=False, indent=2)}

Rules:
- Use only read_around or search_in_file.
- file must be one of the allowed files.
- Prefer reading around source_locations first.
- Keep at most {max_actions} actions.
- Do not mention or request benchmark ground truth, case documents, scoring files, or evidence_gt files.

Return JSON:
{{
  "chain_id": "string",
  "actions": [
    {{"tool": "read_around", "file": "string", "line_start": 1, "line_end": 1, "reason": "string"}},
    {{"tool": "search_in_file", "file": "string", "query": "string", "reason": "string"}}
  ]
}}

Chain graph:
{json.dumps(reduced, ensure_ascii=False, indent=2)}
"""


def build_synthesis_prompt(chain: dict[str, Any], observations: list[dict[str, Any]]) -> str:
    reduced = _strip_large_attrs(chain)
    return f"""You are analyzing a SystemVerilog RTL permission-security chain.

You are given:
1. the graph-only permission chain;
2. source observations produced by controlled read/search tools.

Use only the source observations as source-code evidence. The graph helps interpret relationships but is not itself evidence.

Decide whether there is a permission-related vulnerability finding. A finding requires concrete source evidence for a violation such as missing guard, bypassed lock/auth/privilege check, unsafe reset/debug behavior, sensitive readback, or incorrect protection-state update.

Return only JSON:
{{
  "chain_id": "string",
  "has_finding": true,
  "finding": {{
    "summary": "string",
    "evidence": [
      {{
        "file": "string",
        "line_start": 1,
        "line_end": 1,
        "module": "string",
        "object": "string",
        "evidence_role": "access_entry | permission_state | guard_logic | protected_resource | lifecycle_behavior | debug_or_test_control | violation | impact",
        "description": "string",
        "supports_claim": "string"
      }}
    ],
    "reasoning_summary": "string",
    "security_impact": "string",
    "confidence": "high | medium | low",
    "uncertainty_or_missing_evidence": "string"
  }},
  "no_finding_reason": "string"
}}

Chain graph:
{json.dumps(reduced, ensure_ascii=False, indent=2)}

Tool observations:
{json.dumps(observations, ensure_ascii=False, indent=2)}
"""


def _strip_large_attrs(chain: dict[str, Any]) -> dict[str, Any]:
    return {
        "chain_id": chain.get("chain_id"),
        "seed_targets": chain.get("seed_targets", []),
        "nodes": chain.get("nodes", []),
        "edges": chain.get("edges", []),
        "source_locations": chain.get("source_locations", []),
    }

