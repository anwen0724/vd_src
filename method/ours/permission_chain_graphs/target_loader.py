from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .schema import ChainTargetRef


def load_targets(path: str | Path) -> tuple[str, list[dict[str, Any]]]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return str(doc.get("graph_id", "")), list(doc.get("targets", []))


def target_ref(target: dict[str, Any]) -> ChainTargetRef:
    point = target.get("point") or {}
    return ChainTargetRef(
        target_id=str(target.get("target_id", "")),
        node_id=str(point.get("node_id", "")),
        name=str(point.get("name", "")),
        module=str(point.get("module", "")),
    )


def seed_node_ids(target: dict[str, Any], include_access_nodes: bool = True) -> list[str]:
    result: list[str] = []
    point = target.get("point") or {}
    if point.get("node_id"):
        result.append(str(point["node_id"]))
    if include_access_nodes:
        for access in target.get("accesses", []) or []:
            node_id = access.get("node_id")
            if node_id and str(node_id) not in result:
                result.append(str(node_id))
    return result

