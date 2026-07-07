from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from method.ours.permission_check_targets.access_collector import collect_accesses
from method.ours.permission_check_targets.config import PermissionTargetConfig
from method.ours.permission_check_targets.dedup import dedupe_and_trim
from method.ours.permission_check_targets.diagnostics import build_diagnostics
from method.ours.permission_check_targets.graph_index import RtlGraphIndex
from method.ours.permission_check_targets.point_selector import select_candidate_points
from method.ours.permission_check_targets.schema import PermissionCheckTargets, TargetGenerationDiagnostics
from method.ours.permission_check_targets.target_builder import make_target


@dataclass(frozen=True)
class PermissionTargetBuildResult:
    targets: PermissionCheckTargets
    diagnostics: TargetGenerationDiagnostics


def build_permission_check_targets(
    graph: dict[str, Any] | str | Path,
    config: PermissionTargetConfig | None = None,
) -> PermissionTargetBuildResult:
    active_config = config or PermissionTargetConfig()
    graph_payload = _load_graph(graph)
    index = RtlGraphIndex.from_json_dict(graph_payload)
    candidate_points = select_candidate_points(index)

    targets = []
    missing_source_loc_count = 0
    for sequence, point in enumerate(candidate_points, start=1):
        accesses = collect_accesses(index, point.node_id, active_config)
        target = make_target(index, point, accesses, sequence, active_config)
        if not target.source_locs:
            missing_source_loc_count += 1
        targets.append(target)

    final_targets, trim_stats = dedupe_and_trim(targets, active_config)
    diagnostics = build_diagnostics(
        graph_id=index.graph_id,
        candidate_points=candidate_points,
        targets_before_dedup=targets,
        targets_after_dedup=final_targets,
        trim_stats=trim_stats,
        missing_source_loc_count=missing_source_loc_count,
    )
    return PermissionTargetBuildResult(
        targets=PermissionCheckTargets(graph_id=index.graph_id, targets=final_targets),
        diagnostics=diagnostics,
    )


def _load_graph(graph: dict[str, Any] | str | Path) -> dict[str, Any]:
    if isinstance(graph, dict):
        return graph
    return json.loads(Path(graph).read_text(encoding="utf-8"))
