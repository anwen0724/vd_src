from __future__ import annotations

from collections import Counter

from method.ours.permission_check_targets.point_selector import CandidatePoint
from method.ours.permission_check_targets.schema import PermissionCheckTarget, TargetGenerationDiagnostics
from method.ours.permission_check_targets.target_builder import count_roles


def build_diagnostics(
    graph_id: str,
    candidate_points: list[CandidatePoint],
    targets_before_dedup: list[PermissionCheckTarget],
    targets_after_dedup: list[PermissionCheckTarget],
    trim_stats: dict[str, int],
    missing_source_loc_count: int,
) -> TargetGenerationDiagnostics:
    point_roles, access_roles = count_roles(targets_after_dedup)
    matched_rules: Counter[str] = Counter()
    evidence_modes: Counter[str] = Counter()
    for point in candidate_points:
        matched_rules.update(point.matched_rules)
        evidence_modes.update(point.evidence_modes.values())

    return TargetGenerationDiagnostics(
        graph_id=graph_id,
        candidate_point_count=len(candidate_points),
        target_count_before_dedup=len(targets_before_dedup),
        target_count_after_dedup=len(targets_after_dedup),
        target_count_final=len(targets_after_dedup),
        point_roles_distribution=point_roles,
        access_roles_distribution=access_roles,
        matched_rules_distribution=dict(matched_rules),
        evidence_mode_distribution=dict(evidence_modes),
        targets_trimmed_by_repo_limit=trim_stats.get("targets_trimmed_by_repo_limit", 0),
        targets_trimmed_by_module_limit=trim_stats.get("targets_trimmed_by_module_limit", 0),
        deduplicated_target_count=trim_stats.get("deduplicated_target_count", 0),
        missing_source_loc_count=missing_source_loc_count,
        reset_branch_explicit=False,
        warnings=[],
    )
