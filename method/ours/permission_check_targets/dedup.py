from __future__ import annotations

from collections import Counter, defaultdict

from method.ours.permission_check_targets.config import PermissionTargetConfig
from method.ours.permission_check_targets.schema import PermissionCheckTarget


HIGH_PRIORITY_ROLES = {
    "debug_interface",
    "lock_state",
    "reset_sensitive_state",
    "register_interface",
    "resource_like",
    "protected_data",
    "crypto_state",
    "secret_state",
    "state_residue_risk",
}


def dedupe_and_trim(
    targets: list[PermissionCheckTarget],
    config: PermissionTargetConfig,
) -> tuple[list[PermissionCheckTarget], dict[str, int]]:
    stats = {
        "deduplicated_target_count": 0,
        "targets_trimmed_by_module_limit": 0,
        "targets_trimmed_by_repo_limit": 0,
    }
    working = targets
    if config.deduplicate_similar_targets:
        deduped: list[PermissionCheckTarget] = []
        seen: set[tuple[str, str, tuple[str, ...]]] = set()
        for target in working:
            key = (
                target.point.module,
                target.point.name,
                tuple(role for role in target.point.point_roles if role in HIGH_PRIORITY_ROLES)
                or tuple(target.point.point_roles[:2]),
            )
            if key in seen:
                stats["deduplicated_target_count"] += 1
                continue
            seen.add(key)
            deduped.append(target)
        working = deduped

    working = sorted(working, key=_target_priority)
    per_module: Counter[str] = Counter()
    module_trimmed: defaultdict[str, int] = defaultdict(int)
    module_kept: list[PermissionCheckTarget] = []
    for target in working:
        if per_module[target.point.module] >= config.max_targets_per_module:
            module_trimmed[target.point.module] += 1
            continue
        per_module[target.point.module] += 1
        module_kept.append(target)
    stats["targets_trimmed_by_module_limit"] = sum(module_trimmed.values())

    if len(module_kept) > config.max_targets_per_repo:
        stats["targets_trimmed_by_repo_limit"] = len(module_kept) - config.max_targets_per_repo
        module_kept = module_kept[: config.max_targets_per_repo]

    return sorted(module_kept, key=lambda target: target.target_id), stats


def _target_priority(target: PermissionCheckTarget) -> tuple[int, str, str]:
    roles = set(target.point.point_roles)
    score = 0
    if "register" in roles:
        score -= 4
    if "output_port" in roles:
        score -= 3
    if "control_like" in roles:
        score -= 2
    if roles & HIGH_PRIORITY_ROLES:
        score -= 2
    return (score, target.point.module, target.point.name)
