import json

from method.ours.permission_check_targets.config import PermissionTargetConfig
from method.ours.permission_check_targets.schema import (
    PermissionCheckTarget,
    PermissionCheckTargets,
    TargetAccess,
    TargetGenerationDiagnostics,
    TargetPoint,
    TargetSourceLoc,
)


def test_targets_json_has_formal_interface_only_and_diagnostics_stays_separate():
    target = PermissionCheckTarget(
        target_id="target:regblk:cfg_lock:1",
        point=TargetPoint(
            node_id="signal:regblk.cfg_lock",
            name="cfg_lock",
            module="regblk",
            point_roles=["lock_state", "write_protection"],
        ),
        accesses=[
            TargetAccess(
                node_id="stmt:regblk:12:state_update",
                kind="state_update",
                type="write",
                access_roles=["state_update", "register_write"],
            )
        ],
        source_locs=[
            TargetSourceLoc(
                node_id="signal:regblk.cfg_lock",
                file="rtl/regblk.sv",
                line_start=7,
                line_end=7,
                role="point",
            )
        ],
    )
    payload = PermissionCheckTargets(graph_id="demo", targets=[target]).to_json_dict()
    diagnostics = TargetGenerationDiagnostics(graph_id="demo")
    diagnostics.candidate_point_count = 3

    assert set(payload) == {"graph_id", "schema_version", "generation_mode", "targets"}
    assert payload["schema_version"] == "0.1"
    assert payload["generation_mode"] == "algorithm"
    assert payload["targets"][0]["point"]["point_roles"] == ["lock_state", "write_protection"]
    assert "candidate_point_count" not in payload
    assert diagnostics.to_json_dict()["candidate_point_count"] == 3
    json.dumps(payload, ensure_ascii=False)
    json.dumps(diagnostics.to_json_dict(), ensure_ascii=False)


def test_default_config_prefers_recall_but_limits_cost():
    config = PermissionTargetConfig()

    assert config.max_targets_per_repo == 160
    assert config.max_targets_per_module == 80
    assert config.max_accesses_per_target == 12
    assert config.max_source_locs_per_target == 16
    assert config.deduplicate_similar_targets is True
