from method.ours.permission_check_targets.builder import build_permission_check_targets
from method.ours.permission_check_targets.config import PermissionTargetConfig


def _builder_graph():
    return {
        "graph_id": "builder",
        "nodes": [
            {
                "id": "module:regblk",
                "type": "Module",
                "scope": None,
                "name": "regblk",
                "loc": {"file": "regblk.sv", "line_start": 1, "line_end": 80},
                "attrs": {},
            },
            {
                "id": "signal:regblk.cfg_lock",
                "type": "Signal",
                "scope": "module:regblk",
                "name": "cfg_lock",
                "loc": {"file": "regblk.sv", "line_start": 5, "line_end": 5},
                "attrs": {"kind": "register"},
            },
            {
                "id": "signal:regblk.we",
                "type": "Signal",
                "scope": "module:regblk",
                "name": "we",
                "loc": {"file": "regblk.sv", "line_start": 6, "line_end": 6},
                "attrs": {"kind": "port", "direction": "input"},
            },
            {
                "id": "stmt:regblk:20:state_update",
                "type": "StmtSummary",
                "scope": "module:regblk",
                "name": "state_update:20",
                "loc": {"file": "regblk.sv", "line_start": 20, "line_end": 20},
                "attrs": {"kind": "state_update"},
            },
            {
                "id": "stmt:regblk:21:condition",
                "type": "StmtSummary",
                "scope": "module:regblk",
                "name": "condition:21",
                "loc": {"file": "regblk.sv", "line_start": 21, "line_end": 21},
                "attrs": {"kind": "condition"},
            },
        ],
        "edges": [
            {
                "id": "edge:writes:1",
                "type": "writes",
                "from": "stmt:regblk:20:state_update",
                "to": "signal:regblk.cfg_lock",
                "attrs": {"lhs_raw": "cfg_lock"},
            },
            {
                "id": "edge:reads:2",
                "type": "reads",
                "from": "stmt:regblk:21:condition",
                "to": "signal:regblk.cfg_lock",
                "attrs": {"read_role": "condition"},
            },
            {
                "id": "edge:reads:3",
                "type": "reads",
                "from": "stmt:regblk:20:state_update",
                "to": "signal:regblk.we",
                "attrs": {"read_role": "condition"},
            },
        ],
    }


def test_builder_generates_targets_accesses_source_locs_and_diagnostics():
    result = build_permission_check_targets(_builder_graph(), PermissionTargetConfig())
    payload = result.targets.to_json_dict()
    diagnostics = result.diagnostics.to_json_dict()

    assert payload["graph_id"] == "builder"
    assert len(payload["targets"]) == 1
    target = payload["targets"][0]
    assert target["target_id"].startswith("target:regblk:cfg_lock:")
    assert target["point"] == {
        "node_id": "signal:regblk.cfg_lock",
        "name": "cfg_lock",
        "module": "regblk",
        "point_roles": ["control_like", "lock_state", "register", "state_update_target", "write_protection"],
    }
    assert {access["type"] for access in target["accesses"]} == {"write", "control"}
    assert any(loc["role"] == "point" for loc in target["source_locs"])
    assert diagnostics["candidate_point_count"] == 1
    assert diagnostics["target_count_final"] == 1
    assert diagnostics["evidence_mode_distribution"]["explicit"] >= 1


def test_builder_respects_access_source_and_repo_limits():
    config = PermissionTargetConfig(
        max_targets_per_repo=1,
        max_targets_per_module=1,
        max_accesses_per_target=1,
        max_source_locs_per_target=2,
    )
    result = build_permission_check_targets(_builder_graph(), config)
    target = result.targets.to_json_dict()["targets"][0]

    assert len(target["accesses"]) == 1
    assert len(target["source_locs"]) <= 2
    assert result.diagnostics.to_json_dict()["target_count_final"] == 1
