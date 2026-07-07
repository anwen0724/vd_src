from method.ours.permission_check_targets.evidence import EvidenceAnalyzer
from method.ours.permission_check_targets.graph_index import RtlGraphIndex
from method.ours.permission_check_targets.point_selector import select_candidate_points


def _rule_graph():
    nodes = [
        {
            "id": "module:top",
            "type": "Module",
            "scope": None,
            "name": "top",
            "loc": {"file": "top.sv", "line_start": 1, "line_end": 100},
            "attrs": {},
        },
        {
            "id": "signal:top.jtag_unlock",
            "type": "Signal",
            "scope": "module:top",
            "name": "jtag_unlock",
            "loc": {"file": "top.sv", "line_start": 3, "line_end": 3},
            "attrs": {"kind": "port", "direction": "input"},
        },
        {
            "id": "signal:top.cfg_lock",
            "type": "Signal",
            "scope": "module:top",
            "name": "cfg_lock",
            "loc": {"file": "top.sv", "line_start": 4, "line_end": 4},
            "attrs": {"kind": "register"},
        },
        {
            "id": "signal:top.aes_key0",
            "type": "Signal",
            "scope": "module:top",
            "name": "aes_key0",
            "loc": {"file": "top.sv", "line_start": 5, "line_end": 5},
            "attrs": {"kind": "register"},
        },
        {
            "id": "signal:top.valid",
            "type": "Signal",
            "scope": "module:top",
            "name": "valid",
            "loc": {"file": "top.sv", "line_start": 6, "line_end": 6},
            "attrs": {"kind": "internal"},
        },
        {
            "id": "signal:top.secure_idle",
            "type": "Signal",
            "scope": "module:top",
            "name": "secure_idle",
            "loc": {"file": "top.sv", "line_start": 7, "line_end": 7},
            "attrs": {"kind": "internal"},
        },
        {
            "id": "signal:top.rst_debug_flag",
            "type": "Signal",
            "scope": "module:top",
            "name": "rst_debug_flag",
            "loc": {"file": "top.sv", "line_start": 8, "line_end": 8},
            "attrs": {"kind": "internal"},
        },
        {
            "id": "stmt:top:20:state_update",
            "type": "StmtSummary",
            "scope": "module:top",
            "name": "state_update:20",
            "loc": {"file": "top.sv", "line_start": 20, "line_end": 20},
            "attrs": {"kind": "state_update"},
        },
        {
            "id": "stmt:top:30:continuous_assign",
            "type": "StmtSummary",
            "scope": "module:top",
            "name": "continuous_assign:30",
            "loc": {"file": "top.sv", "line_start": 30, "line_end": 30},
            "attrs": {"kind": "continuous_assign"},
        },
    ]
    edges = [
        {
            "id": "edge:writes:1",
            "type": "writes",
            "from": "stmt:top:20:state_update",
            "to": "signal:top.cfg_lock",
            "attrs": {},
        },
        {
            "id": "edge:reads:2",
            "type": "reads",
            "from": "stmt:top:30:continuous_assign",
            "to": "signal:top.aes_key0",
            "attrs": {"read_role": "rhs"},
        },
        {
            "id": "edge:writes:3",
            "type": "writes",
            "from": "stmt:top:20:state_update",
            "to": "signal:top.rst_debug_flag",
            "attrs": {},
        },
    ]
    return {"graph_id": "rules", "nodes": nodes, "edges": edges}


def test_rules_select_permission_targets_and_exclude_weak_or_unstructured_names():
    index = RtlGraphIndex.from_json_dict(_rule_graph())
    points = {point.node_id: point for point in select_candidate_points(index)}

    assert "signal:top.jtag_unlock" in points
    assert {"debug_interface", "auth_state"} <= set(points["signal:top.jtag_unlock"].point_roles)
    assert "signal:top.cfg_lock" in points
    assert {"lock_state", "write_protection"} <= set(points["signal:top.cfg_lock"].point_roles)
    assert "signal:top.aes_key0" in points
    assert {"secret_state", "crypto_state"} <= set(points["signal:top.aes_key0"].point_roles)
    assert "signal:top.valid" not in points
    assert "signal:top.secure_idle" not in points
    assert "signal:top.rst_debug_flag" in points
    assert "reset_sensitive_state" in points["signal:top.rst_debug_flag"].point_roles
    assert points["signal:top.rst_debug_flag"].evidence_modes["reset_related"] == "inferred"


def test_evidence_reports_explicit_inferred_and_unavailable_modes():
    index = RtlGraphIndex.from_json_dict(_rule_graph())
    evidence = EvidenceAnalyzer(index)

    assert evidence.is_register("signal:top.cfg_lock").mode == "explicit"
    assert evidence.is_state_update_target("signal:top.cfg_lock").mode == "explicit"
    assert evidence.is_condition_used("signal:top.cfg_lock").mode == "unavailable"
    assert evidence.is_reset_related("signal:top.rst_debug_flag").mode == "inferred"


def test_module_or_bus_context_alone_does_not_turn_every_signal_into_a_point():
    graph = {
        "graph_id": "context_noise",
        "nodes": [
            {
                "id": "module:adbg_axi_biu",
                "type": "Module",
                "scope": None,
                "name": "adbg_axi_biu",
                "loc": {"file": "adbg_axi_biu.sv", "line_start": 1, "line_end": 50},
                "attrs": {},
            },
            {
                "id": "signal:adbg_axi_biu.addr_reg",
                "type": "Signal",
                "scope": "module:adbg_axi_biu",
                "name": "addr_reg",
                "loc": {"file": "adbg_axi_biu.sv", "line_start": 4, "line_end": 4},
                "attrs": {"kind": "register"},
            },
            {
                "id": "module:apb_adv_timer",
                "type": "Module",
                "scope": None,
                "name": "apb_adv_timer",
                "loc": {"file": "apb_adv_timer.sv", "line_start": 1, "line_end": 60},
                "attrs": {},
            },
            {
                "id": "signal:apb_adv_timer:HCLK",
                "type": "Signal",
                "scope": "module:apb_adv_timer",
                "name": "HCLK",
                "loc": {"file": "apb_adv_timer.sv", "line_start": 2, "line_end": 2},
                "attrs": {"kind": "port", "direction": "input"},
            },
            {
                "id": "signal:apb_adv_timer:PADDR",
                "type": "Signal",
                "scope": "module:apb_adv_timer",
                "name": "PADDR",
                "loc": {"file": "apb_adv_timer.sv", "line_start": 3, "line_end": 3},
                "attrs": {"kind": "port", "direction": "input"},
            },
        ],
        "edges": [],
    }
    points = {point.node_id: point for point in select_candidate_points(RtlGraphIndex.from_json_dict(graph))}

    assert "signal:adbg_axi_biu.addr_reg" not in points
    assert "signal:apb_adv_timer:HCLK" not in points
    assert "signal:apb_adv_timer:PADDR" not in points


def test_implicit_macro_or_enum_like_constants_are_not_points():
    graph = {
        "graph_id": "constants",
        "nodes": [
            {
                "id": "module:adbg_axi_module",
                "type": "Module",
                "scope": None,
                "name": "adbg_axi_module",
                "loc": {"file": "adbg_axi_module.sv", "line_start": 1, "line_end": 100},
                "attrs": {},
            },
            {
                "id": "signal:adbg_axi_module.DBG_AXI_CMD_BREAD16",
                "type": "Signal",
                "scope": "module:adbg_axi_module",
                "name": "DBG_AXI_CMD_BREAD16",
                "loc": {"file": "adbg_axi_module.sv", "line_start": 20, "line_end": 20},
                "attrs": {"kind": "implicit", "decl_raw": None},
            },
            {
                "id": "signal:adbg_axi_module.STATE_Rburst",
                "type": "Signal",
                "scope": "module:adbg_axi_module",
                "name": "STATE_Rburst",
                "loc": {"file": "adbg_axi_module.sv", "line_start": 21, "line_end": 21},
                "attrs": {"kind": "implicit", "decl_raw": None},
            },
        ],
        "edges": [
            {
                "id": "edge:reads:1",
                "type": "reads",
                "from": "stmt:adbg_axi_module:30:condition",
                "to": "signal:adbg_axi_module.DBG_AXI_CMD_BREAD16",
                "attrs": {"read_role": "condition"},
            }
        ],
    }

    points = {point.node_id: point for point in select_candidate_points(RtlGraphIndex.from_json_dict(graph))}

    assert "signal:adbg_axi_module.DBG_AXI_CMD_BREAD16" not in points
    assert "signal:adbg_axi_module.STATE_Rburst" not in points


def test_generic_length_signal_is_not_dma_pmp_point_without_dma_or_pmp_context():
    graph = {
        "graph_id": "length",
        "nodes": [
            {
                "id": "module:tap",
                "type": "Module",
                "scope": None,
                "name": "tap",
                "loc": {"file": "tap.sv", "line_start": 1, "line_end": 10},
                "attrs": {},
            },
            {
                "id": "signal:tap.IR_LENGTH",
                "type": "Signal",
                "scope": "module:tap",
                "name": "IR_LENGTH",
                "loc": {"file": "tap.sv", "line_start": 2, "line_end": 2},
                "attrs": {"kind": "register"},
            },
        ],
        "edges": [],
    }
    points = {point.node_id: point for point in select_candidate_points(RtlGraphIndex.from_json_dict(graph))}

    assert "signal:tap.IR_LENGTH" not in points


def test_resource_named_peripheral_paths_are_permission_targets():
    graph = {
        "graph_id": "resource_paths",
        "nodes": [
            {
                "id": "module:riscv_peripherals",
                "type": "Module",
                "scope": None,
                "name": "riscv_peripherals",
                "loc": {"file": "riscv_peripherals.sv", "line_start": 1, "line_end": 200},
                "attrs": {},
            },
            {
                "id": "signal:riscv_peripherals.plic_req",
                "type": "Signal",
                "scope": "module:riscv_peripherals",
                "name": "plic_req",
                "loc": {"file": "riscv_peripherals.sv", "line_start": 20, "line_end": 20},
                "attrs": {"kind": "internal"},
            },
            {
                "id": "signal:riscv_peripherals.rom_req",
                "type": "Signal",
                "scope": "module:riscv_peripherals",
                "name": "rom_req",
                "loc": {"file": "riscv_peripherals.sv", "line_start": 30, "line_end": 30},
                "attrs": {"kind": "internal"},
            },
            {
                "id": "stmt:riscv_peripherals:40:continuous_assign",
                "type": "StmtSummary",
                "scope": "module:riscv_peripherals",
                "name": "continuous_assign:40",
                "loc": {"file": "riscv_peripherals.sv", "line_start": 40, "line_end": 40},
                "attrs": {"kind": "continuous_assign"},
            },
        ],
        "edges": [
            {
                "id": "edge:writes:1",
                "type": "writes",
                "from": "stmt:riscv_peripherals:40:continuous_assign",
                "to": "signal:riscv_peripherals.plic_req",
                "attrs": {},
            },
            {
                "id": "edge:reads:2",
                "type": "reads",
                "from": "stmt:riscv_peripherals:40:continuous_assign",
                "to": "signal:riscv_peripherals.rom_req",
                "attrs": {"read_role": "rhs"},
            },
        ],
    }

    points = {point.node_id: point for point in select_candidate_points(RtlGraphIndex.from_json_dict(graph))}

    assert "signal:riscv_peripherals.plic_req" in points
    assert "resource_like" in points["signal:riscv_peripherals.plic_req"].point_roles
    assert "signal:riscv_peripherals.rom_req" in points
    assert "resource_like" in points["signal:riscv_peripherals.rom_req"].point_roles


def test_reset_controller_state_and_outputs_are_permission_targets():
    graph = {
        "graph_id": "reset_controller",
        "nodes": [
            {
                "id": "module:rst_wrapper",
                "type": "Module",
                "scope": None,
                "name": "rst_wrapper",
                "loc": {"file": "rst_ctrl/rst_wrapper.sv", "line_start": 1, "line_end": 200},
                "attrs": {},
            },
            {
                "id": "signal:rst_wrapper.rst_mem",
                "type": "Signal",
                "scope": "module:rst_wrapper",
                "name": "rst_mem",
                "loc": {"file": "rst_ctrl/rst_wrapper.sv", "line_start": 50, "line_end": 50},
                "attrs": {"kind": "register"},
            },
            {
                "id": "signal:rst_wrapper.rst_id",
                "type": "Signal",
                "scope": "module:rst_wrapper",
                "name": "rst_id",
                "loc": {"file": "rst_ctrl/rst_wrapper.sv", "line_start": 51, "line_end": 51},
                "attrs": {"kind": "register"},
            },
            {
                "id": "signal:rst_wrapper.start",
                "type": "Signal",
                "scope": "module:rst_wrapper",
                "name": "start",
                "loc": {"file": "rst_ctrl/rst_wrapper.sv", "line_start": 52, "line_end": 52},
                "attrs": {"kind": "register"},
            },
            {
                "id": "signal:rst_wrapper.rst_9",
                "type": "Signal",
                "scope": "module:rst_wrapper",
                "name": "rst_9",
                "loc": {"file": "rst_ctrl/rst_wrapper.sv", "line_start": 53, "line_end": 53},
                "attrs": {"kind": "port", "direction": "output"},
            },
            {
                "id": "stmt:rst_wrapper:80:state_update",
                "type": "StmtSummary",
                "scope": "module:rst_wrapper",
                "name": "state_update:80",
                "loc": {"file": "rst_ctrl/rst_wrapper.sv", "line_start": 80, "line_end": 80},
                "attrs": {"kind": "state_update"},
            },
            {
                "id": "stmt:rst_wrapper:90:continuous_assign",
                "type": "StmtSummary",
                "scope": "module:rst_wrapper",
                "name": "continuous_assign:90",
                "loc": {"file": "rst_ctrl/rst_wrapper.sv", "line_start": 90, "line_end": 90},
                "attrs": {"kind": "continuous_assign"},
            },
        ],
        "edges": [
            {"id": "edge:writes:1", "type": "writes", "from": "stmt:rst_wrapper:80:state_update", "to": "signal:rst_wrapper.rst_mem", "attrs": {}},
            {"id": "edge:writes:2", "type": "writes", "from": "stmt:rst_wrapper:80:state_update", "to": "signal:rst_wrapper.rst_id", "attrs": {}},
            {"id": "edge:writes:3", "type": "writes", "from": "stmt:rst_wrapper:80:state_update", "to": "signal:rst_wrapper.start", "attrs": {}},
            {"id": "edge:writes:4", "type": "writes", "from": "stmt:rst_wrapper:90:continuous_assign", "to": "signal:rst_wrapper.rst_9", "attrs": {}},
        ],
    }

    points = {point.node_id: point for point in select_candidate_points(RtlGraphIndex.from_json_dict(graph))}

    assert "signal:rst_wrapper.rst_mem" in points
    assert "signal:rst_wrapper.rst_id" in points
    assert "signal:rst_wrapper.start" in points
    assert "signal:rst_wrapper.rst_9" in points
    assert "reset_sensitive_state" in points["signal:rst_wrapper.start"].point_roles


def test_crypto_wrapper_state_and_readout_are_permission_targets():
    graph = {
        "graph_id": "crypto_state",
        "nodes": [
            {
                "id": "module:rsa_wrapper",
                "type": "Module",
                "scope": None,
                "name": "rsa_wrapper",
                "loc": {"file": "rsa/rsa_wrapper.sv", "line_start": 1, "line_end": 520},
                "attrs": {},
            },
            {
                "id": "signal:rsa_wrapper.msg_out",
                "type": "Signal",
                "scope": "module:rsa_wrapper",
                "name": "msg_out",
                "loc": {"file": "rsa/rsa_wrapper.sv", "line_start": 33, "line_end": 33},
                "attrs": {"kind": "internal"},
            },
            {
                "id": "signal:rsa_wrapper.msg_in",
                "type": "Signal",
                "scope": "module:rsa_wrapper",
                "name": "msg_in",
                "loc": {"file": "rsa/rsa_wrapper.sv", "line_start": 33, "line_end": 33},
                "attrs": {"kind": "register"},
            },
            {
                "id": "signal:rsa_wrapper.rdata",
                "type": "Signal",
                "scope": "module:rsa_wrapper",
                "name": "rdata",
                "loc": {"file": "rsa/rsa_wrapper.sv", "line_start": 40, "line_end": 40},
                "attrs": {"kind": "internal"},
            },
            {
                "id": "signal:rsa_wrapper.inter_rst_ni",
                "type": "Signal",
                "scope": "module:rsa_wrapper",
                "name": "inter_rst_ni",
                "loc": {"file": "rsa/rsa_wrapper.sv", "line_start": 27, "line_end": 27},
                "attrs": {"kind": "register"},
            },
            {
                "id": "signal:rsa_wrapper.rst_13",
                "type": "Signal",
                "scope": "module:rsa_wrapper",
                "name": "rst_13",
                "loc": {"file": "rsa/rsa_wrapper.sv", "line_start": 21, "line_end": 21},
                "attrs": {"kind": "port", "direction": "input"},
            },
            {
                "id": "stmt:rsa_wrapper:75:state_update",
                "type": "StmtSummary",
                "scope": "module:rsa_wrapper",
                "name": "state_update:75",
                "loc": {"file": "rsa/rsa_wrapper.sv", "line_start": 75, "line_end": 75},
                "attrs": {"kind": "state_update"},
            },
            {
                "id": "stmt:rsa_wrapper:359:procedural_assign",
                "type": "StmtSummary",
                "scope": "module:rsa_wrapper",
                "name": "procedural_assign:359",
                "loc": {"file": "rsa/rsa_wrapper.sv", "line_start": 359, "line_end": 359},
                "attrs": {"kind": "procedural_assign", "lhs_raw": "rdata", "rhs_raw": "msg_out[31:0]"},
            },
            {
                "id": "stmt:rsa_wrapper:63:continuous_assign",
                "type": "StmtSummary",
                "scope": "module:rsa_wrapper",
                "name": "continuous_assign:63",
                "loc": {"file": "rsa/rsa_wrapper.sv", "line_start": 63, "line_end": 63},
                "attrs": {"kind": "continuous_assign", "lhs_raw": "exe_finish_o", "rhs_raw": "rst_13 ? 1'b1 : exe_finish"},
            },
        ],
        "edges": [
            {"id": "edge:writes:1", "type": "writes", "from": "stmt:rsa_wrapper:75:state_update", "to": "signal:rsa_wrapper.msg_in", "attrs": {}},
            {"id": "edge:writes:2", "type": "writes", "from": "stmt:rsa_wrapper:75:state_update", "to": "signal:rsa_wrapper.inter_rst_ni", "attrs": {}},
            {"id": "edge:writes:3", "type": "writes", "from": "stmt:rsa_wrapper:359:procedural_assign", "to": "signal:rsa_wrapper.rdata", "attrs": {}},
            {"id": "edge:reads:4", "type": "reads", "from": "stmt:rsa_wrapper:359:procedural_assign", "to": "signal:rsa_wrapper.msg_out", "attrs": {"read_role": "rhs"}},
            {"id": "edge:reads:5", "type": "reads", "from": "stmt:rsa_wrapper:63:continuous_assign", "to": "signal:rsa_wrapper.rst_13", "attrs": {"read_role": "condition"}},
        ],
    }

    points = {point.node_id: point for point in select_candidate_points(RtlGraphIndex.from_json_dict(graph))}

    assert "signal:rsa_wrapper.msg_out" in points
    assert {"crypto_state", "protected_data"} <= set(points["signal:rsa_wrapper.msg_out"].point_roles)
    assert "signal:rsa_wrapper.msg_in" in points
    assert "signal:rsa_wrapper.rdata" in points
    assert "signal:rsa_wrapper.inter_rst_ni" in points
    assert "signal:rsa_wrapper.rst_13" in points
