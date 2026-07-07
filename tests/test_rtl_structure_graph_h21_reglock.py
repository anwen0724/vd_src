from pathlib import Path

from method.ours.rtl_structure_graph.builder import build_rtl_structure_graph


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _payload_for_h21_scope():
    repo = (
        _repo_root()
        / "experiments"
        / "baseline_hackatdac21"
        / "agent_input"
        / "h21_access_reglock_reset_expansion_scope"
        / "piton"
        / "design"
        / "chip"
        / "tile"
        / "ariane"
    )
    result = build_rtl_structure_graph(repo, graph_id="h21_access_reglock_reset_expansion_scope")
    return result.graph.to_json_dict()


def test_h21_reglock_scope_contains_acct_cross_module_connection():
    payload = _payload_for_h21_scope()

    node_ids = {node["id"] for node in payload["nodes"]}
    assert "module:riscv_peripherals" in node_ids
    assert "module:acct_wrapper" in node_ids
    assert "instance:riscv_peripherals.i_acct_wrapper" in node_ids
    assert "signal:riscv_peripherals.reglk_ctrl" in node_ids
    assert "signal:acct_wrapper.reglk_ctrl_i" in node_ids

    connects = [edge for edge in payload["edges"] if edge["type"] == "connects"]
    assert any(
        edge["from"] == "signal:riscv_peripherals.reglk_ctrl"
        and edge["to"] == "signal:acct_wrapper.reglk_ctrl_i"
        and edge["attrs"].get("via_instance") == "instance:riscv_peripherals.i_acct_wrapper"
        and edge["attrs"].get("formal_port") == "reglk_ctrl_i"
        for edge in connects
    )


def test_h21_reglock_scope_contains_acct_statement_read_write_chain():
    payload = _payload_for_h21_scope()

    assign_en = next(
        node
        for node in payload["nodes"]
        if node["type"] == "StmtSummary"
        and node["scope"] == "module:acct_wrapper"
        and node["attrs"].get("lhs_raw") == "en"
        and node["attrs"].get("rhs_raw") == "en_acct && acct_ctrl_i"
    )
    acct_mem_node = next(node for node in payload["nodes"] if node["id"] == "signal:acct_wrapper.acct_mem")
    assert acct_mem_node["attrs"]["kind"] == "register"

    reads = {(edge["from"], edge["to"], edge["attrs"].get("read_role")) for edge in payload["edges"] if edge["type"] == "reads"}
    writes = {(edge["from"], edge["to"]) for edge in payload["edges"] if edge["type"] == "writes"}

    assert (assign_en["id"], "signal:acct_wrapper.en") in writes
    assert (assign_en["id"], "signal:acct_wrapper.en_acct", "rhs") in reads
    assert (assign_en["id"], "signal:acct_wrapper.acct_ctrl_i", "rhs") in reads
    assert any(to_id == "signal:acct_wrapper.acct_mem" for _, to_id in writes)
