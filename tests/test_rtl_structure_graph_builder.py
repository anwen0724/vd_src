from pathlib import Path

from method.ours.rtl_structure_graph.builder import build_rtl_structure_graph
from method.ours.rtl_structure_graph.extractors.instances import extract_instances
from method.ours.rtl_structure_graph.extractors.modules import extract_modules
from method.ours.rtl_structure_graph.scanner import RtlSource


def _ids_by_type(payload, node_type):
    return {node["id"] for node in payload["nodes"] if node["type"] == node_type}


def _node(payload, node_id):
    for node in payload["nodes"]:
        if node["id"] == node_id:
            return node
    raise AssertionError(f"missing node {node_id}")


def _src_root():
    return Path(__file__).resolve().parents[1]


def test_builder_extracts_cross_module_connections_and_statement_reads_writes(tmp_path):
    repo = Path(tmp_path)
    (repo / "top.sv").write_text(
        """
module child(input logic clk, input logic ctrl_i, output logic out_o);
  logic en;
  logic [7:0] state;

  assign en = ctrl_i;

  always @(posedge clk) begin
    if (en) begin
      state <= state + 1'b1;
    end
  end

  assign out_o = state[0];
endmodule

module top(input logic clk, input logic top_ctrl, output logic top_out);
  child u_child(.clk(clk), .ctrl_i(top_ctrl), .out_o(top_out));
endmodule
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = build_rtl_structure_graph(repo, graph_id="unit")
    payload = result.graph.to_json_dict()

    assert payload["graph_id"] == "unit"
    assert {"module:child", "module:top"} <= _ids_by_type(payload, "Module")
    assert "instance:top.u_child" in _ids_by_type(payload, "Instance")
    assert _node(payload, "instance:top.u_child")["scope"] == "module:top"
    assert _node(payload, "instance:top.u_child")["attrs"]["resolved_module"] == "module:child"
    assert {"signal:top.top_ctrl", "signal:child.ctrl_i", "signal:child.state"} <= _ids_by_type(
        payload, "Signal"
    )
    assert _node(payload, "signal:child.state")["scope"] == "module:child"
    assert _node(payload, "signal:child.state")["attrs"]["kind"] == "register"

    connects = [edge for edge in payload["edges"] if edge["type"] == "connects"]
    assert {
        (edge["from"], edge["to"], edge["attrs"].get("via_instance"))
        for edge in connects
    } >= {
        ("signal:top.top_ctrl", "signal:child.ctrl_i", "instance:top.u_child"),
        ("signal:child.out_o", "signal:top.top_out", "instance:top.u_child"),
    }

    reads = {(edge["from"], edge["to"], edge["attrs"].get("read_role")) for edge in payload["edges"] if edge["type"] == "reads"}
    writes = {(edge["from"], edge["to"]) for edge in payload["edges"] if edge["type"] == "writes"}

    assign_en_stmt = next(
        node["id"]
        for node in payload["nodes"]
        if node["type"] == "StmtSummary" and node["attrs"].get("lhs_raw") == "en"
    )
    state_update_stmt = next(
        node["id"]
        for node in payload["nodes"]
        if node["type"] == "StmtSummary" and node["attrs"].get("lhs_raw") == "state"
    )

    assert (assign_en_stmt, "signal:child.en") in writes
    assert (assign_en_stmt, "signal:child.ctrl_i", "rhs") in reads
    assert (state_update_stmt, "signal:child.state") in writes
    assert (state_update_stmt, "signal:child.en", "condition") in reads
    assert (state_update_stmt, "signal:child.state", "rhs") in reads
    assert all("loc" not in edge for edge in payload["edges"])


def test_builder_does_not_treat_control_constructs_as_instances(tmp_path):
    repo = Path(tmp_path)
    (repo / "top.sv").write_text(
        """
module child(input logic a);
endmodule

module top(input logic clk, input logic sel, output logic out);
  generate
    genvar i;
    for (i = 0; i < 2; i = i + 1) begin : gen_blk
    end
  endgenerate

  always_comb
  begin
    unique case (sel)
      1'b0: out = 1'b0;
      default: out = 1'b1;
    endcase
  end

  always_comb
  begin
    if (sel)
    begin
      out = 1'b1;
    end
    if (out)
    begin
      out = sel;
    end
  end

  assert property (@(posedge clk) sel |-> out);

  child u_child(.a(sel));
endmodule
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = build_rtl_structure_graph(repo, graph_id="control_constructs")
    payload = result.graph.to_json_dict()

    instances = [node for node in payload["nodes"] if node["type"] == "Instance"]
    assert [node["id"] for node in instances] == ["instance:top.u_child"]


def test_instance_extractor_does_not_treat_real_begin_if_blocks_as_instances():
    source_path = (
        _src_root()
        / "datasets"
        / "agent_inputs"
        / "hackatdac18"
        / "debug_jtag_scope"
        / "ips"
        / "adv_dbg_if"
        / "rtl"
        / "adbg_axi_biu.sv"
    )
    source = RtlSource(
        path=source_path,
        relative_path="ips/adv_dbg_if/rtl/adbg_axi_biu.sv",
        text=source_path.read_text(encoding="utf-8", errors="ignore"),
    )
    modules = extract_modules(source)
    known_modules = {module.name for module in modules}

    bad_instances = [
        instance
        for module in modules
        for instance in extract_instances(module, known_modules)
        if instance.module_type in {"begin", "end", "endcase"}
        or instance.name in {"if", "case", "for"}
    ]

    assert bad_instances == []
