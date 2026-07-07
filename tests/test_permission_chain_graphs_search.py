from method.ours.permission_chain_graphs.chain_search import build_chains
from method.ours.permission_chain_graphs.config import PermissionChainGraphConfig
from method.ours.permission_chain_graphs.graph_index import ChainGraphIndex


def _graph():
    return {
        "graph_id": "g",
        "nodes": [
            {"id": "signal:top.req", "type": "Signal", "scope": "module:top", "name": "req", "loc": {"file": "top.sv", "line_start": 1, "line_end": 1}},
            {"id": "signal:child.req_i", "type": "Signal", "scope": "module:child", "name": "req_i", "loc": {"file": "child.sv", "line_start": 2, "line_end": 2}},
            {"id": "stmt:child:3:assign", "type": "StmtSummary", "scope": "module:child", "name": "assign:3", "loc": {"file": "child.sv", "line_start": 3, "line_end": 3}},
            {"id": "signal:child.rdata", "type": "Signal", "scope": "module:child", "name": "rdata", "loc": {"file": "child.sv", "line_start": 4, "line_end": 4}},
            {"id": "instance:top.i_child", "type": "Instance", "scope": "module:top", "name": "i_child", "loc": {"file": "top.sv", "line_start": 10, "line_end": 10}},
        ],
        "edges": [
            {"id": "edge:connects:1", "type": "connects", "from": "signal:top.req", "to": "signal:child.req_i", "attrs": {"via_instance": "instance:top.i_child"}},
            {"id": "edge:reads:1", "type": "reads", "from": "stmt:child:3:assign", "to": "signal:child.req_i"},
            {"id": "edge:writes:1", "type": "writes", "from": "stmt:child:3:assign", "to": "signal:child.rdata"},
        ],
    }


def test_search_includes_connects_statements_and_instance_locations():
    target = {
        "target_id": "T",
        "point": {"node_id": "signal:child.req_i", "name": "req_i", "module": "child"},
        "accesses": [],
    }
    chains, diagnostics = build_chains([target], ChainGraphIndex(_graph()), PermissionChainGraphConfig(max_depth=3))
    chain = chains[0]
    node_ids = {node.node_id for node in chain.nodes}
    edge_ids = {edge.edge_id for edge in chain.edges}
    assert "signal:top.req" in node_ids
    assert "stmt:child:3:assign" in node_ids
    assert "instance:top.i_child" in node_ids
    assert "edge:connects:1" in edge_ids
    assert "edge:reads:1" in edge_ids
    assert diagnostics[0].source_location_count >= 3
