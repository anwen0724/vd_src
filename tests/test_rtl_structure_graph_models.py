from method.ours.rtl_structure_graph.models import (
    GraphEdge,
    GraphNode,
    RtlGraph,
    SourceLoc,
)


def test_graph_json_has_formal_interface_only_and_edges_have_no_loc():
    graph = RtlGraph(graph_id="demo")
    graph.add_node(
        GraphNode(
            id="module:top",
            type="Module",
            scope=None,
            name="top",
            loc=SourceLoc(file="top.sv", line_start=1, line_end=3),
            attrs={"parameters": ""},
        )
    )
    graph.add_node(
        GraphNode(
            id="signal:top.en",
            type="Signal",
            scope="top",
            name="en",
            loc=SourceLoc(file="top.sv", line_start=2, line_end=2),
            attrs={"kind": "port", "direction": "input"},
        )
    )
    graph.add_edge(
        GraphEdge(
            id="edge:reads:1",
            type="reads",
            from_id="stmt:top:2:continuous_assign",
            to_id="signal:top.en",
            attrs={"read_role": "rhs"},
        )
    )

    payload = graph.to_json_dict()

    assert set(payload) == {"graph_id", "nodes", "edges"}
    assert payload["nodes"][0]["loc"] == {
        "file": "top.sv",
        "line_start": 1,
        "line_end": 3,
    }
    assert payload["edges"][0] == {
        "id": "edge:reads:1",
        "type": "reads",
        "from": "stmt:top:2:continuous_assign",
        "to": "signal:top.en",
        "attrs": {"read_role": "rhs"},
    }
    assert "loc" not in payload["edges"][0]
