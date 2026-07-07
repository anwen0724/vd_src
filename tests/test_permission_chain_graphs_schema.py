import pytest

from method.ours.permission_chain_graphs.schema import (
    ChainEdge,
    ChainLoc,
    ChainNode,
    ChainSourceLocation,
    ChainTargetRef,
    PermissionChain,
    PermissionChainGraphs,
    assert_no_forbidden_formal_keys,
)


def test_chain_graph_schema_contains_only_formal_fields():
    graph = PermissionChainGraphs(
        graph_id="g",
        chains=[
            PermissionChain(
                chain_id="CHAIN-0001",
                seed_targets=[ChainTargetRef(target_id="T", node_id="signal:m.s", name="s", module="m")],
                nodes=[
                    ChainNode(
                        node_id="signal:m.s",
                        kind="Signal",
                        name="s",
                        module="m",
                        loc=ChainLoc(file="rtl/a.sv", line_start=1, line_end=1),
                    )
                ],
                edges=[ChainEdge(edge_id="edge:1", src="signal:m.s", dst="stmt:m:1:x", kind="reads")],
                source_locations=[
                    ChainSourceLocation(
                        loc_id="LOC-0001",
                        file="rtl/a.sv",
                        line_start=1,
                        line_end=1,
                        node_ids=["signal:m.s"],
                    )
                ],
            )
        ],
    ).to_json_dict()
    assert set(graph) == {"graph_id", "schema_version", "chains"}
    assert set(graph["chains"][0]) == {"chain_id", "seed_targets", "nodes", "edges", "source_locations"}


def test_forbidden_formal_keys_are_rejected():
    with pytest.raises(ValueError):
        assert_no_forbidden_formal_keys({"chains": [{"chain_question": "bad"}]})
