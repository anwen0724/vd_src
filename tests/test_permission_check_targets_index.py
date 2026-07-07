from method.ours.permission_check_targets.graph_index import RtlGraphIndex


def _sample_graph():
    return {
        "graph_id": "demo",
        "nodes": [
            {
                "id": "module:top",
                "type": "Module",
                "scope": None,
                "name": "top",
                "loc": {"file": "top.sv", "line_start": 1, "line_end": 20},
                "attrs": {},
            },
            {
                "id": "signal:top.debug_req",
                "type": "Signal",
                "scope": "module:top",
                "name": "debug_req",
                "loc": {"file": "top.sv", "line_start": 3, "line_end": 3},
                "attrs": {"kind": "port", "direction": "input"},
            },
            {
                "id": "signal:top.auth_flag",
                "type": "Signal",
                "scope": "module:top",
                "name": "auth_flag",
                "loc": {"file": "top.sv", "line_start": 4, "line_end": 4},
                "attrs": {"kind": "register"},
            },
            {
                "id": "stmt:top:9:state_update",
                "type": "StmtSummary",
                "scope": "module:top",
                "name": "state_update:9",
                "loc": {"file": "top.sv", "line_start": 9, "line_end": 9},
                "attrs": {"kind": "state_update"},
            },
        ],
        "edges": [
            {
                "id": "edge:reads:1",
                "type": "reads",
                "from": "stmt:top:9:state_update",
                "to": "signal:top.debug_req",
                "attrs": {"read_role": "condition"},
            },
            {
                "id": "edge:writes:2",
                "type": "writes",
                "from": "stmt:top:9:state_update",
                "to": "signal:top.auth_flag",
                "attrs": {"lhs_raw": "auth_flag"},
            },
        ],
    }


def test_graph_index_maps_signals_statements_edges_and_source_locs():
    index = RtlGraphIndex.from_json_dict(_sample_graph())

    assert index.graph_id == "demo"
    assert index.node("signal:top.auth_flag")["name"] == "auth_flag"
    assert index.module_name_for_signal("signal:top.auth_flag") == "top"
    assert index.signal_written_by("signal:top.auth_flag")[0]["id"] == "stmt:top:9:state_update"
    assert index.signal_read_by("signal:top.debug_req")[0]["id"] == "stmt:top:9:state_update"
    assert index.statement_reads("stmt:top:9:state_update")[0]["id"] == "signal:top.debug_req"
    assert index.statement_writes("stmt:top:9:state_update")[0]["id"] == "signal:top.auth_flag"
    assert index.source_loc("signal:top.auth_flag") == {
        "file": "top.sv",
        "line_start": 4,
        "line_end": 4,
    }
