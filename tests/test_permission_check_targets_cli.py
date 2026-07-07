import json

from scripts.build.build_permission_check_targets import main


def test_single_graph_cli_writes_targets_and_diagnostics(tmp_path):
    graph_path = tmp_path / "rtl_structure_graph.json"
    out_dir = tmp_path / "out"
    graph_path.write_text(
        json.dumps(
            {
                "graph_id": "cli",
                "nodes": [
                    {
                        "id": "module:top",
                        "type": "Module",
                        "scope": None,
                        "name": "top",
                        "loc": {"file": "top.sv", "line_start": 1, "line_end": 10},
                        "attrs": {},
                    },
                    {
                        "id": "signal:top.debug_req",
                        "type": "Signal",
                        "scope": "module:top",
                        "name": "debug_req",
                        "loc": {"file": "top.sv", "line_start": 2, "line_end": 2},
                        "attrs": {"kind": "port", "direction": "input"},
                    },
                ],
                "edges": [],
            }
        ),
        encoding="utf-8",
    )

    assert main(["--graph", str(graph_path), "--out", str(out_dir), "--max-targets-per-repo", "5"]) == 0

    targets = json.loads((out_dir / "permission_check_targets.json").read_text(encoding="utf-8"))
    diagnostics = json.loads((out_dir / "target_generation_diagnostics.json").read_text(encoding="utf-8"))
    assert targets["graph_id"] == "cli"
    assert targets["generation_mode"] == "algorithm"
    assert diagnostics["graph_id"] == "cli"
