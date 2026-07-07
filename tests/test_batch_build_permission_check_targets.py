import json

from scripts.build.batch_build_permission_check_targets import run_batch


def test_batch_build_permission_check_targets_writes_per_scope_outputs_and_manifest(tmp_path):
    graphs_root = tmp_path / "module1"
    scope_dir = graphs_root / "hackatdac_demo__debug_scope"
    scope_dir.mkdir(parents=True)
    (graphs_root / "manifest.json").write_text("{}", encoding="utf-8")
    (scope_dir / "rtl_structure_graph.json").write_text(
        json.dumps(
            {
                "graph_id": "hackatdac_demo__debug_scope",
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
                        "id": "signal:top.jtag_unlock",
                        "type": "Signal",
                        "scope": "module:top",
                        "name": "jtag_unlock",
                        "loc": {"file": "top.sv", "line_start": 2, "line_end": 2},
                        "attrs": {"kind": "port", "direction": "input"},
                    },
                ],
                "edges": [],
            }
        ),
        encoding="utf-8",
    )
    out_root = tmp_path / "module2_1"

    manifest = run_batch(graphs_root=graphs_root, out_root=out_root)

    assert manifest["total_scopes"] == 1
    assert manifest["runs"][0]["status"] == "success"
    assert (out_root / "hackatdac_demo__debug_scope" / "permission_check_targets.json").exists()
    assert (out_root / "hackatdac_demo__debug_scope" / "target_generation_diagnostics.json").exists()
    assert (out_root / "manifest.json").exists()
