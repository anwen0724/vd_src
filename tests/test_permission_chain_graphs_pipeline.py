import json

from method.ours.permission_chain_graphs.pipeline import build_permission_chain_graphs


def test_pipeline_writes_formal_and_diagnostics(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.sv").write_text("module a;\nassign y = x;\nendmodule\n", encoding="utf-8")
    graph = tmp_path / "graph.json"
    graph.write_text(
        json.dumps(
            {
                "graph_id": "g",
                "nodes": [
                    {"id": "signal:m.x", "type": "Signal", "scope": "module:m", "name": "x", "loc": {"file": "a.sv", "line_start": 2, "line_end": 2}},
                    {"id": "stmt:m:2:assign", "type": "StmtSummary", "scope": "module:m", "name": "assign:2", "loc": {"file": "a.sv", "line_start": 2, "line_end": 2}},
                ],
                "edges": [{"id": "edge:reads:1", "type": "reads", "from": "stmt:m:2:assign", "to": "signal:m.x"}],
            }
        ),
        encoding="utf-8",
    )
    targets = tmp_path / "targets.json"
    targets.write_text(
        json.dumps(
            {
                "graph_id": "g",
                "targets": [
                    {"target_id": "T", "point": {"node_id": "signal:m.x", "name": "x", "module": "m"}, "accesses": []}
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    summary = build_permission_chain_graphs(graph, targets, repo, out)
    formal = json.loads((out / "permission_chain_graphs.json").read_text(encoding="utf-8"))
    diagnostics = json.loads((out / "permission_chain_graph_diagnostics.json").read_text(encoding="utf-8"))
    assert summary["chain_count"] == 1
    assert "source_snippets" not in json.dumps(formal)
    assert diagnostics["chain_count"] == 1

