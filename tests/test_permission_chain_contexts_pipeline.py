import json

from method.ours.permission_chain_contexts.pipeline import build_permission_chain_contexts


def test_build_chain_contexts_adds_deterministic_snippets(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.sv").write_text("\n".join(f"line {i}" for i in range(1, 21)), encoding="utf-8")
    graphs = tmp_path / "permission_chain_graphs.json"
    graphs.write_text(
        json.dumps(
            {
                "graph_id": "g",
                "schema_version": "0.1",
                "chains": [
                    {
                        "chain_id": "CHAIN-0001",
                        "seed_targets": [],
                        "nodes": [],
                        "edges": [],
                        "source_locations": [
                            {
                                "loc_id": "LOC-0001",
                                "file": "a.sv",
                                "line_start": 10,
                                "line_end": 10,
                                "node_ids": ["n"],
                                "edge_ids": [],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    summary = build_permission_chain_contexts(graphs, repo, out)
    doc = json.loads((out / "permission_chain_contexts.json").read_text(encoding="utf-8"))
    assert summary["snippet_count"] == 1
    assert doc["chains"][0]["source_snippets"][0]["snippet_id"] == "SNIP-0001"
    assert "prompt" not in json.dumps(doc)
