import json
import subprocess
import sys
from pathlib import Path


def test_cli_writes_formal_graph_and_separate_diagnostics(tmp_path):
    rtl_repo = tmp_path / "rtl"
    out_dir = tmp_path / "out"
    rtl_repo.mkdir()
    (rtl_repo / "top.sv").write_text(
        """
module top(input logic a, output logic b);
  assign b = a;
endmodule
""".strip()
        + "\n",
        encoding="utf-8",
    )

    script = Path(__file__).resolve().parents[1] / "scripts" / "build_rtl_structure_graph.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--repo",
            str(rtl_repo),
            "--out",
            str(out_dir),
            "--graph-id",
            "cli_unit",
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    graph_path = out_dir / "rtl_structure_graph.json"
    diagnostics_path = out_dir / "rtl_structure_graph_diagnostics.json"
    assert graph_path.exists()
    assert diagnostics_path.exists()

    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))

    assert set(graph) == {"graph_id", "nodes", "edges"}
    assert graph["graph_id"] == "cli_unit"
    assert "warnings" in diagnostics
    assert "source_files" in diagnostics
