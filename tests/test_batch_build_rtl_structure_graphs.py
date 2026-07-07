import json
import subprocess
import sys
from pathlib import Path

from scripts.build.batch_build_rtl_structure_graphs import discover_input_scopes


def test_discover_input_scopes_uses_benchmark_scope_directories(tmp_path):
    input_root = tmp_path / "datasets" / "agent_inputs"
    scope = input_root / "hackatdac21" / "h21_demo_scope"
    scope.mkdir(parents=True)
    (scope / "top.sv").write_text("module top; endmodule\n", encoding="utf-8")
    nested = scope / "nested"
    nested.mkdir()
    (nested / "child.sv").write_text("module child; endmodule\n", encoding="utf-8")

    discovered = discover_input_scopes(input_root)

    assert [(item.benchmark, item.scope_name, item.path) for item in discovered] == [
        ("hackatdac21", "h21_demo_scope", scope)
    ]


def test_batch_cli_writes_each_scope_to_module1_runs_dir(tmp_path):
    input_root = tmp_path / "datasets" / "agent_inputs"
    out_root = tmp_path / "runs" / "module1_rtl_structure_graphs"
    first = input_root / "hackatdac18" / "debug_jtag_scope"
    second = input_root / "hackatdac21" / "h21_demo_scope"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (first / "top.sv").write_text("module top(input logic a); endmodule\n", encoding="utf-8")
    (second / "core.sv").write_text("module core(output logic b); endmodule\n", encoding="utf-8")

    script = Path(__file__).resolve().parents[1] / "scripts" / "build" / "batch_build_rtl_structure_graphs.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--input-root",
            str(input_root),
            "--out-root",
            str(out_root),
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    manifest_path = out_root / "manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert [row["scope_id"] for row in manifest["runs"]] == [
        "hackatdac18__debug_jtag_scope",
        "hackatdac21__h21_demo_scope",
    ]
    assert (out_root / "hackatdac18__debug_jtag_scope" / "rtl_structure_graph.json").exists()
    assert (out_root / "hackatdac21__h21_demo_scope" / "rtl_structure_graph.json").exists()
