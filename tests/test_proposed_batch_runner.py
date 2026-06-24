from __future__ import annotations

import json
from pathlib import Path

import yaml

from runtime.proposed_batch_runner import ProposedBatchRunner


def test_proposed_batch_runner_runs_model_scope_repetition_loop(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    rtl = scope / "rtl"
    rtl.mkdir(parents=True)
    (rtl / "top.sv").write_text(
        """
module top(input logic debug_req);
  logic [31:0] secret_reg;
  assign secret_reg[0] = debug_req;
endmodule
""".strip(),
        encoding="utf-8",
    )
    knowledge = tmp_path / "knowledge.md"
    knowledge.write_text("Generic permission knowledge.", encoding="utf-8")
    config_path = tmp_path / "proposed_batch.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "batch_id": "batch",
                "output_root": "runs/proposed",
                "knowledge_base_path": str(knowledge),
                "repetitions": 2,
                "max_steps": 3,
                "max_closure_iterations": 1,
                "models": [
                    {"model_id": "mock", "provider": "mock", "model": "mock-proposed"},
                ],
                "input_scopes": [
                    {"scope_id": "scope", "path": str(scope)},
                ],
            },
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    batch_dir = ProposedBatchRunner(project_root=tmp_path).run_from_config(config_path)

    status_rows = [
        json.loads(line)
        for line in (batch_dir / "batch_status.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(status_rows) == 2
    assert all(row["status"] == "success" for row in status_rows)
    assert (batch_dir / "models" / "mock" / "scope" / "rep_1" / "structured_output.json").exists()
    assert (batch_dir / "models" / "mock" / "scope" / "rep_2" / "structured_output.json").exists()
