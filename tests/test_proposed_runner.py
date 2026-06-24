from __future__ import annotations

import json
from pathlib import Path

from runtime.proposed_runner import ProposedRunConfig, ProposedRunner
from schemas.agent_output import AgentOutput


def test_proposed_runner_mock_persists_initial_version_outputs(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    rtl = scope / "rtl"
    rtl.mkdir(parents=True)
    (rtl / "top.sv").write_text(
        """
module top(input logic clk, input logic rst_n, input logic debug_req, input logic [31:0] data_i);
  logic [31:0] secret_reg;
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) secret_reg <= '0;
    else if (debug_req) secret_reg <= data_i;
  end
endmodule
""".strip(),
        encoding="utf-8",
    )
    knowledge = tmp_path / "knowledge.md"
    knowledge.write_text("Debug access should be mediated by authorization guards.", encoding="utf-8")

    runner = ProposedRunner(project_root=tmp_path)
    record = runner.run(
        ProposedRunConfig(
            run_id="rep_1",
            provider="mock",
            model="mock-proposed",
            input_scope_path=str(scope),
            knowledge_base_path=str(knowledge),
            output_dir="runs/proposed/smoke/models/mock/scope",
            max_closure_iterations=1,
        )
    )

    assert Path(record.permission_fact_layer_path).exists()
    assert Path(record.obligations_path).exists()
    assert Path(record.inspection_records_path).exists()
    assert Path(record.closure_records_path).exists()
    assert Path(record.final_answer_path).exists()
    output_text = Path(record.structured_output_path).read_text(encoding="utf-8")
    assert Path(record.final_answer_path).read_text(encoding="utf-8") == output_text
    AgentOutput.model_validate_json(output_text)

    metadata = json.loads(Path(record.run_metadata_path).read_text(encoding="utf-8"))
    assert metadata["method_name"] == "proposed_initial"
    assert metadata["provider"] == "mock"
    assert metadata["final_answer_path"] == record.final_answer_path
