from __future__ import annotations

from pathlib import Path

from method.proposed.closure.checker import EvidenceClosureChecker
from method.proposed.fact_layer.extractor import StaticRTLFactExtractor
from method.proposed.models import (
    AnalysisObligation,
    AnalysisObligationSet,
    EvidenceSlotRecord,
    FactLayer,
    InspectionRecord,
    ObligationAnalysisRecords,
    PermissionFactLayer,
)
from method.proposed.pipeline import ProposedMethodPipeline, ProposedPipelineConfig
from schemas.agent_output import AgentOutput


class FakeInitialVersionLLM:
    """Deterministic fake for proposed method structured LLM stages."""

    def semantic_label(self, static_facts: FactLayer, knowledge: str) -> PermissionFactLayer:
        return PermissionFactLayer(
            static_facts=static_facts,
            asset_candidates=[
                {
                    "name": "secret_reg",
                    "file": "rtl/top.sv",
                    "module": "top",
                    "signal_or_register": "secret_reg",
                    "reason": "Name and write path indicate protected state.",
                    "source_evidence": "reg [31:0] secret_reg;",
                }
            ],
            subject_candidates=[
                {
                    "name": "debug_req",
                    "interface_or_module": "top",
                    "possible_access_type": "debug write",
                    "source_evidence": "input debug_req;",
                }
            ],
            operation_candidates=[
                {
                    "operation_type": "write",
                    "signal_or_condition": "debug_req",
                    "file": "rtl/top.sv",
                    "module": "top",
                    "source_evidence": "if (debug_req) secret_reg <= data_i;",
                }
            ],
            guard_candidates=[],
            state_lifecycle_facts=[],
            path_candidates=[
                {
                    "path_id": "P1",
                    "subject": "debug_req",
                    "object": "secret_reg",
                    "path_nodes": ["top.debug_req", "top.secret_reg"],
                    "guards_on_path": [],
                    "uncertain_links": [],
                    "source_evidence": "debug_req directly controls secret_reg write.",
                }
            ],
            summary="Debug requester may write secret_reg without a visible guard.",
        )

    def plan_obligations(
        self,
        permission_facts: PermissionFactLayer,
        knowledge: str,
    ) -> AnalysisObligationSet:
        return AnalysisObligationSet(
            scope_id="scope",
            obligations=[
                AnalysisObligation(
                    obligation_id="O1",
                    reason="Check whether debug write to secret_reg is guarded.",
                    subject="debug_req",
                    operation="write",
                    object="secret_reg",
                    expected_guard="debug authorization or privilege guard",
                    candidate_path="top.debug_req -> top.secret_reg",
                    state_conditions_to_check=[],
                    required_evidence_slots=[
                        "subject",
                        "operation",
                        "object",
                        "expected_guard",
                        "observed_behavior",
                        "path",
                        "impact",
                        "rtl_evidence",
                    ],
                    files_or_modules_to_inspect=["rtl/top.sv"],
                    knowledge_used=["debug access control"],
                    priority="high",
                    uncertainty="Need confirm visible guard.",
                )
            ],
        )

    def inspect_obligations(
        self,
        obligations: AnalysisObligationSet,
        permission_facts: PermissionFactLayer,
        input_scope: Path,
        missing_evidence_requests: list[dict] | None = None,
    ) -> ObligationAnalysisRecords:
        return ObligationAnalysisRecords(
            scope_id="scope",
            obligations=obligations.obligations,
            inspection_records=[
                InspectionRecord(
                    obligation_id="O1",
                    inspection_status="candidate_violation",
                    evidence_slots=EvidenceSlotRecord(
                        subject="debug_req",
                        operation="write",
                        object="secret_reg",
                        expected_guard="debug authorization or privilege guard",
                        observed_behavior="secret_reg is written when debug_req is true.",
                        path="top.debug_req -> top.secret_reg",
                        state_condition="No lifecycle state required in this simple path.",
                        impact="Debug requester may modify protected state.",
                        rtl_evidence=[
                            {
                                "file": "rtl/top.sv",
                                "line_start": 8,
                                "line_end": 9,
                                "module": "top",
                                "object": "secret_reg",
                                "evidence_type": "register_access",
                                "description": "secret_reg write is controlled by debug_req.",
                                "supports_claim": "Shows debug-controlled write to protected state.",
                            }
                        ],
                    ),
                    missing_or_uncertain_evidence="No explicit guard found in visible scope.",
                    candidate_finding="Debug write to secret_reg may be unguarded.",
                )
            ],
        )


def test_static_extractor_collects_rtl_structure(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    rtl = scope / "rtl"
    rtl.mkdir(parents=True)
    (rtl / "top.sv").write_text(
        """
module top(input logic clk, input logic rst_n, input logic debug_req, input logic [31:0] data_i);
  logic [31:0] secret_reg;
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      secret_reg <= '0;
    end else if (debug_req) begin
      secret_reg <= data_i;
    end
  end
endmodule
""".strip(),
        encoding="utf-8",
    )

    facts = StaticRTLFactExtractor().extract(scope)

    assert facts.files[0].path == "rtl/top.sv"
    assert any(module.name == "top" for module in facts.modules)
    assert any(signal.name == "secret_reg" for signal in facts.signals)
    assert any(reset.file == "rtl/top.sv" for reset in facts.reset_facts)


def test_closure_checker_emits_baseline_compatible_agent_output() -> None:
    records = FakeInitialVersionLLM().inspect_obligations(
        FakeInitialVersionLLM().plan_obligations(
            PermissionFactLayer(static_facts=FactLayer()),
            "debug access knowledge",
        ),
        PermissionFactLayer(static_facts=FactLayer()),
        Path("."),
    )

    closure = EvidenceClosureChecker().check(records)
    output = EvidenceClosureChecker().to_agent_output(records, closure)

    validated = AgentOutput.model_validate(output)
    assert validated.findings[0].status == "confirmed_finding"
    assert validated.findings[0].evidence[0].file == "rtl/top.sv"


def test_pipeline_runs_initial_version_and_persists_artifacts(tmp_path: Path) -> None:
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
    output_dir = tmp_path / "run"

    pipeline = ProposedMethodPipeline(llm=FakeInitialVersionLLM())
    result = pipeline.run(
        ProposedPipelineConfig(
            scope_id="scope",
            input_scope_path=scope,
            knowledge_base_path=knowledge,
            output_dir=output_dir,
        )
    )

    assert result.structured_output_path.exists()
    assert result.final_answer_path.exists()
    assert (output_dir / "permission_fact_layer.json").exists()
    assert (output_dir / "obligations.json").exists()
    assert (output_dir / "inspection_records.json").exists()
    assert (output_dir / "closure_records.json").exists()
    assert result.final_answer_path.read_text(encoding="utf-8") == result.structured_output_path.read_text(encoding="utf-8")
    AgentOutput.model_validate_json(result.structured_output_path.read_text(encoding="utf-8"))
