"""Pipeline orchestration for the complete initial proposed method."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from method.proposed.closure.checker import EvidenceClosureChecker
from method.proposed.fact_layer.extractor import StaticRTLFactExtractor
from method.proposed.knowledge.loader import KnowledgeBaseLoader
from method.proposed.models import (
    AnalysisObligationSet,
    ClosureResult,
    FactLayer,
    ObligationAnalysisRecords,
    PermissionFactLayer,
    ProposedPipelineConfig,
)


class InitialVersionLLM(Protocol):
    """LLM stage interface used by the proposed initial-version pipeline."""

    def semantic_label(self, static_facts: FactLayer, knowledge: str) -> PermissionFactLayer: ...

    def plan_obligations(
        self,
        permission_facts: PermissionFactLayer,
        knowledge: str,
    ) -> AnalysisObligationSet: ...

    def inspect_obligations(
        self,
        obligations: AnalysisObligationSet,
        permission_facts: PermissionFactLayer,
        input_scope: Path,
        missing_evidence_requests: list[dict] | None = None,
    ) -> ObligationAnalysisRecords: ...


@dataclass(frozen=True)
class ProposedPipelineResult:
    output_dir: Path
    static_fact_layer_path: Path
    permission_fact_layer_path: Path
    obligations_path: Path
    inspection_records_path: Path
    tool_observations_path: Path
    closure_records_path: Path
    final_answer_path: Path
    structured_output_path: Path


class ProposedMethodPipeline:
    """Run the full initial-version proposed method."""

    def __init__(
        self,
        llm: InitialVersionLLM,
        extractor: StaticRTLFactExtractor | None = None,
        knowledge_loader: KnowledgeBaseLoader | None = None,
        closure_checker: EvidenceClosureChecker | None = None,
    ) -> None:
        self.llm = llm
        self.extractor = extractor or StaticRTLFactExtractor()
        self.knowledge_loader = knowledge_loader or KnowledgeBaseLoader()
        self.closure_checker = closure_checker or EvidenceClosureChecker()

    def run(self, config: ProposedPipelineConfig) -> ProposedPipelineResult:
        input_scope = Path(config.input_scope_path).resolve()
        output_dir = Path(config.output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        _log_stage(config.scope_id, "load_knowledge", "START")
        knowledge = self.knowledge_loader.load(config.knowledge_base_path)
        _log_stage(config.scope_id, "load_knowledge", "OK")
        _log_stage(config.scope_id, "extract_static_facts", "START")
        static_facts = self.extractor.extract(input_scope)
        _log_stage(config.scope_id, "extract_static_facts", "OK")
        _log_stage(config.scope_id, "semantic_label", "START")
        permission_facts = self.llm.semantic_label(static_facts, knowledge)
        _log_stage(config.scope_id, "semantic_label", "OK")
        _log_stage(config.scope_id, "plan_obligations", "START")
        obligations = self.llm.plan_obligations(permission_facts, knowledge)
        _log_stage(config.scope_id, "plan_obligations", "OK")
        if not obligations.scope_id:
            obligations.scope_id = config.scope_id
        _log_stage(config.scope_id, "inspect_obligations", "START")
        records = self.llm.inspect_obligations(obligations, permission_facts, input_scope)
        _log_stage(config.scope_id, "inspect_obligations", "OK")
        if not records.scope_id:
            records.scope_id = config.scope_id

        _log_stage(config.scope_id, "closure_check", "START")
        closure = self.closure_checker.check(records)
        _log_stage(config.scope_id, "closure_check", "OK")
        for _ in range(config.max_closure_iterations):
            missing_requests = closure.missing_requests()
            if not missing_requests:
                break
            _log_stage(config.scope_id, "inspect_obligations_closure", "START")
            records = self.llm.inspect_obligations(
                obligations,
                permission_facts,
                input_scope,
                missing_evidence_requests=missing_requests,
            )
            _log_stage(config.scope_id, "inspect_obligations_closure", "OK")
            if not records.scope_id:
                records.scope_id = config.scope_id
            _log_stage(config.scope_id, "closure_check", "START")
            closure = self.closure_checker.check(records)
            _log_stage(config.scope_id, "closure_check", "OK")

        _log_stage(config.scope_id, "final_output", "START")
        agent_output = self.closure_checker.to_agent_output(records, closure)

        static_fact_layer_path = output_dir / "static_fact_layer.json"
        permission_fact_layer_path = output_dir / "permission_fact_layer.json"
        obligations_path = output_dir / "obligations.json"
        inspection_records_path = output_dir / "inspection_records.json"
        tool_observations_path = output_dir / "tool_observations.jsonl"
        closure_records_path = output_dir / "closure_records.json"
        final_answer_path = output_dir / "final_answer.json"
        structured_output_path = output_dir / "structured_output.json"

        _write_model(static_fact_layer_path, static_facts)
        _write_model(permission_fact_layer_path, permission_facts)
        _write_model(obligations_path, obligations)
        _write_model(inspection_records_path, records)
        _write_jsonl(tool_observations_path, records.tool_observations)
        _write_model(closure_records_path, closure)
        output_text = json.dumps(agent_output, ensure_ascii=False, indent=2)
        final_answer_path.write_text(output_text, encoding="utf-8")
        structured_output_path.write_text(output_text, encoding="utf-8")
        _log_stage(config.scope_id, "final_output", "OK")

        return ProposedPipelineResult(
            output_dir=output_dir,
            static_fact_layer_path=static_fact_layer_path,
            permission_fact_layer_path=permission_fact_layer_path,
            obligations_path=obligations_path,
            inspection_records_path=inspection_records_path,
            tool_observations_path=tool_observations_path,
            closure_records_path=closure_records_path,
            final_answer_path=final_answer_path,
            structured_output_path=structured_output_path,
        )


def _write_model(path: Path, model) -> None:
    path.write_text(model.model_dump_json(indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    lines = [json.dumps(row, ensure_ascii=False) for row in rows]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _log_stage(scope_id: str, stage: str, status: str) -> None:
    print(f"[proposed-stage] scope={scope_id} stage={stage} {status}", flush=True)
