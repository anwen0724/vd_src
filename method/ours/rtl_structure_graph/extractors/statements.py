from __future__ import annotations

import re
from dataclasses import dataclass, field

from method.ours.rtl_structure_graph.extractors.expressions import SignalRef, extract_signal_refs
from method.ours.rtl_structure_graph.extractors.modules import ModuleDef
from method.ours.rtl_structure_graph.models import SourceLoc


@dataclass(frozen=True)
class StatementDef:
    kind: str
    loc: SourceLoc
    attrs: dict[str, object] = field(default_factory=dict)
    read_refs: list[tuple[SignalRef, str]] = field(default_factory=list)
    write_refs: list[SignalRef] = field(default_factory=list)


def extract_statements(module: ModuleDef) -> list[StatementDef]:
    statements: list[StatementDef] = []
    statements.extend(_extract_continuous_assigns(module))
    statements.extend(_extract_always_assigns(module))
    return statements


def _extract_continuous_assigns(module: ModuleDef) -> list[StatementDef]:
    results: list[StatementDef] = []
    for match in re.finditer(r"(?ms)\bassign\s+(.+?)\s*=\s*(.+?)\s*;", module.body_text):
        lhs_raw = match.group(1).strip()
        rhs_raw = match.group(2).strip()
        line = module.source.line_for_offset(module.body_start_offset + match.start())
        results.append(
            StatementDef(
                kind="continuous_assign",
                loc=SourceLoc(file=module.source.relative_path, line_start=line, line_end=line),
                attrs={
                    "kind": "continuous_assign",
                    "lhs_raw": lhs_raw,
                    "rhs_raw": rhs_raw,
                },
                read_refs=[(ref, "rhs") for ref in extract_signal_refs(rhs_raw)],
                write_refs=extract_signal_refs(lhs_raw),
            )
        )
    return results


def _extract_always_assigns(module: ModuleDef) -> list[StatementDef]:
    results: list[StatementDef] = []
    for block_start, block_end, header, block_text in _iter_always_blocks(module.body_text):
        temporal = "posedge" in header or "negedge" in header or "always_ff" in header
        conditions = re.findall(r"\bif\s*\((.*?)\)", block_text, flags=re.S)
        case_selectors = re.findall(r"\bcase\s*\((.*?)\)", block_text, flags=re.S)
        for match in re.finditer(r"(?m)([A-Za-z_][A-Za-z0-9_$]*(?:\[[^\]]+\])?)\s*(<=|=)\s*(.+?);", block_text):
            lhs_raw = match.group(1).strip()
            op = match.group(2)
            rhs_raw = match.group(3).strip()
            kind = "state_update" if temporal or op == "<=" else "procedural_assign"
            line = module.source.line_for_offset(module.body_start_offset + block_start + match.start())
            read_refs = [(ref, "rhs") for ref in extract_signal_refs(rhs_raw)]
            for condition in conditions:
                read_refs.extend((ref, "condition") for ref in extract_signal_refs(condition))
            for selector in case_selectors:
                read_refs.extend((ref, "case_selector") for ref in extract_signal_refs(selector))
            results.append(
                StatementDef(
                    kind=kind,
                    loc=SourceLoc(file=module.source.relative_path, line_start=line, line_end=line),
                    attrs={
                        "kind": kind,
                        "assignment_op": op,
                        "lhs_raw": lhs_raw,
                        "rhs_raw": rhs_raw,
                        "conditions": [" ".join(item.split()) for item in conditions],
                        "case_selectors": [" ".join(item.split()) for item in case_selectors],
                    },
                    read_refs=read_refs,
                    write_refs=extract_signal_refs(lhs_raw),
                )
            )
    return results


def _iter_always_blocks(text: str) -> list[tuple[int, int, str, str]]:
    blocks: list[tuple[int, int, str, str]] = []
    for match in re.finditer(r"\balways(?:_[A-Za-z0-9_]+)?\s*(?:@\s*\([^;]*?\))?", text):
        start = match.start()
        next_match = re.search(r"\balways(?:_[A-Za-z0-9_]+)?\b|\bendmodule\b", text[match.end() :])
        end = len(text) if not next_match else match.end() + next_match.start()
        block = text[start:end]
        blocks.append((start, end, match.group(0), block))
    return blocks
