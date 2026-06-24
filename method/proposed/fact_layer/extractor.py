"""Lightweight RTL static fact extraction for the proposed method."""

from __future__ import annotations

import re
from pathlib import Path

from method.proposed.models import (
    AlwaysBlockFact,
    AssignmentFact,
    CSRFacts,
    FactLayer,
    FileFact,
    InstanceFact,
    ModuleFact,
    PortFact,
    ResetFact,
    SignalFact,
)


RTL_SUFFIXES = {".v", ".sv", ".vh", ".svh"}


class StaticRTLFactExtractor:
    """Extract coarse RTL facts without needing a full SystemVerilog parser."""

    def extract(self, input_scope: str | Path) -> FactLayer:
        root = Path(input_scope).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Input scope does not exist: {root}")
        if not root.is_dir():
            raise NotADirectoryError(f"Input scope is not a directory: {root}")

        facts = FactLayer()
        for file_path in sorted(root.rglob("*")):
            if not file_path.is_file() or file_path.suffix.lower() not in RTL_SUFFIXES:
                continue
            rel = file_path.relative_to(root).as_posix()
            text = file_path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            facts.files.append(FileFact(path=rel, suffix=file_path.suffix, line_count=len(lines)))
            self._extract_file_facts(rel, lines, facts)
        return facts

    def _extract_file_facts(self, rel: str, lines: list[str], facts: FactLayer) -> None:
        current_module = ""
        module_start: dict[str, int] = {}
        for line_number, line in enumerate(lines, start=1):
            stripped = _strip_comment(line).strip()
            if not stripped:
                continue

            module_match = re.match(r"\s*module\s+([A-Za-z_][A-Za-z0-9_$]*)\b", stripped)
            if module_match:
                current_module = module_match.group(1)
                module_start[current_module] = line_number
                facts.modules.append(ModuleFact(name=current_module, file=rel, line_start=line_number))

            if re.match(r"\s*endmodule\b", stripped):
                if current_module:
                    for module in facts.modules:
                        if module.name == current_module and module.file == rel and module.line_end is None:
                            module.line_end = line_number
                            break
                current_module = ""

            port = _match_port(stripped)
            if port:
                facts.ports.append(
                    PortFact(
                        name=port["name"],
                        direction=port["direction"],
                        width=port["width"],
                        file=rel,
                        module=current_module,
                        line_start=line_number,
                    )
                )

            signal = _match_signal(stripped)
            if signal:
                facts.signals.append(
                    SignalFact(
                        name=signal["name"],
                        kind=signal["kind"],
                        width=signal["width"],
                        file=rel,
                        module=current_module,
                        line_start=line_number,
                    )
                )

            assignment = _match_assignment(stripped)
            if assignment:
                facts.assignments.append(
                    AssignmentFact(
                        target=assignment["target"],
                        expression=assignment["expression"],
                        file=rel,
                        module=current_module,
                        line_start=line_number,
                        text=stripped,
                    )
                )

            instance = _match_instance(stripped)
            if instance:
                facts.instances.append(
                    InstanceFact(
                        instance=instance["instance"],
                        module_type=instance["module_type"],
                        file=rel,
                        parent_module=current_module,
                        line_start=line_number,
                    )
                )

            if _looks_like_always(stripped):
                preview = "\n".join(lines[line_number - 1 : min(len(lines), line_number + 8)])
                facts.always_blocks.append(
                    AlwaysBlockFact(
                        file=rel,
                        module=current_module,
                        line_start=line_number,
                        header=stripped,
                        text_preview=preview,
                    )
                )

            if _looks_like_reset(stripped):
                preview = "\n".join(lines[max(0, line_number - 2) : min(len(lines), line_number + 4)])
                facts.reset_facts.append(
                    ResetFact(
                        file=rel,
                        module=current_module,
                        line_start=line_number,
                        signal_or_condition=stripped,
                        text_preview=preview,
                    )
                )

            if _looks_like_csr_or_security(stripped):
                facts.csr_facts.append(
                    CSRFacts(
                        file=rel,
                        module=current_module,
                        line_start=line_number,
                        object=_first_identifier(stripped),
                        evidence_type=_classify_security_line(stripped),
                        text=stripped,
                    )
                )


def _strip_comment(line: str) -> str:
    return line.split("//", 1)[0]


def _match_port(line: str) -> dict[str, str] | None:
    match = re.match(
        r"\s*(input|output|inout)\s+(?:wire\s+|logic\s+|reg\s+)?(\[[^\]]+\])?\s*([A-Za-z_][A-Za-z0-9_$]*)",
        line,
    )
    if not match:
        return None
    return {"direction": match.group(1), "width": match.group(2) or "", "name": match.group(3)}


def _match_signal(line: str) -> dict[str, str] | None:
    match = re.match(
        r"\s*(logic|wire|reg)\s+(\[[^\]]+\])?\s*([A-Za-z_][A-Za-z0-9_$]*)",
        line,
    )
    if not match:
        return None
    return {"kind": match.group(1), "width": match.group(2) or "", "name": match.group(3)}


def _match_assignment(line: str) -> dict[str, str] | None:
    continuous = re.match(r"\s*assign\s+([A-Za-z_][A-Za-z0-9_$\[\]\.]+)\s*=\s*(.+?);?\s*$", line)
    if continuous:
        return {"target": continuous.group(1), "expression": continuous.group(2).rstrip(";")}
    procedural = re.match(r"\s*([A-Za-z_][A-Za-z0-9_$\[\]\.]+)\s*(?:<=|=)\s*(.+?);?\s*$", line)
    if procedural and not line.startswith(("if", "else", "for", "while", "case")):
        return {"target": procedural.group(1), "expression": procedural.group(2).rstrip(";")}
    return None


def _match_instance(line: str) -> dict[str, str] | None:
    match = re.match(
        r"\s*([A-Za-z_][A-Za-z0-9_$]*)\s+(?:#\s*\([^;]*\)\s*)?([A-Za-z_][A-Za-z0-9_$]*)\s*\(",
        line,
    )
    if not match:
        return None
    module_type, instance = match.groups()
    if module_type in {"if", "for", "while", "case", "assign", "module", "always_ff", "always_comb"}:
        return None
    return {"module_type": module_type, "instance": instance}


def _looks_like_always(line: str) -> bool:
    return bool(re.match(r"\s*always(?:_ff|_comb|_latch)?\b", line))


def _looks_like_reset(line: str) -> bool:
    lowered = line.lower()
    return "reset" in lowered or "rst" in lowered or "negedge rst" in lowered


def _looks_like_csr_or_security(line: str) -> bool:
    lowered = line.lower()
    keywords = [
        "csr",
        "reglk",
        "lock",
        "debug",
        "jtag",
        "auth",
        "priv",
        "key",
        "secret",
        "fuse",
        "pmp",
        "dma",
        "access",
        "addr",
        "write",
        "read",
    ]
    return any(keyword in lowered for keyword in keywords)


def _classify_security_line(line: str) -> str:
    lowered = line.lower()
    if "addr" in lowered:
        return "address_decode"
    if "reset" in lowered or "rst" in lowered:
        return "reset_behavior"
    if "lock" in lowered or "csr" in lowered or "write" in lowered or "read" in lowered:
        return "register_access"
    if "debug" in lowered or "jtag" in lowered:
        return "interface_signal"
    return "unknown"


def _first_identifier(line: str) -> str:
    match = re.search(r"[A-Za-z_][A-Za-z0-9_$]*", line)
    return match.group(0) if match else ""

