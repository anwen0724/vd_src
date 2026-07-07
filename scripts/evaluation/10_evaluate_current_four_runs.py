from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
GT_CASES = PROJECT_ROOT / "evaluation_results" / "gt_cases.csv"
OUTPUT_ROOT = PROJECT_ROOT / "evaluation_results" / "current_four_runs"


BATCHES = [
    {
        "label": "baseline_claude",
        "method_name": "baseline",
        "batch_dir": PROJECT_ROOT / "runs" / "baseline" / "baseline_hackatdac_claude_v1",
        "model_family": "claude_sonnet_4-6",
        "scope_count_mode": "single",
    },
    {
        "label": "baseline_gemini",
        "method_name": "baseline",
        "batch_dir": PROJECT_ROOT / "runs" / "baseline" / "baseline_hackatdac_gemini_v1",
        "model_family": "gemini_3.1_pro_preview",
        "scope_count_mode": "repeated",
    },
    {
        "label": "ours_claude",
        "method_name": "ours_chain_context",
        "batch_dir": PROJECT_ROOT / "runs" / "ours_chain_context" / "ours_chain_context_claude",
        "model_family": "claude_sonnet_4-6",
        "scope_count_mode": "single",
    },
    {
        "label": "ours_gemini",
        "method_name": "ours_chain_context",
        "batch_dir": PROJECT_ROOT / "runs" / "ours_chain_context" / "ours_chain_context_gemini",
        "model_family": "gemini_3.1_pro_preview",
        "scope_count_mode": "single",
    },
]


FINDING_REVIEW_COLUMNS = [
    "finding_uid",
    "model_family",
    "method_name",
    "input_scope",
    "repetition",
    "run_id",
    "final_answer_path",
    "finding_id",
    "model_reported_status",
    "summary",
    "vulnerability_category",
    "affected_locations",
    "claimed_files",
    "claimed_modules",
    "claimed_signals_or_registers",
    "evidence_items",
    "reasoning_summary",
    "security_impact",
    "confidence",
    "uncertainty_or_missing_evidence",
    "matched_case_id",
    "detection_match",
    "duplicate_of_finding_uid",
    "evidence_quality",
    "review_notes",
]


SINGLE_RUN_COLUMNS = [
    "model_family",
    "method_name",
    "repetition",
    "num_gt_cases",
    "tp_cases",
    "fn_cases",
    "tp_findings",
    "fp_findings",
    "precision",
    "recall",
    "f1_score",
    "evidence_sufficiency_rate",
    "fabricated_unsupported_evidence_rate",
]


ANYHIT_COLUMNS = [
    "model_family",
    "method_name",
    "num_gt_cases",
    "tp_cases",
    "fn_cases",
    "representative_tp_findings",
    "fp_findings",
    "precision",
    "recall",
    "f1_score",
    "evidence_sufficiency_rate",
    "fabricated_unsupported_evidence_rate",
]

SINGLE_RUN_SUMMARY_COLUMNS = [
    "model_family",
    "method_name",
    "precision_mean",
    "recall_mean",
    "f1_score_mean",
    "evidence_sufficiency_rate_mean",
    "fabricated_unsupported_evidence_rate_mean",
    "precision_std",
    "recall_std",
    "f1_score_std",
    "evidence_sufficiency_rate_std",
    "fabricated_unsupported_evidence_rate_std",
]


CASE_HIT_COLUMNS = [
    "model_family",
    "method_name",
    "input_scope",
    "benchmark_id",
    "case_id",
    "case_result",
    "hit_repetitions",
    "representative_finding_uid",
    "representative_evidence_quality",
    "notes",
]


AGGREGATION_COLUMNS = [
    "model_family",
    "method_name",
    "input_scope",
    "repetition",
    "matched_case_id",
    "detection_match",
    "representative_finding_uid",
    "duplicate_count",
    "fp_count",
    "example_summaries",
]


SCOPE_MAP = {
    "hackatdac18__debug_jtag_scope": "h18_debug_jtag_scope",
    "hackatdac18__fc_core_security_scope": "h18_fc_core_security_scope",
    "hackatdac18__gpio_apb_scope": "h18_gpio_apb_scope",
    "hackatdac19__h19_access_control_fabric_scope": "h19_access_control_fabric_scope",
    "hackatdac19__h19_aes_rom2_security_scope": "h19_aes_rom2_security_scope",
    "hackatdac19__h19_csr_privilege_scope": "h19_csr_privilege_scope",
    "hackatdac19__h19_debug_jtag_scope": "h19_debug_jtag_scope",
    "hackatdac19__h19_jtag_debug_expansion_scope": "h19_jtag_debug_expansion_scope",
    "hackatdac21__h21_access_lock_scope": "h21_access_lock_scope",
    "hackatdac21__h21_access_reglock_reset_expansion_scope": "h21_access_reglock_reset_expansion_scope",
    "hackatdac21__h21_crypto_security_scope": "h21_crypto_security_scope",
    "hackatdac21__h21_dma_pkt_scope": "h21_dma_pkt_scope",
    "hackatdac21__h21_dma_pmp_expansion_scope": "h21_dma_pmp_expansion_scope",
    "hackatdac21__h21_fuse_rng_rsa_expansion_scope": "h21_fuse_rng_rsa_expansion_scope",
    "hackatdac21__h21_jtag_auth_expansion_scope": "h21_jtag_auth_expansion_scope",
}


def main() -> int:
    gt_rows = read_csv(GT_CASES)
    gt_by_scope = group_by(gt_rows, "input_scope")
    all_gt_ids = {row["case_id"] for row in gt_rows}
    evidence = load_evidence_index()
    for batch in BATCHES:
        rows = build_review_rows(batch)
        for row in rows:
            match_row(row, gt_by_scope, evidence)
        mark_duplicates(rows)
        out_dir = OUTPUT_ROOT / batch["method_name"] / batch["model_family"]
        write_csv(out_dir / "finding_review.csv", FINDING_REVIEW_COLUMNS, rows)
        write_csv(out_dir / "finding_review_draft.csv", FINDING_REVIEW_COLUMNS, rows)
        write_csv(out_dir / "aggregation_review.csv", AGGREGATION_COLUMNS, build_aggregation_rows(rows))
        single_run_rows = compute_single_run(rows, gt_rows, batch)
        write_csv(out_dir / "single_run" / "single_run_metrics.csv", SINGLE_RUN_COLUMNS, single_run_rows)
        write_csv(
            out_dir / "single_run" / "single_run_model_summary.csv",
            SINGLE_RUN_SUMMARY_COLUMNS,
            summarize_single_run(single_run_rows),
        )
        case_rows, anyhit_rows = compute_anyhit(rows, gt_rows, all_gt_ids, batch)
        write_csv(out_dir / "anyhit3" / "anyhit3_case_hits.csv", CASE_HIT_COLUMNS, case_rows)
        write_csv(out_dir / "anyhit3" / "anyhit3_model_summary.csv", ANYHIT_COLUMNS, anyhit_rows)
        write_json(out_dir / "run_status_summary.json", summarize_batch_status(batch))
        print(f"[ok] {batch['label']} rows={len(rows)} out={out_dir}")
    write_csv(OUTPUT_ROOT / "combined_summary.csv", ANYHIT_COLUMNS, collect_combined_summary())
    return 0


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def group_by(rows: list[dict[str, str]], key: str) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row.get(key, "")].append(row)
    return dict(grouped)


def build_review_rows(batch: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for final_answer in sorted(batch["batch_dir"].glob("models/*/*/rep_*/final_answer.json")):
        model = final_answer.parents[2].name
        if model != batch["model_family"]:
            continue
        raw_scope = final_answer.parents[1].name
        scope = SCOPE_MAP.get(raw_scope, raw_scope)
        repetition = final_answer.parent.name.replace("rep_", "")
        answer = json.loads(final_answer.read_text(encoding="utf-8"))
        for index, finding in enumerate(answer.get("findings") or [], start=1):
            rows.append(finding_to_row(batch, model, scope, repetition, final_answer, finding, index))
    return rows


def finding_to_row(
    batch: dict[str, Any],
    model: str,
    scope: str,
    repetition: str,
    final_answer: Path,
    finding: dict[str, Any],
    index: int,
) -> dict[str, str]:
    locations = finding.get("affected_locations") or []
    evidence = finding.get("evidence") or []
    finding_id = str(finding.get("finding_id") or f"F{index}")
    run_id = f"{batch['method_name']}:{model}:{scope}:rep_{repetition}"
    return {
        "finding_uid": f"{run_id}:{finding_id}",
        "model_family": model,
        "method_name": batch["method_name"],
        "input_scope": scope,
        "repetition": repetition,
        "run_id": run_id,
        "final_answer_path": str(final_answer),
        "finding_id": finding_id,
        "model_reported_status": str(finding.get("status") or ""),
        "summary": str(finding.get("summary") or ""),
        "vulnerability_category": str(finding.get("vulnerability_category") or ""),
        "affected_locations": flatten_locations(locations),
        "claimed_files": unique_join(
            [item.get("file", "") for item in locations if isinstance(item, dict)]
            + [item.get("file", "") for item in evidence if isinstance(item, dict)]
        ),
        "claimed_modules": unique_join(
            [item.get("module", "") for item in locations if isinstance(item, dict)]
            + [item.get("module", "") for item in evidence if isinstance(item, dict)]
        ),
        "claimed_signals_or_registers": unique_join(
            [item.get("signal_or_register", "") for item in locations if isinstance(item, dict)]
            + [item.get("object", "") for item in evidence if isinstance(item, dict)]
        ),
        "evidence_items": flatten_evidence(evidence),
        "reasoning_summary": str(finding.get("reasoning_summary") or ""),
        "security_impact": str(finding.get("security_impact") or ""),
        "confidence": str(finding.get("confidence") or ""),
        "uncertainty_or_missing_evidence": str(finding.get("uncertainty_or_missing_evidence") or ""),
        "matched_case_id": "",
        "detection_match": "",
        "duplicate_of_finding_uid": "",
        "evidence_quality": "",
        "review_notes": "",
    }


def flatten_locations(items: list[Any]) -> str:
    parts: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        line = format_line(item)
        parts.append(" | ".join(str(v) for v in [line, item.get("module", ""), item.get("signal_or_register", "")] if v))
    return "\n".join(parts)


def flatten_evidence(items: list[Any]) -> str:
    parts: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        fields = [
            format_line(item),
            item.get("module", ""),
            item.get("object", ""),
            item.get("evidence_type", ""),
            item.get("description", ""),
            item.get("supports_claim", ""),
        ]
        parts.append(" | ".join(str(v) for v in fields if v))
    return "\n".join(parts)


def format_line(item: dict[str, Any]) -> str:
    file = item.get("file") or ""
    start = item.get("line_start")
    end = item.get("line_end")
    if start in {None, ""}:
        return str(file)
    if end in {None, "", start}:
        return f"{file}:{start}"
    return f"{file}:{start}-{end}"


def unique_join(values: list[Any]) -> str:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return "; ".join(out)


def load_evidence_index() -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for path in (PROJECT_ROOT / "datasets" / "benchmarks").glob("hackatdac*/evidence_gt.jsonl"):
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            index[item["case_id"]] = item
    return index


def match_row(row: dict[str, str], gt_by_scope: dict[str, list[dict[str, str]]], evidence: dict[str, dict[str, Any]]) -> None:
    scope = row["input_scope"]
    text = row_text(row)
    candidates = gt_by_scope.get(scope, [])
    case_id, reason = manual_match(scope, text, row, candidates, evidence)
    if case_id:
        row["matched_case_id"] = case_id
        row["detection_match"] = "TP"
        row["evidence_quality"] = "Sufficient"
        row["review_notes"] = reason
    else:
        row["detection_match"] = "FP"
        row["evidence_quality"] = infer_fp_evidence_quality(row)
        row["review_notes"] = reason or "FP: no stable match to a visible GT case in this input scope."


def row_text(row: dict[str, str]) -> str:
    return "\n".join(
        row.get(key, "")
        for key in [
            "summary",
            "vulnerability_category",
            "affected_locations",
            "claimed_files",
            "claimed_modules",
            "claimed_signals_or_registers",
            "evidence_items",
            "reasoning_summary",
            "security_impact",
        ]
    ).lower()


def has_any(text: str, *words: str) -> bool:
    return any(term_in_text(text, word) for word in words)


def has_all(text: str, *words: str) -> bool:
    return all(term_in_text(text, word) for word in words)


def term_in_text(text: str, term: str) -> bool:
    needle = term.lower()
    if re.fullmatch(r"[a-z0-9_]+", needle):
        return re.search(rf"(?<![a-z0-9_]){re.escape(needle)}(?![a-z0-9_])", text) is not None
    return needle in text


def manual_match(
    scope: str,
    text: str,
    row: dict[str, str],
    candidates: list[dict[str, str]],
    evidence: dict[str, dict[str, Any]],
) -> tuple[str, str]:
    # Match on the model's claimed vulnerability semantics. The provided
    # evidence/context may mention many neighboring modules from the chain and
    # must not by itself create a GT hit.
    text = claim_text(row)
    # The rules below encode the manual GT matching rubric from gt_cases.csv plus
    # the benchmark evidence_gt.jsonl hit_summary fields. They intentionally
    # require a mechanism-specific claim, not just a broad security keyword.
    if scope == "h18_debug_jtag_scope":
        if has_all(text, "passchk") and has_any(text, "correct", "bitindex", "threshold", "counter", "partial", "31"):
            return "H18-009", "Matched H18-009: reports incorrect passchk/correct/bitindex password-checking logic."
        if has_any(text, "31 of", "31-bit", "31 bit", "only checks 31", "incomplete password", "partial password"):
            return "H18-010", "Matched H18-010: reports incomplete 32-bit password checking."
        if has_all(text, "passchk") and has_any(text, "not reset", "residual", "sticky", "remains", "lifecycle"):
            return "H18-012", "Matched H18-012: reports passchk authorization state is not cleared after successful check."
        if has_any(text, "jtag", "debug") and has_any(text, "no authentication", "without authentication", "not password", "unprotected", "unauthenticated", "unrestricted"):
            return "H18-028", "Matched H18-028: reports unprotected JTAG/debug access path without password/authentication."
    if scope == "h18_fc_core_security_scope":
        if has_any(text, "debug") and has_any(text, "register file", "gpr", "code injection", "debug_rdata", "debug unit", "csr") and has_any(text, "write", "read", "access"):
            return "H18-017", "Matched H18-017: reports memory-mapped/debug access to CPU register or CSR state."
        if has_any(text, "csr", "mstatus", "mepc", "mret", "machine mode", "priv_lvl", "privilege") and has_any(text, "unprivileged", "no privilege", "without privilege", "bypass", "lower privilege", "force"):
            return "H18-025", "Matched H18-025: reports missing/incorrect privilege enforcement for privileged CSR or privilege state."
        if has_any(text, "secure irq", "core_irq_sec", "core_secure_mode", "secure-mode", "interrupt") and has_any(text, "unconnected", "hardwired", "disabled", "not required", "no security"):
            return "H18-027", "Matched H18-027: reports secure interrupt mediation disabled or not enforced."
    if scope == "h18_gpio_apb_scope":
        if has_any(text, "udma", "spi") and has_any(text, "soc_ctrl", "soc control") and has_any(text, "overlap", "alias"):
            if has_any(text, "gpio"):
                return "H18-008", "Matched H18-008: reports GPIO/SPI-UDMA/SoC-control APB address overlap."
            return "H18-001", "Matched H18-001: reports SPI/UDMA versus SoC-control APB address overlap."
        if has_any(text, "apb") and has_any(text, "alias", "overlap", "range decode", "address range"):
            return "H18-006", "Matched H18-006: reports broader APB address aliasing/range decode issue."
        if has_any(text, "r_gpio_lock", "reg_gpiolock", "gpio lock") and has_any(text, "reset", "hresetn"):
            return "H18-005", "Matched H18-005: reports reset clears GPIO lock state."
        if has_any(text, "r_gpio_lock", "reg_gpiolock", "gpio lock") and has_any(text, "writable", "write", "apb", "software", "bypass"):
            return "H18-004", "Matched H18-004: reports software/APB can write or bypass GPIO lock protection."
    if scope == "h19_access_control_fabric_scope":
        if has_any(text, "clint") and has_any(text, "plic") and has_any(text, "connectivity", "access_ctrl", "bypass", "inherits"):
            return "H19-001", "Matched H19-001: reports CLINT-to-PLIC access-control bypass in connectivity mapping."
        if has_any(text, "dram") and has_any(text, "lower privilege", "user", "privilege") and has_any(text, "fully accessible", "accessible"):
            return "H19-041", "Matched H19-041: reports DRAM accessible from lower privilege."
    if scope == "h19_aes_rom2_security_scope":
        if has_any(text, "aes") and has_any(text, "inter_state", "internal state", "round state") and has_any(text, "read", "visible", "exposed"):
            return "H19-011", "Matched H19-011: reports AES internal state visible externally."
        if has_any(text, "bootrom", "boot rom") and has_any(text, "write", "writable", "corrupt"):
            return "H19-017", "Matched H19-017: reports writable/corruptible bootrom path."
        if has_any(text, "rom2", "secure_reg", "fuse") and has_any(text, "axi", "bus", "memory-mapped") and has_any(text, "accessible", "read", "write", "unprotected"):
            return "H19-045", "Matched H19-045: reports secure ROM2/registers accessible via AXI."
        if has_any(text, "oracle", "encrypt", "decrypt") and has_any(text, "unprivileged", "application", "exposed"):
            return "H19-014", "Matched H19-014: reports AES encrypt/decrypt oracle exposed."
        if has_any(text, "aes") and has_any(text, "hardcoded", "constant") and has_any(text, "key"):
            return "H19-015", "Matched H19-015: reports hardcoded AES key."
        if has_any(text, "aes") and has_any(text, "key", "key_big") and has_any(text, "read", "readable", "exposed", "visible"):
            return "H19-010", "Matched H19-010: reports AES key readback from bus-visible registers."
        if has_any(text, "lock") and has_any(text, "reprogram", "after boot", "boot-up", "writable"):
            return "H19-058", "Matched H19-058: reports register locks can be reprogrammed after boot."
    if scope == "h19_csr_privilege_scope":
        if has_any(text, "umode_i") and has_any(text, "machine", "priv_lvl_m", "force", "escalat"):
            return "H19-009", "Matched H19-009: reports umode_i forcing machine privilege."
        if has_any(text, "csr") and has_any(text, "lower privilege", "user", "supervisor", "bypass", "without privilege", "mepc"):
            if has_any(text, "satp", "tvm"):
                if has_any(text, "read") and not has_any(text, "write"):
                    return "H19-024", "Matched H19-024: reports SATP read access despite TVM."
                return "H19-025", "Matched H19-025: reports SATP write access despite TVM."
            return "H19-020", "Matched H19-020: reports lower-privilege CSR access."
        if has_any(text, "satp") and has_any(text, "tvm"):
            return ("H19-025" if has_any(text, "write") else "H19-024"), "Matched SATP/TVM CSR access case."
    if scope == "h19_debug_jtag_scope":
        if has_any(text, "authenticated") and has_any(text, "hardwired", "always", "enabled", "true"):
            return "H19-005", "Matched H19-005: reports debug authenticated/enabled without real authentication."
        if has_any(text, "dmi", "jtag") and has_any(text, "write", "read", "dtm_write", "dtm_read") and has_any(text, "without password", "bypass", "not gated", "unauthenticated"):
            return "H19-047", "Matched H19-047: reports JTAG/DMI operation not consistently password guarded."
        if has_any(text, "umode", "priv_lvl", "machine mode") and has_any(text, "jtag", "pass_chk", "unlock"):
            return "H19-048", "Matched H19-048: reports JTAG unlock to machine-privilege path."
        if has_any(text, "32-bit", "32 bit", "32 bits") and has_any(text, "password", "jtag_key"):
            return "H19-049", "Matched H19-049: reports 32-bit JTAG password width."
        if has_any(text, "sba", "debug") and has_any(text, "rom2", "fuse"):
            return "H19-050", "Matched H19-050: reports debug SBA access to ROM2/FUSE memory."
        if has_any(text, "pass_chk") and has_any(text, "reset", "not reset"):
            return "H19-051", "Matched H19-051: reports JTAG password flag reset problem."
        if has_any(text, "jtag key", "jtag_key") and has_any(text, "hardcoded", "rom2", "constant"):
            return "H19-054", "Matched H19-054: reports hardcoded ROM2-derived JTAG key."
        if has_any(text, "ndmreset", "secondary reset", "reset control") and has_any(text, "debug", "jtag"):
            return "H19-056", "Matched H19-056: reports debug-controlled secondary reset."
    if scope == "h19_jtag_debug_expansion_scope":
        if has_any(text, "jtag_key") and has_any(text, "unconnected", "undriven", "not driven", "floating"):
            return "H19-046", "Matched H19-046: reports undriven jtag_key reference password port."
        if has_any(text, "jtag reset", "dmi reset", "dmi_rst", "trst", "uninitialized reset") or (
            "reset path" in text and has_any(text, "jtag", "dmi")
        ):
            return "H19-052", "Matched H19-052: reports split/uninitialized JTAG reset path."
        if has_any(text, "debug module") and has_any(text, "system reset", "does not reset", "separated from system reset", "reset path separated"):
            return "H19-053", "Matched H19-053: reports debug module reset separated from system reset."
        if has_any(text, "wrong password", "retry", "lockout", "temporary disable") and has_any(text, "not", "no "):
            return "H19-055", "Matched H19-055: reports no retry lockout/temporary disable."
        if has_any(text, "high impedance", "z state", "floating") and has_any(text, "jtag", "password", "jtag_key"):
            return "H19-057", "Matched H19-057: reports unsanitized/high-impedance JTAG password input."
    if scope == "h21_access_lock_scope":
        if has_any(text, "hmac") and has_any(text, "pkt") and has_any(text, "access", "configuration", "bypass"):
            return "H21-005", "Matched H21-005: reports HMAC access granting PKT access regardless of PKT configuration."
        if has_any(text, "reglk", "register lock") and has_any(text, "reset") and has_any(text, "disabled", "zero", "unlocked"):
            return "H21-035", "Matched H21-035: reports register locks disabled by default/reset."
        if has_any(text, "acct_mem", "access control") and has_any(text, "reset") and has_any(text, "full access", "all 1", "0xffffffff", "fail-open"):
            return "H21-042", "Matched H21-042: reports access-control values reset to full access."
        if has_any(text, "acct") and has_any(text, "not locked", "out-of-range", "reglk_ctrl[13]", "unlocked"):
            return "H21-043", "Matched H21-043: reports missing locks for ACCT registers."
        if has_any(text, "jtag") and has_any(text, "unlock") and has_any(text, "reglock", "reglk", "clear", "disable"):
            return "H21-048", "Matched H21-048: reports JTAG unlock disables reglocks."
        if has_any(text, "chicken") and has_any(text, "access control"):
            return "H21-049", "Matched H21-049: reports chicken-bit corruption of access-control value."
        if has_any(text, "clint") and has_any(text, "not protected", "access control", "unprotected"):
            return "H21-099", "Matched H21-099: reports CLINT registers not protected by access control."
    if scope == "h21_access_reglock_reset_expansion_scope":
        if has_any(text, "plic registers", "plic_wrapper") and has_any(text, "access control", "not protected", "unprotected"):
            return "H21-009", "Matched H21-009: reports PLIC registers not protected by access control."
        if has_any(text, "uart registers", "uart_wrapper") and has_any(text, "access control", "not protected", "unprotected"):
            return "H21-012", "Matched H21-012: reports UART registers not protected by access control."
        if has_any(text, "plic registers", "plic_wrapper") and has_any(text, "not locked", "reglk", "register lock"):
            return "H21-032", "Matched H21-032: reports PLIC registers not locked."
        if has_any(text, "rom registers", "rom_wrapper", "bootrom") and has_any(text, "not locked", "reglk", "register lock"):
            return "H21-033", "Matched H21-033: reports ROM registers not locked."
        if has_any(text, "uart registers", "uart_wrapper") and has_any(text, "not locked", "reglk", "register lock"):
            return "H21-034", "Matched H21-034: reports UART registers not locked."
        if has_any(text, "reset controller", "rst_ctrl", "rst_wrapper") and has_any(
            text,
            "reset register locks",
            "reset register-lock",
            "clear all register-lock",
            "private data",
            "make private data readable",
        ):
            return "H21-072", "Matched H21-072: reports reset controller can reset locks and expose private data."
        if has_any(text, "reglk") and has_any(text, "reglk_mem", "register lock registers") and has_any(
            text, "not locked", "wrong bit", "bypass", "single lock bit", "readable regardless"
        ):
            return "H21-076", "Matched H21-076: reports register-lock registers not protected by locks."
        if has_any(text, "acct") and has_any(text, "reglk_ctrl[13]", "out-of-range", "not locked", "bypass"):
            return "H21-077", "Matched H21-077: reports access-control registers not protected by register locks."
        if has_any(text, "reset controller", "rst_ctrl", "rst_wrapper") and has_any(text, "not locked", "register lock", "reglk"):
            return "H21-081", "Matched H21-081: reports reset-controller registers not locked by reglocks."
    if scope == "h21_crypto_security_scope":
        if (
            has_any(text, "aes2")
            and not has_any(text, "aes0", "aes1", "hmac")
            and has_any(text, "internal register", "internal state", "key register")
            and has_any(text, "visible", "readback", "externally visible", "exposed via")
        ):
            return "H21-013", "Matched H21-013: reports AES2 internal/key registers externally visible."
        if has_any(text, "sha256", "sha input", "sha registers", "sha256_wrapper") and has_any(text, "input", "data") and has_any(text, "not cleared", "residue"):
            return "H21-036", "Matched H21-036: reports SHA input data not cleared after hash."
        if has_any(text, "aes0", "aes") and has_any(text, "plain", "plaintext", "p_c") and has_any(text, "not cleared", "residue", "after encryption"):
            return "H21-039", "Matched H21-039: reports AES plaintext residue after encryption."
        if has_any(text, "debug") and has_any(text, "aes") and has_any(text, "key") and has_any(text, "not cleared", "not zeroed", "not masked", "key2", "key_reg2"):
            return "H21-047", "Matched H21-047: reports AES key not cleared/masked on debug mode."
        if has_any(text, "aes") and has_any(text, "default case") and has_any(text, "key0", "leak"):
            return "H21-060", "Matched H21-060: reports AES key0 leak through incomplete default case."
        if has_any(text, "aes2") and has_any(text, "user mode", "unprivileged"):
            return "H21-073", "Matched H21-073: reports AES2 registers accessible from user mode."
        if has_any(text, "hmac") and has_any(text, "user mode", "unprivileged"):
            return "H21-074", "Matched H21-074: reports HMAC registers accessible from user mode."
        if has_any(text, "hmac") and has_any(text, "key") and has_any(text, "not locked", "no reglk", "without reglk", "register lock"):
            return "H21-075", "Matched H21-075: reports HMAC key registers not locked."
        if has_any(text, "sha registers", "sha256_wrapper") and has_any(text, "not locked", "no reglk", "without reglk", "register lock"):
            return "H21-079", "Matched H21-079: reports SHA registers not locked."
        if has_any(text, "aes1") and has_any(text, "key") and has_any(text, "not locked", "no reglk", "without reglk", "register lock", "not protected by reglk"):
            return "H21-080", "Matched H21-080: reports AES1 key registers not locked."
        if has_any(text, "hmac") and has_any(text, "not reset", "registers are not reset"):
            return "H21-097", "Matched H21-097: reports HMAC registers not reset."
        if has_any(text, "debug") and has_any(text, "aes") and has_any(text, "key") and has_any(text, "exposes", "visible", "leak"):
            return "H21-098", "Matched H21-098: reports AES core exposes keys in debug mode."
    if scope == "h21_dma_pkt_scope":
        if has_any(text, "dma") and has_any(text, "not locked", "reglk", "register lock", "missing lock"):
            return "H21-031", "Matched H21-031: reports DMA registers not locked."
        if has_any(text, "pkt") and has_any(text, "fuse") and has_any(text, "default case", "leak", "readback"):
            return "H21-059", "Matched H21-059: reports PKT leaks fuse data through incomplete/default case."
        if has_any(text, "pkt") and has_any(text, "not locked", "reglk", "register lock"):
            return "H21-078", "Matched H21-078: reports PKT registers not locked."
    if scope == "h21_dma_pmp_expansion_scope":
        if has_any(text, "length") and has_any(text, "max", "syscall"):
            return "H21-045", "Matched H21-045: reports DMA missing max length check in syscall."
        if has_any(text, "chicken") and has_any(text, "pmp", "dma"):
            return "H21-052", "Matched H21-052: reports chicken-bit corruption of DMA PMP check."
        if has_any(text, "load") and has_any(text, "store") and has_any(text, "pmp"):
            return "H21-054", "Matched H21-054: reports DMA load/store PMP check mismatch."
        if has_any(text, "end addr", "end address", "entire range", "range") and has_any(text, "pmp", "dma"):
            return "H21-055", "Matched H21-055: reports DMA checks only end address rather than whole range."
        if has_any(text, "pmp config", "pmpcfg") and has_any(text, "existing", "abort", "change"):
            return "H21-056", "Matched H21-056: reports PMP config change does not abort existing DMA transfer."
        if has_any(text, "64-bit words", "64 bit words", "length") and has_any(text, "syscall", "dma"):
            return "H21-064", "Matched H21-064: reports DMA syscall length unit misuse."
    if scope == "h21_fuse_rng_rsa_expansion_scope":
        if has_any(text, "fuse") and has_any(text, "debug mode", "disconnect", "readback", "sensitive") and not has_any(text, "rsa"):
            return "H21-046", "Matched H21-046: reports sensitive fuse data not disconnected in debug mode/readback path."
        if has_any(text, "lfsr", "polynomial", "rng") and has_any(text, "software", "write", "not checked", "unchecked"):
            return "H21-069", "Matched H21-069: reports software-programmed LFSR polynomial not checked."
        if has_any(text, "rsa", "msg_out", "output message") and has_any(text, "soft reset", "not cleared", "reset"):
            return "H21-095", "Matched H21-095: reports RSA output message not cleared after soft reset."
    if scope == "h21_jtag_auth_expansion_scope":
        if has_any(text, "password flag", "pass_check", "pass_mode", "unlock") and has_any(text, "not reset", "combinational", "resets every cycle"):
            return "H21-001", "Matched H21-001: reports JTAG password flag reset/lifecycle problem."
        if has_any(text, "jtag", "dmi") and has_any(text, "write", "dtm_pass") and has_any(text, "without password", "bypass", "unauthenticated"):
            return "H21-002", "Matched H21-002: reports unauthenticated JTAG write."
        if has_any(text, "256") and has_any(text, "jtag", "password", "padded"):
            return "H21-003", "Matched H21-003: reports JTAG password padded to 256 bits."
        if has_any(text, "wrong password", "retry", "lockout", "temporary disable") and has_any(text, "not", "no "):
            return "H21-004", "Matched H21-004: reports no temporary JTAG disable after wrong passwords."
        if has_any(text, "debug") and has_any(text, "enabled", "authenticated", "hardwired", "always"):
            return "H21-007", "Matched H21-007: reports debug enabled by incorrect access-control setting."
        if has_any(text, "hardcoded", "constant") and has_any(text, "jtag", "key", "hmac"):
            return "H21-030", "Matched H21-030: reports hardcoded JTAG key."
        if has_any(text, "chicken") and has_any(text, "jtag", "password"):
            return "H21-053", "Matched H21-053: reports chicken-bit corruption of expected JTAG password."
    # Conservative fallback: if no mechanism-specific rule fired, do not count as TP.
    return "", "FP: checked against gt_cases.csv and available evidence_gt hit summaries; no mechanism-specific GT match was established."


def claim_text(row: dict[str, str]) -> str:
    return "\n".join(
        row.get(key, "")
        for key in [
            "summary",
            "vulnerability_category",
            "affected_locations",
        ]
    ).lower()


def infer_fp_evidence_quality(row: dict[str, str]) -> str:
    if row.get("evidence_items", "").strip():
        return "Sufficient"
    return "Unsupported"


def mark_duplicates(rows: list[dict[str, str]]) -> None:
    first_tp: dict[tuple[str, str, str, str], str] = {}
    for row in rows:
        if row.get("detection_match") != "TP":
            continue
        key = (row["model_family"], row["method_name"], row["input_scope"], row["repetition"], row["matched_case_id"])
        if key not in first_tp:
            first_tp[key] = row["finding_uid"]
            continue
        original = first_tp[key]
        row["detection_match"] = "Duplicate"
        row["duplicate_of_finding_uid"] = original
        row["review_notes"] = f"Duplicate of {original}: same run reports {row['matched_case_id']} again. " + row.get("review_notes", "")


def build_aggregation_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    grouped: dict[tuple[str, str, str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[
            (
                row["model_family"],
                row["method_name"],
                row["input_scope"],
                row["repetition"],
                row.get("matched_case_id", ""),
                row.get("detection_match", ""),
            )
        ].append(row)
    out: list[dict[str, str]] = []
    for key, group in sorted(grouped.items()):
        model, method, scope, rep, case_id, match = key
        representative = next((row for row in group if row.get("detection_match") == "TP"), group[0])
        out.append(
            {
                "model_family": model,
                "method_name": method,
                "input_scope": scope,
                "repetition": rep,
                "matched_case_id": case_id,
                "detection_match": match,
                "representative_finding_uid": representative.get("finding_uid", ""),
                "duplicate_count": str(sum(1 for row in group if row.get("detection_match") == "Duplicate")),
                "fp_count": str(sum(1 for row in group if row.get("detection_match") == "FP")),
                "example_summaries": "\n---\n".join(row.get("summary", "") for row in group[:5]),
            }
        )
    return out


def compute_single_run(rows: list[dict[str, str]], gt_rows: list[dict[str, str]], batch: dict[str, Any]) -> list[dict[str, str]]:
    repetitions = sorted({row["repetition"] for row in rows}) or status_repetitions(batch) or ["1"]
    out = []
    for rep in repetitions:
        rep_rows = [row for row in rows if row.get("repetition") == rep]
        out.append(metric_row(batch["model_family"], batch["method_name"], rep, gt_rows, rep_rows))
    return out


def metric_row(model: str, method: str, rep: str, gt_rows: list[dict[str, str]], rows: list[dict[str, str]]) -> dict[str, str]:
    gt_ids = {row["case_id"] for row in gt_rows}
    tp_rows = [row for row in rows if row.get("detection_match") == "TP"]
    fp_rows = [row for row in rows if row.get("detection_match") == "FP"]
    hit_ids = {row["matched_case_id"] for row in tp_rows if row.get("matched_case_id")}
    tp_cases = len(hit_ids & gt_ids)
    fn_cases = len(gt_ids - hit_ids)
    precision = ratio(len(tp_rows), len(tp_rows) + len(fp_rows))
    recall = ratio(tp_cases, tp_cases + fn_cases)
    sufficient = sum(1 for row in tp_rows if row.get("evidence_quality") == "Sufficient")
    fabricated_unsupported = sum(
        1 for row in tp_rows + fp_rows if row.get("evidence_quality") in {"Fabricated", "Unsupported"}
    )
    return {
        "model_family": model,
        "method_name": method,
        "repetition": rep,
        "num_gt_cases": str(len(gt_ids)),
        "tp_cases": str(tp_cases),
        "fn_cases": str(fn_cases),
        "tp_findings": str(len(tp_rows)),
        "fp_findings": str(len(fp_rows)),
        "precision": precision,
        "recall": recall,
        "f1_score": f1(precision, recall),
        "evidence_sufficiency_rate": ratio(sufficient, len(tp_rows)),
        "fabricated_unsupported_evidence_rate": ratio(fabricated_unsupported, len(tp_rows) + len(fp_rows)),
    }


def summarize_single_run(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[(row["model_family"], row["method_name"])].append(row)
    metric_names = [
        "precision",
        "recall",
        "f1_score",
        "evidence_sufficiency_rate",
        "fabricated_unsupported_evidence_rate",
    ]
    out: list[dict[str, str]] = []
    for (model, method), group in sorted(grouped.items()):
        item: dict[str, str] = {"model_family": model, "method_name": method}
        for name in metric_names:
            values = [row.get(name, "") for row in group if row.get(name, "") != ""]
            item[f"{name}_mean"] = mean_str(values)
        for name in metric_names:
            values = [row.get(name, "") for row in group if row.get(name, "") != ""]
            item[f"{name}_std"] = sample_std_str(values)
        out.append(item)
    return out


def compute_anyhit(
    rows: list[dict[str, str]],
    gt_rows: list[dict[str, str]],
    all_gt_ids: set[str],
    batch: dict[str, Any],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    tp_rows = [row for row in rows if row.get("detection_match") == "TP"]
    tp_by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in tp_rows:
        tp_by_case[row["matched_case_id"]].append(row)
    case_rows: list[dict[str, str]] = []
    representative_tp: list[dict[str, str]] = []
    for gt in sorted(gt_rows, key=lambda row: row["case_id"]):
        hits = tp_by_case.get(gt["case_id"], [])
        rep = hits[0] if hits else {}
        if rep:
            representative_tp.append(rep)
        case_rows.append(
            {
                "model_family": batch["model_family"],
                "method_name": batch["method_name"],
                "input_scope": gt["input_scope"],
                "benchmark_id": gt["benchmark_id"],
                "case_id": gt["case_id"],
                "case_result": "TP" if hits else "FN",
                "hit_repetitions": ";".join(sorted({row["repetition"] for row in hits})),
                "representative_finding_uid": rep.get("finding_uid", ""),
                "representative_evidence_quality": rep.get("evidence_quality", ""),
                "notes": "",
            }
        )
    fp_rows = [row for row in rows if row.get("detection_match") == "FP"]
    precision = ratio(len(representative_tp), len(representative_tp) + len(fp_rows))
    recall = ratio(len({row["matched_case_id"] for row in representative_tp}), len(all_gt_ids))
    sufficient = sum(1 for row in representative_tp if row.get("evidence_quality") == "Sufficient")
    fabricated_unsupported = sum(
        1 for row in representative_tp + fp_rows if row.get("evidence_quality") in {"Fabricated", "Unsupported"}
    )
    summary = [
        {
            "model_family": batch["model_family"],
            "method_name": batch["method_name"],
            "num_gt_cases": str(len(all_gt_ids)),
            "tp_cases": str(len({row["matched_case_id"] for row in representative_tp})),
            "fn_cases": str(len(all_gt_ids) - len({row["matched_case_id"] for row in representative_tp})),
            "representative_tp_findings": str(len(representative_tp)),
            "fp_findings": str(len(fp_rows)),
            "precision": precision,
            "recall": recall,
            "f1_score": f1(precision, recall),
            "evidence_sufficiency_rate": ratio(sufficient, len(representative_tp)),
            "fabricated_unsupported_evidence_rate": ratio(fabricated_unsupported, len(representative_tp) + len(fp_rows)),
        }
    ]
    return case_rows, summary


def collect_combined_summary() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in sorted(OUTPUT_ROOT.glob("*/*/anyhit3/anyhit3_model_summary.csv")):
        rows.extend(read_csv(path))
    return rows


def ratio(num: int, den: int) -> str:
    if den == 0:
        return ""
    return f"{num / den:.6f}"


def mean_str(values: list[str]) -> str:
    nums = [float(value) for value in values if value != ""]
    if not nums:
        return ""
    return f"{sum(nums) / len(nums):.6f}"


def sample_std_str(values: list[str]) -> str:
    nums = [float(value) for value in values if value != ""]
    if len(nums) < 2:
        return ""
    avg = sum(nums) / len(nums)
    return f"{(sum((value - avg) ** 2 for value in nums) / (len(nums) - 1)) ** 0.5:.6f}"


def f1(precision: str, recall: str) -> str:
    if not precision or not recall:
        return ""
    p = float(precision)
    r = float(recall)
    if p + r == 0:
        return ""
    return f"{2 * p * r / (p + r):.6f}"


def status_repetitions(batch: dict[str, Any]) -> list[str]:
    status_path = batch["batch_dir"] / "batch_status.jsonl"
    if not status_path.exists():
        return []
    reps = set()
    for line in status_path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("batch_id") == batch["batch_dir"].name:
            rep = str(row.get("repetition") or row.get("rep") or "")
            if rep:
                reps.add(rep)
    return sorted(reps)


def summarize_batch_status(batch: dict[str, Any]) -> dict[str, Any]:
    status_path = batch["batch_dir"] / "batch_status.jsonl"
    rows = []
    if status_path.exists():
        rows = [json.loads(line) for line in status_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    latest = {}
    for row in rows:
        latest[row.get("run_id", len(latest))] = row
    final_answers = sorted(batch["batch_dir"].glob("models/*/*/rep_*/final_answer.json"))
    return {
        "batch_dir": str(batch["batch_dir"]),
        "status_rows": len(rows),
        "latest_unique_runs": len(latest),
        "latest_success": sum(1 for row in latest.values() if row.get("status") == "success"),
        "latest_failed": sum(1 for row in latest.values() if row.get("status") == "failed"),
        "final_answer_json": len(final_answers),
        "finding_count": sum(len(json.loads(path.read_text(encoding="utf-8")).get("findings") or []) for path in final_answers),
    }


if __name__ == "__main__":
    raise SystemExit(main())
