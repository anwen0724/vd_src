# Scope Evaluation Summary

## 1. Basic Info

- input_scope: `h19_csr_privilege_scope`
- benchmark: `hackatdac19`
- models: `deepseek_v4_pro`, `gpt_5_5`
- repetitions: 3 per model
- expected GT cases: `H19-009`, `H19-020`, `H19-024`, `H19-025`

## 2. GT Cases

| case_id | brief meaning |
|---|---|
| `H19-009` | `umode_i` can force effective machine privilege. |
| `H19-020` | `CSR_MEPC` is exempted from normal CSR privilege checks. |
| `H19-024` | SATP read is not blocked when TVM is enabled. |
| `H19-025` | SATP write is not blocked when TVM is enabled. |

## 3. Per-run Results

All six runs detect `H19-009` and `H19-020`. All six runs miss `H19-024` and `H19-025`.

## 4. Main Observations

The models reliably detect conspicuous CSR privilege bypasses involving `umode_i` and `CSR_MEPC`. They fail on the more conditional SATP/TVM cases, which require checking mode-specific virtual-memory mediation rather than generic CSR privilege exceptions.

## 5. Notes for Later Scoring

Do not score MEPC or umode findings as SATP/TVM cases. `H19-024` and `H19-025` require explicit `CSR_SATP` read/write and `mstatus.tvm` mediation evidence.
