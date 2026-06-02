# Scope Evaluation Summary

## 1. Basic Info

- input_scope: `h19_access_control_fabric_scope`
- benchmark: `hackatdac19`
- models: `deepseek_v4_pro`, `gpt_5_5`
- repetitions: 3 per model
- expected GT cases: `H19-001`, `H19-041`

## 2. GT Cases

| case_id | brief meaning |
|---|---|
| `H19-001` | CLINT permission bit incorrectly grants PLIC access in AXI connectivity map. |
| `H19-041` | DRAM region is accessible from lower privilege level. |

## 3. Per-run Results

| model | rep | H19-001 | H19-041 |
|---|---:|---|---|
| `deepseek_v4_pro` | 1 | TP | FN |
| `deepseek_v4_pro` | 2 | FN | FN |
| `deepseek_v4_pro` | 3 | TP | FN |
| `gpt_5_5` | 1 | TP | FN |
| `gpt_5_5` | 2 | TP | FN |
| `gpt_5_5` | 3 | TP | FN |

## 4. Main Observations

Most runs detect the PLIC/CLINT permission alias. No run identifies the DRAM lower-privilege access case. Several ROM2/access-control mutability findings are plausible security issues but are not scored as visible GT hits in this scope.

## 5. Notes for Later Scoring

Do not score ROM2 secure-register or access-control mutability findings as `H19-041` unless the finding specifically identifies DRAM lower-privilege accessibility through the matrix.
