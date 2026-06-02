# Scope Evaluation Summary

## 1. Basic Info

- input_scope: `h18_fc_core_security_scope`
- benchmark: `hackatdac18`
- models: `deepseek_v4_pro`, `gpt_5_5`
- repetitions: 3 per model
- evaluated runs: 6
- expected GT cases: `H18-017`, `H18-025`, `H18-027`

## 2. GT Cases

| case_id | brief meaning |
|---|---|
| `H18-017` | Memory-mapped APB debug/register-file path can support code-injection style state manipulation. |
| `H18-025` | Privileged CSR writes lack privilege-level mediation in the zero-riscy CSR path. |
| `H18-027` | APB interrupt control registers can be written without secure-mode gating. |

## 3. Per-run Results

| model | rep | H18-017 | H18-025 | H18-027 | extra FP |
|---|---:|---|---|---|---:|
| `deepseek_v4_pro` | 1 | Partial | Partial | Partial | 1 |
| `deepseek_v4_pro` | 2 | Partial | Partial | Partial | 0 |
| `deepseek_v4_pro` | 3 | FN | Partial | Partial | 2 |
| `gpt_5_5` | 1 | TP | FN | TP | 1 |
| `gpt_5_5` | 2 | FN | FN | TP | 1 |
| `gpt_5_5` | 3 | TP | FN | TP | 0 |

## 4. Main Observations

DeepSeek usually identifies broad CSR/debug/interrupt security smells, but often misses the full evidence chain required by the GT. Its findings are therefore mostly Partial, with some unrelated FP outputs.

GPT is stronger on APB debug and APB interrupt secure-mode cases. It correctly detects `H18-017` in two runs and `H18-027` in all three runs. However, it does not detect `H18-025`; its supervisor-mode findings do not establish the zero-riscy CSR instruction/write mediation bug.

## 5. Notes for Later Scoring

Do not score generic hardwired supervisor-mode findings as `H18-025` unless the finding also identifies the CSR instruction decode/write path and privileged CSR targets. For `H18-017`, the key requirement is APB-visible debug access reaching register-file write/read or execution redirection evidence. For `H18-027`, the key requirement is APB writes to interrupt registers without `core_secure_mode_i` gating.
