# Scope Evaluation Summary

## 1. Basic Info

- input_scope: `h18_debug_jtag_scope`
- benchmark: `hackatdac18`
- models: `deepseek_v4_pro`, `gpt_5_5`
- repetitions: 3 per model
- evaluated runs: 6
- expected GT cases: `H18-009`, `H18-010`, `H18-012`, `H18-028`
- scoring tables:
  - `finding_level_scores.csv`
  - `case_level_scores.csv`
  - `failure_analysis.csv`
  - `run_summary.csv`

## 2. GT Cases

| case_id | brief meaning |
|---|---|
| `H18-009` | Incorrect password checking logic in the debug TAP. |
| `H18-010` | Advanced debug unit only checks part of the intended password bits. |
| `H18-012` | Debug password-check state is not reset after successful authentication. |
| `H18-028` | JTAG interface exposes an unprotected path to internal debug/LINT access. |

## 3. Per-run Results

| model | rep | H18-009 | H18-010 | H18-012 | H18-028 | extra FP |
|---|---:|---|---|---|---|---:|
| `deepseek_v4_pro` | 1 | FN | FN | FN | Partial | 0 |
| `deepseek_v4_pro` | 2 | FN | FN | FN | Partial | 0 |
| `deepseek_v4_pro` | 3 | FN | FN | FN | Partial | 0 |
| `gpt_5_5` | 1 | FN | FN | FN | TP | 1 |
| `gpt_5_5` | 2 | FN | FN | FN | Partial | 0 |
| `gpt_5_5` | 3 | FN | FN | FN | TP | 0 |

## 4. Main Observations

The two models repeatedly identify a broad JTAG/debug authentication risk, but they do not identify the three finer-grained password-check logic cases.

`H18-009`, `H18-010`, and `H18-012` require reasoning about the specific `passchk`, `correct`, `bitindex`, and `pass` logic in the advanced debug TAP. None of the six runs provided a finding that matched these implementation-level password-check defects.

`H18-028` is easier for the models to approach because it matches a broader unprotected debug-interface pattern. GPT produced two TP results by tracing the integrated JTAG-to-LINT path through `pulp_soc`, `lint_jtag_wrap`, `adbg_lintonly_top`, and related LINT bus evidence. DeepSeek produced only Partial results because its findings mainly focused on generic or standalone `adv_dbg_if` / AXI debug access and did not sufficiently prove the official integrated LINT path.

GPT rep1 also produced one extra FP: a conditional standalone `adv_dbg_if` AXI/CPU debug warning. The model itself noted that this path was not proven integrated in the visible top-level SoC path, so it was not counted as a visible GT case for this input scope.

## 5. Notes for Later Scoring

For this scope, generic statements such as "JTAG debug has no authentication" are not enough to match all debug-related GT cases.

Scoring boundary:

- Match `H18-009`, `H18-010`, or `H18-012` only when the finding identifies the specific password-check implementation logic and cites relevant `passchk`, `correct`, `bitindex`, or `pass` evidence.
- Match `H18-028` as TP only when the finding traces the integrated JTAG-to-LINT/internal debug path through SoC-level wiring and LINT debug bus evidence.
- Treat standalone `adv_dbg_if` / AXI debug claims as Partial or FP depending on whether the official integrated path is established.

This scope is a useful early example of the baseline problem: models can detect a broad security smell but may miss concrete RTL implementation vulnerabilities and may overstate insufficiently localized evidence.
