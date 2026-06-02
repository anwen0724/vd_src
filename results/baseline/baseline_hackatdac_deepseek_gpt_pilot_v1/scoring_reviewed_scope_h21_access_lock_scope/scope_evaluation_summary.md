# Scope Evaluation Summary

## 1. Basic Info

- input_scope: `h21_access_lock_scope`
- benchmark: `hackatdac21`
- models: `deepseek_v4_pro`, `gpt_5_5`
- repetitions: 3 per model
- expected GT cases: `H21-005`, `H21-035`, `H21-042`, `H21-043`, `H21-048`, `H21-049`, `H21-099`

## 2. GT Cases

This scope covers access-control coupling, reset-default access control, register-lock behavior, JTAG unlock interaction, chicken-bit corruption, and CLINT access-control omission.

## 3. Per-run Results

Models commonly detect `H21-042`; some runs detect `H21-005`, `H21-043`, `H21-048`, and `H21-049`. No run detects `H21-035` or `H21-099`.

## 4. Main Observations

The models handle obvious all-ones access-control reset well, but confuse several adjacent lock bugs. Many findings are plausible RTL issues but not visible GT cases for this scope.

## 5. Notes for Later Scoring

Keep `H21-035` separate from `H21-048`: reset-to-unlocked reglocks is not the same as JTAG unlock clearing reglocks. Keep `H21-005` direction-specific: HMAC permission grants PKT access.
