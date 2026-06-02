# Scope Evaluation Summary

## 1. Basic Info

- input_scope: `h21_crypto_security_scope`
- benchmark: `hackatdac21`
- models: `deepseek_v4_pro`, `gpt_5_5`
- repetitions: 3 per model
- expected GT cases: 12 crypto/access-control cases

## 2. GT Cases

This scope covers AES/SHA/HMAC state exposure, uncleared sensitive state, debug-mode key exposure, user-mode access to crypto peripherals, inconsistent register locks, and reset residue.

## 3. Per-run Results

DeepSeek detects AES debug key-clearing issues in rep1 and rep3. GPT detects broad default-allow crypto access-control in rep1 and rep3. Most other crypto-specific GT cases are missed.

## 4. Main Observations

The models find high-level access-control/reset-default and debug-key patterns, but miss most fine-grained crypto register state issues. They do not reliably inspect individual read maps, reset blocks, and lock-bit consistency across AES/SHA/HMAC wrappers.

## 5. Notes for Later Scoring

Do not count broad we_flag, ACCT, or REGLK findings as crypto GT unless the finding ties to a specific AES/SHA/HMAC case. For debug key cases, AES0 `key_big2` maps to `H21-047`; AES1 `core_key1` maps to `H21-098`.
