# Scope Evaluation Summary

## 1. Basic Info

- input_scope: `h19_aes_rom2_security_scope`
- benchmark: `hackatdac19`
- models: `deepseek_v4_pro`, `gpt_5_5`
- repetitions: 3 per model
- expected GT cases: `H19-010`, `H19-011`, `H19-014`, `H19-015`, `H19-017`, `H19-045`, `H19-058`

## 2. GT Cases

| case_id | brief meaning |
|---|---|
| `H19-010` | AES key is readable through AES registers. |
| `H19-011` | AES internal state is externally visible. |
| `H19-014` | AES operation interface acts as an unprivileged crypto oracle. |
| `H19-015` | AES key is hardcoded in ROM2 constants. |
| `H19-017` | Boot ROM is writable through the bus path. |
| `H19-045` | ROM2 secure registers are exposed through AXI. |
| `H19-058` | Access-control/lock configuration can be reprogrammed after boot. |

## 3. Per-run Results

Most runs detect `H19-010` and `H19-045`; selected runs detect `H19-058`. All runs miss `H19-011`, `H19-014`, `H19-015`, and `H19-017` under the current hit criteria.

## 4. Main Observations

The models are strong at direct key-readout and bus-exposed ROM2 register findings. They are weak at distinguishing adjacent crypto/security cases that require more specific semantics: AES internal state readback, crypto oracle exposure, hardcoded-key provenance, and boot ROM writability.

## 5. Notes for Later Scoring

Do not merge all ROM2-related claims into one case. `H19-045` is secure-register AXI exposure; `H19-058` is mutable access-control/lock configuration; `H19-015` requires hardcoded AES key provenance into AES, not only writable or readable ROM2 state.
