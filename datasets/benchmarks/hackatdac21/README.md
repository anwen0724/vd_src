# hackatdac21 Benchmark Data

This directory stores structured benchmark data derived from the seed mapping document.

Source seed mapping:

```text
data/benchmarks/_seed_mappings/hackatdac2021_full_mapping.md
```

Design target: OpenPiton + Ariane/RISC-V

Current status:

- `official_gt.csv`: initialized from description-level seed mapping.
- `task_gt.csv`: initialized from description-level seed mapping; first RTL-confirmed batch has been labeled.
- `eval_case_set.csv`: first RTL-confirmed evaluation set for Hack@DAC21.
- `batch_plan.md`: records selected and deferred case groups.
- `cases/`: case-level GT documents for confirmed cases.
- `evidence_gt.jsonl`: hidden evidence records for confirmed cases.

Important constraints:

- Only cases marked `rtl_confirmed` should be used for scoring.
- Cases still marked `needs_review` are not baseline-ready.
- Do not treat description-level labels as ground truth without source evidence.

Confirmed evaluation set:

- current_confirmed_cases: 22
- H21-005: HMAC access grants PKT access through access-control coupling.
- H21-013: AES internal registers externally visible.
- H21-031: DMA registers missing register-lock mediation.
- H21-035: register locks reset to disabled state.
- H21-036: SHA input data remains readable after hash computation.
- H21-039: AES plaintext remains readable after encryption.
- H21-042: access-control values reset to full access.
- H21-043: some ACCT registers are not effectively register-lock protected.
- H21-047: one AES0 key path is not masked in debug mode.
- H21-048: JTAG unlock clears register-lock state.
- H21-049: chicken-bit style flag corrupts access-control output.
- H21-059: PKT read/default handling can leak fuse data.
- H21-060: AES0 key0 can leak through default read handling.
- H21-073: AES2 protected registers accessible from user mode through reset-open access control.
- H21-074: HMAC protected registers are accessible from user mode through reset-open access control.
- H21-075: HMAC key-derived registers have inconsistent register-lock mediation.
- H21-078: PKT fuse-control registers are writable without lock guards.
- H21-079: SHA data registers have inconsistent read/write lock mediation.
- H21-080: AES1 key registers have inconsistent read/write lock mediation.
- H21-097: HMAC key-related registers are not reset.
- H21-098: AES1 key path remains unmasked in debug mode.
- H21-099: CLINT registers lack explicit access-control mediation.
