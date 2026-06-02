# hackatdac19 Benchmark Data

This directory stores structured benchmark data derived from the seed mapping document.

Source seed mapping:

```text
data/benchmarks/_seed_mappings/hackatdac2019_full_mapping.md
```

Design target: Ariane SoC

Current status:

- `official_gt.csv`: initialized from description-level seed mapping.
- `task_gt.csv`: initialized from description-level seed mapping; RTL-confirmed batches have been updated.
- `batch_plan.md`: records priority groups and the current RTL evidence batch.
- `cases/`: contains case-level GT for RTL-confirmed cases.
- `evidence_gt.jsonl`: contains hidden evidence-level GT for RTL-confirmed cases.
- `eval_case_set.csv`: contains the current scored positive case set.

Important constraints:

- These files are not baseline-ready.
- Only cases marked `rtl_confirmed` and included in `eval_case_set.csv` should be used for scoring.
- Remaining `needs_review` cases still require RTL evidence review before constructing agent input.

Current confirmed eval cases:

- H19-001
- H19-009
- H19-010
- H19-011
- H19-017
- H19-020
- H19-024
- H19-025
- H19-045
- H19-005
- H19-047
- H19-048
- H19-051
- H19-054
- H19-056
- H19-058
- H19-014
- H19-015
- H19-041
- H19-049
- H19-050
