# Benchmark Dataset Validation

Last updated: 2026-06-22

## Current Scored Case Counts

- hackatdac18: 12 scored cases
- hackatdac19: 26 scored cases
- hackatdac21: 47 scored cases

Total scored cases: 85

## Agent Input Scope Count

Total agent input scopes under experiments/*/agent_input/: 15

## Expansion Notes

- The 2026-06-22 expansion followed docs/06_evaluation_notes/28_benchmark_dataset_expansion_plan.md.
- New cases were selected from `_seed_mappings/` and existing `task_gt.csv` candidate rows.
- RTL/source evidence was checked against local source mirrors under `third_party/`.
- Repair branches were not used as the primary candidate source.
- The target of around 90 cases was treated as non-mandatory; weak or unsupported candidates were not forced into the scored set.
