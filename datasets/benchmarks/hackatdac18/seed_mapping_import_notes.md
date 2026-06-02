# Hack@DAC18 Seed Mapping Import Notes

## Status

Hack@DAC18 already had structured benchmark data before moving seed mappings into `data/benchmarks/_seed_mappings/`.

This file records how the seed mapping should be used going forward.

## Existing Structured Data

- `official_gt.csv`: 31 official cases already present.
- `task_gt.csv`: 31 task-level rows already present.
- `priority_cases.md`: existing priority batch notes.
- `cases/`: case-level GT exists for selected priority cases.
- `evidence_gt.jsonl`: evidence-level GT exists for selected priority cases.

## Seed Mapping

Seed mapping path:

```text
data/benchmarks/_seed_mappings/hackatdac2018_full_mapping.md
```

Use this seed mapping only as a description-level reference when checking or extending Hack@DAC18 task labels.

Do not overwrite existing `official_gt.csv`, `task_gt.csv`, `cases/`, or `evidence_gt.jsonl` from the seed mapping.

## Next Use

When selecting additional Hack@DAC18 cases for RTL evidence review, use:

- existing `task_gt.csv`;
- existing `priority_cases.md`;
- seed mapping priority groups as a secondary reference.

All new cases still require source-level RTL evidence review before being marked `rtl_confirmed`.
