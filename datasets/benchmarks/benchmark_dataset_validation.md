# Benchmark Dataset Validation

## 1. 验收范围

本次验收覆盖：

- `data/benchmarks/hackatdac18/`
- `data/benchmarks/hackatdac19/`
- `data/benchmarks/hackatdac21/`

验收目标：

- 确认三套 benchmark 的核心文件齐全；
- 确认 `task_gt.csv`、`eval_case_set.csv`、`evidence_gt.jsonl`、`cases/*.md` 的评分 case 能互相对应；
- 生成统一总览表 `data/benchmarks/benchmark_case_inventory.csv`，供后续 baseline 实验调度和统计使用。

## 2. 核心文件状态

| Benchmark | `official_gt.csv` | `task_gt.csv` | `eval_case_set.csv` | `evidence_gt.jsonl` | `cases/*.md` |
|---|---:|---:|---:|---:|---:|
| Hack@DAC18 | OK | OK | OK | OK | 13 |
| Hack@DAC19 | OK | OK | OK | OK | 21 |
| Hack@DAC21 | OK | OK | OK | OK | 22 |

## 3. 评分 Case 对应关系

| Benchmark | official rows | task rows | `rtl_confirmed` | eval rows | evidence records | eval case docs |
|---|---:|---:|---:|---:|---:|---:|
| Hack@DAC18 | 31 | 31 | 12 | 12 | 13 | 12 |
| Hack@DAC19 | 66 | 66 | 21 | 21 | 21 | 21 |
| Hack@DAC21 | 99 | 99 | 22 | 22 | 22 | 22 |
| **Total** | 196 | 196 | 55 | 55 | 56 | 55 |

结论：

- 三套 benchmark 的评分集总计 55 个 case。
- `eval_case_set.csv` 中的 55 个 case 均能在 `task_gt.csv` 中找到 `rtl_confirmed` 标记。
- `eval_case_set.csv` 中的 55 个 case 均有对应 case 文档。
- `eval_case_set.csv` 中的 55 个 case 均有对应 evidence 记录。

## 4. Schema 状态

`eval_case_set.csv` 三套 benchmark 字段一致：

```text
case_id,official_id,task_relevance,permission_security_objective,evidence_status,eval_label,case_doc,evidence_gt_ref,scoring_use,notes
```

`task_gt.csv` 中 Hack@DAC19 和 Hack@DAC21 字段一致：

```text
case_id,official_id,task_relevance,relevance_reason,permission_security_objective,vulnerable_behavior_summary,expected_safe_behavior_summary,needs_source_review,label_status,notes
```

Hack@DAC18 的 `task_gt.csv` 额外保留了 legacy 字段：

```text
permission_related,cross_module,legacy_include_in_task,legacy_permission_category,legacy_bug_id
```

这不影响后续使用，因为评分入口以 `eval_case_set.csv` 和 `benchmark_case_inventory.csv` 为准。

## 5. 已知差异

Hack@DAC18 存在一个额外非评分产物：

- `cases/H18-031.md`
- `evidence_gt.jsonl` 中的 `H18-031`

该 case 未进入 `eval_case_set.csv`，也未在 `task_gt.csv` 中标为 `rtl_confirmed`。当前处理方式：

- 不纳入 `benchmark_case_inventory.csv`；
- 不参与 baseline 评分；
- 后续如需使用，必须先补充进入 `task_gt.csv` 与 `eval_case_set.csv`，并重新验收。

## 6. 当前可用评分集

| Benchmark | confirmed scoring cases |
|---|---:|
| Hack@DAC18 | 12 |
| Hack@DAC19 | 21 |
| Hack@DAC21 | 22 |
| **Total** | **55** |

当前统一总览表：

```text
data/benchmarks/benchmark_case_inventory.csv
```

该表只收录已进入 `eval_case_set.csv` 的评分 case，不包含 description-level candidate 或未进入评分集的遗留 case。

## 7. 后续使用原则

- baseline 实验 case 列表优先从 `benchmark_case_inventory.csv` 读取。
- agent 不应读取 `data/benchmarks/**` 下的 GT/evidence/case 文档。
- agent 可读取的源码输入应来自 `third_party/hackatdac18/`、`third_party/hackatdac19/`、`third_party/hackatdac21/` 或后续构造的 sanitized input scope。
- 评分时使用 `eval_case_set.csv`、`cases/*.md`、`evidence_gt.jsonl` 作为隐藏 GT。
