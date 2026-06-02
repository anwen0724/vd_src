# Evaluation scripts

本目录存放 baseline/proposed method 输出后的评估脚本。

评估不是全自动判卷。脚本负责把运行结果整理成可人工复核的评分表，并在评分表填写完成后自动汇总主指标。

## 输入

运行结果目录来自：

```text
runs/baseline/<batch_id>/
```

评分还需要 evaluator-side hidden GT 映射：

```text
experiments/<run_id>/evaluation/input_scope_gt_map.csv
```

`input_scope_gt_map.csv` 不给 LLM/method 读取，只给评估脚本和人工评分使用。

## 输出

`build_score_tables.py` 生成：

```text
run_metadata.csv
case_level_scores.csv
finding_level_scores.csv
failure_analysis.csv
```

其中：

- `case_level_scores.csv`：按 hidden GT case 生成待评分行，用于统计 TP、Partial、FN、Recall；
- `finding_level_scores.csv`：按 agent 输出 finding 生成待评分行，用于统计 FP、Precision 和可信性问题；
- `failure_analysis.csv`：记录后验失败原因分析，不作为主指标来源；
- `run_metadata.csv`：记录 run、模型、prompt、输出路径和工具轨迹路径。

人工完成 `case_level_scores.csv` 和 `finding_level_scores.csv` 后，运行 `aggregate_scores.py` 生成：

```text
run_summary.csv
```

`run_summary.csv` 保存论文主指标：

```text
Precision
Recall
Partial rate
Localization error rate
Evidence failure rate
Overconfidence rate
```

## 生成待评分表

示例：

```powershell
python -m evaluation.build_score_tables `
  --batch-dir runs/baseline/baseline_pilot_v1 `
  --gt-map ../experiments/baseline_hackatdac18/evaluation/input_scope_gt_map.csv `
  --gt-map ../experiments/baseline_hackatdac19/evaluation/input_scope_gt_map.csv `
  --gt-map ../experiments/baseline_hackatdac21/evaluation/input_scope_gt_map.csv `
  --output-dir results/baseline/baseline_pilot_v1/scoring_draft
```

## 汇总指标

人工标注完成后：

```powershell
python -m evaluation.aggregate_scores `
  --scoring-dir results/baseline/baseline_pilot_v1/scoring_draft
```

输出：

```text
results/baseline/baseline_pilot_v1/scoring_draft/run_summary.csv
```

## 人工需要填写的字段

实际评分时会看到四张表。它们的职责不同。

### `run_metadata.csv`

一行对应一次 run。

该表记录：

```text
模型
input scope
repetition
prompt 版本
输出文件路径
tool trace 路径
运行时间
```

该表主要用于索引和追溯，一般不需要人工评分。

通常只可能补充：

```text
notes
```

### `finding_level_scores.csv`

一行对应 agent 输出的一个 finding。

该表回答：

```text
agent 报告的这个漏洞发现是否真实？
它对应哪个 GT case？
证据是否充分？
是否存在错误定位、编造证据、无证据结论或过度自信？
```

自动生成字段包括：

```text
run_id
finding_id
input_scope
claimed_summary
claimed_files
claimed_modules
claimed_signals
confidence_label
```

人工需要填写：

```text
matched_case_id
detection_match
evidence_quality
wrong_localization
insufficient_evidence
fabricated_evidence
unsupported_claim
overconfidence
scorer_notes
```

字段含义：

| 字段 | 填写方式 |
|---|---|
| `matched_case_id` | finding 对应的 GT case，例如 `H18-009`；找不到匹配则留空。 |
| `detection_match` | `TP` / `Partial` / `FP` / `Duplicate` / `Unscorable`。 |
| `evidence_quality` | `Sufficient` / `Insufficient` / `Fabricated` / `Unsupported` / `Unclear`。 |
| `wrong_localization` | `yes` / `no` / `unclear`。 |
| `insufficient_evidence` | `yes` / `no` / `unclear`。 |
| `fabricated_evidence` | `yes` / `no` / `unclear`。 |
| `unsupported_claim` | `yes` / `no` / `unclear`。 |
| `overconfidence` | `yes` / `no` / `unclear`。 |
| `scorer_notes` | 简短说明评分依据。 |

该表是计算以下指标的主要来源：

```text
Precision
FP rate
Localization error rate
Evidence failure rate
Overconfidence rate
```

### `case_level_scores.csv`

一行对应某个 run 中应该被发现的一个 hidden GT case。

该表回答：

```text
这个 input scope 里本来应该发现的 GT 漏洞，agent 是否发现了？
```

自动生成字段包括：

```text
run_id
input_scope
benchmark_id
case_id
case_visibility
```

人工需要填写：

```text
case_result
matched_finding_ids
miss_reason
scorer_notes
```

字段含义：

| 字段 | 填写方式 |
|---|---|
| `case_result` | `TP` / `Partial` / `FN` / `Unscorable`。 |
| `matched_finding_ids` | 命中该 case 的 finding id，例如 `F-001`；漏报则留空。 |
| `miss_reason` | 如果是 `FN`，简短记录漏报原因。 |
| `scorer_notes` | 评分说明。 |

该表是计算以下指标的主要来源：

```text
Recall
Partial rate
FN rate
```

### `failure_analysis.csv`

该表用于记录典型失败样本，不作为主指标来源。

适合记录：

```text
典型 FP
典型 FN
错误定位样本
证据不足样本
编造证据样本
过度自信样本
```

人工填写字段：

```text
run_id
input_scope
case_id_or_finding_id
failure_manifestation
failure_layer
suspected_cause
evidence_excerpt
impact_on_engineer
needs_followup
notes
```

该表用于后续：

```text
failure taxonomy
case study
方法设计动机
论文定性分析
```

## 推荐评分顺序

优先从 `finding_level_scores.csv` 开始。

推荐流程：

```text
1. 按 input_scope 分组查看 finding_level_scores.csv。
2. 对每个 finding 填 matched_case_id、detection_match、evidence_quality 和 failure flags。
3. 根据 finding-to-case matching 回填 case_level_scores.csv。
4. 对没有被任何 finding 命中的 visible GT case 标为 FN。
5. 对典型 FP、FN、错误定位、证据失败和过度自信样本补充 failure_analysis.csv。
6. 运行 aggregate_scores.py 生成 run_summary.csv。
```

布尔字段使用：

```text
yes
no
unclear
```

## Reviewed 结果目录

`scoring_draft/` 是全 batch 的原始待评分表，不直接修改。

人工评估时按 input scope 拆分保存：

```text
results/baseline/<batch_id>/scoring_reviewed_scope_<input_scope>/
```

每个 reviewed scope 目录只保留该 scope 的相关行，不保留其他 scope 的空白行。后续需要总指标时，再合并所有 `scoring_reviewed_scope_*` 目录。

每个 reviewed scope 目录还应包含：

```text
scope_evaluation_summary.md
```

该文档用于人工阅读，记录该 scope 的 GT case、逐 run 评分结果、主要观察和评分边界，不参与自动统计。

## 合并 reviewed scope

人工确认各个 reviewed scope 后，可以运行：

```powershell
python -m evaluation.merge_reviewed_scopes `
  --batch-results-dir results/baseline/<batch_id>
```

默认输出：

```text
results/baseline/<batch_id>/scoring_reviewed_all/
```

输出文件：

```text
run_metadata.csv
finding_level_scores.csv
case_level_scores.csv
failure_analysis.csv
run_summary.csv
global_summary.csv
model_summary.csv
model_benchmark_summary.csv
model_scope_summary.csv
scope_summary_index.md
```

含义：

| 文件 | 用途 |
|---|---|
| `run_metadata.csv` | 合并所有 scope 的 run metadata。 |
| `finding_level_scores.csv` | 合并所有 scope 的 finding-level 评分。 |
| `case_level_scores.csv` | 合并所有 scope 的 case-level 评分。 |
| `failure_analysis.csv` | 合并所有 scope 的失败分析样本。 |
| `run_summary.csv` | 重新计算所有 run-level 指标。 |
| `global_summary.csv` | 所有模型、所有 scope、所有 repetition 合并后的全局参考结果。 |
| `model_summary.csv` | 每个模型一行的主结果表。 |
| `model_benchmark_summary.csv` | 每个模型在每个 benchmark 上的结果。 |
| `model_scope_summary.csv` | 每个模型在每个 input scope 上的结果。 |
| `scope_summary_index.md` | 列出本次合并包含的 scope summary 文档。 |

默认启用 strict 校验：

```text
每个 reviewed scope 目录内部只能包含一个 input_scope；
CSV 字段必须符合当前评分表结构；
FP finding 不允许保留 matched_case_id。
```

如果只是临时检查非标准目录，可以加：

```powershell
--no-strict
```
