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

`case_level_scores.csv`：

```text
case_result
matched_finding_ids
miss_reason
scorer_notes
```

`finding_level_scores.csv`：

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

布尔字段使用：

```text
yes
no
unclear
```
