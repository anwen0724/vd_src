# Baseline Evaluation Workflow

本文档记录 baseline 运行完成后的评估流程。

适用对象：

```text
runs/baseline/<batch_id>/
```

当前 baseline batch：

```text
runs/baseline/baseline_hackatdac_deepseek_gpt_pilot_v1/
```

## 1. 评估目标

评估不是只判断模型“有没有输出漏洞”，而是判断：

```text
1. agent 是否发现了 input scope 中应该发现的 GT case；
2. agent 报告的 finding 是否真实、定位是否正确、证据是否充分；
3. agent 输出是否可能因为误报、漏报、错误定位、证据失败或过度自信误导工程师。
```

主指标分两组。

Detection：

```text
Precision
Recall
Partial rate
```

Analysis reliability：

```text
Localization error rate
Evidence failure rate
Overconfidence rate
```

## 2. 评估输入材料

### 2.1 Agent 输出

每个 run 的输出目录：

```text
runs/baseline/<batch_id>/models/<model_id>/<input_scope>/rep_<n>/
```

核心文件：

```text
final_answer.json
tool_trace.jsonl
run_metadata.json
```

用途：

| 文件 | 用途 |
|---|---|
| `final_answer.json` | 查看 agent 报告的 findings、声称文件、模块、信号、证据、置信度和不确定性。 |
| `tool_trace.jsonl` | 查看 agent 实际调用了哪些 read/search 工具、读取过哪些文件、工具返回了什么。 |
| `run_metadata.json` | 查看模型、input scope、prompt、时间和输出路径。 |

### 2.2 Hidden GT

评分使用的 GT 资料位于：

```text
datasets/benchmarks/hackatdac18/
datasets/benchmarks/hackatdac19/
datasets/benchmarks/hackatdac21/
```

核心文件：

```text
input_scope_gt_map.csv
task_gt.csv
evidence_gt.jsonl
cases/<case_id>.md
```

用途：

| 文件 | 用途 |
|---|---|
| `input_scope_gt_map.csv` | 确定每个 input scope 中应评价哪些 GT case。 |
| `task_gt.csv` | 查看 case 的任务级描述、类别、状态和简要语义。 |
| `evidence_gt.jsonl` | 查看 case 的关键 RTL evidence，包括文件、模块、信号、路径和证据含义。 |
| `cases/<case_id>.md` | 查看 case 的完整描述、hit criteria 和人工整理说明。 |

### 2.3 RTL 源码

Agent 可见源码位于：

```text
datasets/agent_inputs/<benchmark>/<input_scope>/
```

用途：

```text
确认 agent 引用的文件、模块、信号、寄存器是否真实存在；
确认 agent 给出的证据是否足以支撑结论；
确认 finding 是否定位到正确文件、模块、信号或跨文件路径。
```

## 3. 生成待评分表

运行：

```powershell
conda run -n vulnerability_detection python -m evaluation.build_score_tables `
  --batch-dir runs/baseline/baseline_hackatdac_deepseek_gpt_pilot_v1 `
  --gt-map datasets/benchmarks/hackatdac18/input_scope_gt_map.csv `
  --gt-map datasets/benchmarks/hackatdac19/input_scope_gt_map.csv `
  --gt-map datasets/benchmarks/hackatdac21/input_scope_gt_map.csv `
  --output-dir results/baseline/baseline_hackatdac_deepseek_gpt_pilot_v1/scoring_draft
```

输出：

```text
results/baseline/<batch_id>/scoring_draft/
  run_metadata.csv
  finding_level_scores.csv
  case_level_scores.csv
  failure_analysis.csv
```

## 4. 四张表的作用

### 4.1 `run_metadata.csv`

一行对应一次 run。

记录：

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

### 4.2 `finding_level_scores.csv`

一行对应 agent 输出的一个 finding。

该表回答：

```text
agent 报告的这个 finding 是否真实？
它对应哪个 GT case？
证据是否充分？
是否存在错误定位、编造证据、无证据结论或过度自信？
```

自动生成字段：

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

人工填写字段：

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

### 4.3 `case_level_scores.csv`

一行对应某个 run 中应该被发现的一个 hidden GT case。

该表回答：

```text
这个 input scope 中本来应该发现的 GT case，agent 是否发现了？
```

自动生成字段：

```text
run_id
input_scope
benchmark_id
case_id
case_visibility
```

人工填写字段：

```text
case_result
matched_finding_ids
miss_reason
scorer_notes
```

### 4.4 `failure_analysis.csv`

用于记录典型失败样本。

该表不作为主指标来源，主要用于：

```text
failure taxonomy
case study
方法设计动机
论文定性分析
```

适合记录：

```text
典型 FP
典型 FN
错误定位样本
证据不足样本
编造证据样本
过度自信样本
```

## 5. 填写 `finding_level_scores.csv`

优先从该表开始评分。

对每个 finding，执行以下判断。

### 5.1 匹配 GT case

查看：

```text
claimed_summary
claimed_files
claimed_modules
claimed_signals
confidence_label
```

再对照：

```text
datasets/benchmarks/<benchmark>/cases/<case_id>.md
datasets/benchmarks/<benchmark>/evidence_gt.jsonl
datasets/benchmarks/<benchmark>/task_gt.csv
datasets/agent_inputs/<benchmark>/<input_scope>/
```

填写：

```text
matched_case_id
detection_match
```

`detection_match` 取值：

| 值 | 含义 |
|---|---|
| `TP` | finding 能匹配一个 visible GT case，且漏洞语义和关键证据基本正确。 |
| `Partial` | finding 与某个 GT case 相关，但定位、条件、路径或证据不完整。 |
| `FP` | finding 不能匹配任何 visible GT case，也不能确认为有效新问题。 |
| `Duplicate` | finding 与同一 run 中已有 finding 指向同一问题，不重复计入 TP。 |
| `Unscorable` | finding 缺少必要信息或输出异常，无法评分。 |

### 5.2 判断证据质量

填写：

```text
evidence_quality
```

取值：

| 值 | 含义 |
|---|---|
| `Sufficient` | 证据真实存在，且足以支撑 finding 的主要结论。 |
| `Insufficient` | 证据真实存在，但不足以支撑结论。 |
| `Fabricated` | 证据中的文件、模块、信号、寄存器、行号或行为不存在。 |
| `Unsupported` | finding 有结论，但没有提供有效证据。 |
| `Unclear` | 输出信息不足，人工无法判断。 |

### 5.3 填写 reliability flags

填写：

```text
wrong_localization
insufficient_evidence
fabricated_evidence
unsupported_claim
overconfidence
```

布尔字段取值：

```text
yes
no
unclear
```

含义：

| 字段 | 何时填 `yes` |
|---|---|
| `wrong_localization` | finding 的方向可能相关，但文件、模块、信号、寄存器或路径定位错误。 |
| `insufficient_evidence` | 证据真实存在，但不足以支撑结论。 |
| `fabricated_evidence` | 引用的文件、模块、信号、寄存器、行号或行为不存在。 |
| `unsupported_claim` | 给出安全结论，但没有提供有效代码证据。 |
| `overconfidence` | finding 是 FP、Partial、证据不足、编造证据或不确定问题，但 agent 仍以高置信度或确定语气输出。 |

## 6. 回填 `case_level_scores.csv`

完成 finding-to-case matching 后，再回填 case-level 表。

对每个 `case_id`：

```text
查看 finding_level_scores.csv 中是否有 matched_case_id 等于该 case_id 的 finding。
```

填写：

```text
case_result
matched_finding_ids
miss_reason
scorer_notes
```

`case_result` 取值：

| 值 | 含义 |
|---|---|
| `TP` | 至少有一个 finding 以 `TP` 命中该 GT case。 |
| `Partial` | 没有 TP finding，但至少有一个 Partial finding 关联该 case。 |
| `FN` | 该 case 在当前 input scope 可见，但没有任何 finding 命中。 |
| `Unscorable` | 当前 run 或输出异常，无法可靠评分。 |

回填规则：

```text
如果 finding_level_scores.csv 中存在：
  matched_case_id = HXX-YYY
  detection_match = TP

则 case_level_scores.csv 中对应 case：
  case_result = TP
  matched_finding_ids = 对应 finding_id
```

```text
如果只有 Partial finding 命中：
  case_result = Partial
  matched_finding_ids = 对应 finding_id
```

```text
如果没有任何 finding 命中：
  case_result = FN
  matched_finding_ids 留空
  miss_reason 简短说明漏报原因
```

## 7. 两张表的一致性要求

`finding_level_scores.csv` 和 `case_level_scores.csv` 必须一致。

例如：

```text
finding_level_scores.csv:
  finding_id = F-001
  matched_case_id = H18-009
  detection_match = TP

case_level_scores.csv:
  case_id = H18-009
  case_result = TP
  matched_finding_ids = F-001
```

如果一个 finding 被标为 `FP`：

```text
matched_case_id 留空
detection_match = FP
```

则不应出现在任何 case 的 `matched_finding_ids` 中。

如果一个 GT case 没有任何 matched finding：

```text
case_result = FN
matched_finding_ids 留空
```

## 8. 汇总指标

人工评分完成后运行：

```powershell
conda run -n vulnerability_detection python -m evaluation.aggregate_scores `
  --scoring-dir results/baseline/baseline_hackatdac_deepseek_gpt_pilot_v1/scoring_draft
```

输出：

```text
results/baseline/baseline_hackatdac_deepseek_gpt_pilot_v1/scoring_draft/run_summary.csv
```

`run_summary.csv` 计算：

```text
Precision
Recall
Partial_rate
FP_rate
FN_rate
Localization_error_rate
Evidence_failure_rate
Overconfidence_rate
```

## 9. 推荐执行顺序

推荐按 input scope 分批评分。

第一轮建议选择一个 scope 试评分：

```text
h18_debug_jtag_scope
```

步骤：

```text
1. 筛选 finding_level_scores.csv 中 input_scope = h18_debug_jtag_scope 的行。
2. 对照 final_answer.json、tool_trace.jsonl、cases/*.md、evidence_gt.jsonl 和 RTL 源码完成 finding-level 评分。
3. 回填同一 scope 的 case_level_scores.csv。
4. 检查 finding-to-case 与 case-to-finding 是否一致。
5. 再扩展到其他 input scopes。
```

不建议一开始直接评分全部 60 个 run，因为评分口径需要先通过小范围样本校准。

## 10. Reviewed 目录组织规则

`scoring_draft/` 保留全 batch 的原始待评分表，不直接修改。

每个完成评分的 input scope 单独保存一个 reviewed 目录：

```text
results/baseline/<batch_id>/scoring_reviewed_scope_<input_scope>/
```

该目录只保留该 input scope 相关行：

```text
run_metadata.csv
finding_level_scores.csv
case_level_scores.csv
failure_analysis.csv
run_summary.csv
scope_evaluation_summary.md
```

要求：

```text
run_metadata.csv 只包含该 scope 的 run；
finding_level_scores.csv 只包含该 scope 的 findings；
case_level_scores.csv 只包含该 scope 的 GT case rows；
failure_analysis.csv 只包含该 scope 的失败分析记录；
run_summary.csv 只包含该 scope 的汇总结果。
scope_evaluation_summary.md 记录该 scope 的人工可读评估总结。
```

不要在单个 reviewed scope 目录中保留其他 scope 的空白行。后续需要论文总指标时，再由脚本合并所有 `scoring_reviewed_scope_*` 目录。

`scope_evaluation_summary.md` 不参与自动统计，主要用于快速回顾和后续论文分析。建议固定包含：

```text
1. Basic Info
2. GT Cases
3. Per-run Results
4. Main Observations
5. Notes for Later Scoring
```

## 11. 合并所有 reviewed scope

人工确认各个 scope 的评分后，运行：

```powershell
python -m evaluation.merge_reviewed_scopes `
  --batch-results-dir results/baseline/<batch_id>
```

默认输出：

```text
results/baseline/<batch_id>/scoring_reviewed_all/
```

该目录包含：

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

文件含义：

| 文件 | 含义 |
|---|---|
| `run_metadata.csv` | 合并所有 scope 的 run metadata。 |
| `finding_level_scores.csv` | 合并所有 scope 的 finding-level 评分。 |
| `case_level_scores.csv` | 合并所有 scope 的 case-level 评分。 |
| `failure_analysis.csv` | 合并所有 scope 的失败分析样本。 |
| `run_summary.csv` | 每次 run 一行，即 `model × input_scope × repetition`。 |
| `global_summary.csv` | 所有模型、所有 scope、所有 repetition 合并后的全局参考结果。 |
| `model_summary.csv` | 每个模型一行的主结果表。 |
| `model_benchmark_summary.csv` | 每个模型在每个 benchmark 上的结果。 |
| `model_scope_summary.csv` | 每个模型在每个 input scope 上的结果。 |
| `scope_summary_index.md` | 列出本次合并包含的 scope summary 文档。 |

论文主结果优先查看：

```text
model_summary.csv
model_scope_summary.csv
model_benchmark_summary.csv
```

其中 `run_summary.csv` 是细粒度运行级结果，`global_summary.csv` 只作为全局参考，不作为模型对比主表。

当前合并指标采用计数合并方式：

```text
在同一分组内先累计 TP / Partial / FN / FP 等原始计数；
再基于累计计数计算 precision、recall、fp_rate、evidence_failure_rate 等比例。
```

当前不是先计算每次 repetition 的指标再取平均值。

如果人工抽查后修改了某个 `scoring_reviewed_scope_<input_scope>/`：

```text
1. 重新运行 aggregate_scores.py 更新该 scope 的 run_summary.csv；
2. 重新运行 merge_reviewed_scopes.py 更新 scoring_reviewed_all/。
```
