# Single-run Mean Evaluation Workflow

本文档记录 `single-run mean` 评估流程。该流程用于评估模型单次执行 RTL 权限漏洞检测任务的平均表现。

## 1. 评估含义

`single-run mean` 的含义是：

```text
每次 repetition 都视为一次完整、独立的漏洞检测实验。
先分别计算每次 repetition 的指标，再对多次 repetition 的指标取平均。
```

该流程回答的问题是：

```text
如果工程师只运行一次该模型/方法，它平均能达到怎样的检测效果和证据可信性？
```

## 2. 输入

该流程需要两张基础表。

### 2.1 GT case 表

全数据集一张表，一行一个真实漏洞 case。

该表不是按模型、run 或 input scope 展开。

基本字段包括：

```text
case_id
benchmark_id
input_scope
official_description
case_description
gt_files
gt_modules
gt_signals_or_registers
gt_evidence_notes
case_doc_path
```

其中 `gt_files` 使用 agent input 中可见的相对路径，不保留原始源码镜像中的 `third_party/<benchmark_id>/` 前缀。

### 2.2 Finding review 表

从 `runs/` 中抽取所有模型输出 findings 后生成，一行对应模型输出的一条 finding。

该表不是直接使用原始 `final_answer.json`。`final_answer.json` 保留为完整原始输出；finding review 表用于人工评分，应由脚本从 `final_answer.json` 中抽取并扁平化生成。

追踪字段包括：

```text
finding_uid
model_family
method_name
input_scope
repetition
run_id
final_answer_path
```

模型输出内容字段包括：

```text
finding_id
model_reported_status
summary
vulnerability_category
affected_locations
claimed_files
claimed_modules
claimed_signals_or_registers
evidence_items
reasoning_summary
security_impact
confidence
uncertainty_or_missing_evidence
```

这些字段来自当前 `final_answer.json` 中的：

```text
status
summary
vulnerability_category
affected_locations[]
evidence[]
reasoning_summary
security_impact
confidence
uncertainty_or_missing_evidence
```

其中 `affected_locations` 和 `evidence_items` 应压平成可读文本，方便人工快速判断，而不是要求人工逐条打开原始 JSON。

人工评分字段包括：

```text
matched_case_id
detection_match
duplicate_of_finding_uid
evidence_quality
review_notes
```

其中：

```text
detection_match:
- TP
- FP
- Duplicate
- Unscorable
```

`duplicate_of_finding_uid` 只在 `detection_match = Duplicate` 时填写，用于指向被重复报告的代表性 TP finding。

```text
evidence_quality:
- Sufficient
- Insufficient
- Fabricated
- Unsupported
- Unclear
```

不使用 `Partial`。

## 3. 人工评分流程

人工只需要评分 finding review 表。

步骤：

```text
1. 逐条查看模型输出 finding。
2. 对照 GT case 表，判断该 finding 是否命中某个 GT case。
3. 如果命中，填写 matched_case_id，并将 detection_match 标为 TP。
4. 如果无法匹配任何 GT case，将 detection_match 标为 FP。
5. 如果重复报告同一个 GT case，将后续重复 finding 标为 Duplicate。
6. 如果输出无法稳定判断，将 detection_match 标为 Unscorable。
7. 对 TP/FP finding 评估 evidence_quality。
8. 在 review_notes 中记录关键判断依据。
```

## 4. 每次 repetition 的指标计算

对某一个模型，按 `repetition` 分组。

例如一个模型有 3 次完整运行：

```text
repetition = 1
repetition = 2
repetition = 3
```

每个 repetition 应覆盖全部 input scopes，因此每个 repetition 对应一次完整数据集评估。

对每个 repetition，计算以下中间计数：

```text
TP_findings
FP_findings
TP_cases
FN_cases
Sufficient_TP_findings
Fabricated_or_Unsupported_findings
Scored_findings
```

其中：

```text
Scored_findings = TP_findings + FP_findings
```

`Duplicate` 和 `Unscorable` 不进入主指标计算。

### 4.1 TP cases

在该 repetition 中，被至少一个 TP finding 命中的 GT case 数。

### 4.2 FN cases

在该 repetition 中，没有被任何 TP finding 命中的 GT case 数。

分母应为该 repetition 实际覆盖的 GT cases。

如果模型完整跑完全部 input scopes，则该分母为全数据集 GT case 数。

## 5. 主指标公式

每个 repetition 单独计算以下 5 个指标：

```text
Precision = TP_findings / (TP_findings + FP_findings)
```

```text
Recall = TP_cases / (TP_cases + FN_cases)
```

```text
F1-score = 2 * Precision * Recall / (Precision + Recall)
```

```text
Evidence Sufficiency Rate =
Sufficient_TP_findings / TP_findings
```

```text
Fabricated / Unsupported Evidence Rate =
Fabricated_or_Unsupported_findings / Scored_findings
```

## 6. 多次 repetition 汇总

对同一模型的多个 repetition 指标取平均：

```text
Precision_mean
Recall_mean
F1_score_mean
Evidence_Sufficiency_Rate_mean
Fabricated_Unsupported_Evidence_Rate_mean
```

可以额外保留标准差：

```text
Precision_std
Recall_std
F1_score_std
Evidence_Sufficiency_Rate_std
Fabricated_Unsupported_Evidence_Rate_std
```

标准差不是最终主指标，但可以用于分析模型输出稳定性。

## 7. 输出文件

建议输出目录：

```text
evaluation_results/<method_name>/<model_family>/single_run/
```

输出文件：

```text
single_run_metrics.csv
single_run_model_summary.csv
```

两张表的角色不同：

```text
single_run_metrics.csv 是 repetition 级中间结果表。
single_run_model_summary.csv 是 single-run mean 口径下的最终实验结果表。
```

### 7.1 single_run_metrics.csv

一行对应：

```text
model_family + method_name + repetition
```

该表表示某个模型在某次完整 repetition 上的检测效果。

如果每个模型对 15 个 input scopes 都运行 3 次，那么：

```text
一个模型会有 3 行 single_run_metrics 结果。
```

字段：

```text
model_family
method_name
repetition
num_gt_cases
tp_cases
fn_cases
tp_findings
fp_findings
precision
recall
f1_score
evidence_sufficiency_rate
fabricated_unsupported_evidence_rate
```

### 7.2 single_run_model_summary.csv

一行对应：

```text
model_family + method_name
```

该表表示某个模型的最终 single-run mean 结果。

它由 `single_run_metrics.csv` 中同一模型的多个 repetition 指标取平均得到。

字段：

```text
model_family
method_name
precision_mean
recall_mean
f1_score_mean
evidence_sufficiency_rate_mean
fabricated_unsupported_evidence_rate_mean
```

可选字段：

```text
precision_std
recall_std
f1_score_std
evidence_sufficiency_rate_std
fabricated_unsupported_evidence_rate_std
```

如果论文最终选择 single-run mean 口径，该表就是论文主结果表来源。

## 8. 使用边界

该流程适合作为论文主结果候选，因为它评估的是模型单次运行的平均表现。

该流程不把 3 次运行合并为一次检测机会，因此不会因为重复运行给模型额外命中机会。

如果某个模型没有完整跑完所有 input scopes，则该模型的 Recall 分母必须只使用它实际覆盖的 GT cases，不能直接使用全数据集 GT case 数。
