# Evaluation Scripts Implementation Plan

本文档记录后续评估脚本的实现计划。

当前评估流程已重新确定，不再沿用旧的 `run × input_scope × case` 展开式 case-level 评分逻辑。

新的评估流程围绕两张核心表展开：

```text
gt_cases.csv
finding_review.csv
```

其中：

- `gt_cases.csv`：固定 GT case 表，一行一个真实漏洞 case，全方法和全模型共用；
- `finding_review.csv`：人工评分主表，一行一个模型输出 finding，按方法和模型分别维护。

## 1. 目标目录结构

最终评估结果目录：

```text
evaluation_results/
├─ gt_cases.csv
├─ baseline/
│  ├─ gpt_5_5/
│  │  ├─ finding_review.csv
│  │  ├─ single_run/
│  │  │  ├─ single_run_metrics.csv
│  │  │  └─ single_run_model_summary.csv
│  │  ├─ anyhit3/
│  │  │  ├─ anyhit3_case_hits.csv
│  │  │  └─ anyhit3_model_summary.csv
│  │  └─ failure_analysis/
│  │     ├─ run_failure_candidates.csv
│  │     ├─ run_failure_analysis.csv
│  │     └─ failure_mechanism_summary.csv
│  └─ deepseek_v4_pro/
│     └─ ...
├─ proposed/
│  ├─ gpt_5_5/
│  │  └─ ...
│  └─ deepseek_v4_pro/
│     └─ ...
└─ summary/
   ├─ single_run_all_models.csv
   ├─ anyhit3_all_models.csv
   └─ failure_mechanism_all_models.csv
```

## 2. 脚本清单

评估脚本建议放在：

```text
src/evaluation/
```

### 2.1 build_gt_cases.py

作用：

```text
从 src/datasets/benchmarks/ 下的 benchmark 数据中生成统一 GT case 表。
```

输入：

```text
src/datasets/benchmarks/hackatdac18/
src/datasets/benchmarks/hackatdac19/
src/datasets/benchmarks/hackatdac21/
```

输出：

```text
evaluation_results/gt_cases.csv
```

输出字段：

```text
case_id
benchmark_id
input_scope
case_description
gt_files
gt_modules
gt_signals_or_registers
gt_evidence_notes
```

注意：

```text
gt_cases.csv 是全方法、全模型共用的固定答案库。
该表不按 model、method、run 或 repetition 展开。
```

### 2.2 build_finding_review.py

作用：

```text
从 runs/ 中读取 final_answer.json，抽取模型输出 findings，生成扁平化 finding review 草稿表。
```

输入：

```text
runs/<method>/<batch_id>/models/<model_family>/<input_scope>/rep_<n>/final_answer.json
runs/<method>/<batch_id>/models/<model_family>/<input_scope>/rep_<n>/run_metadata.json
```

输出：

```text
evaluation_results/<method_name>/<model_family>/finding_review_draft.csv
```

人工确认和填写后，另存为：

```text
evaluation_results/<method_name>/<model_family>/finding_review.csv
```

自动抽取字段：

```text
finding_uid
model_family
method_name
input_scope
repetition
run_id
final_answer_path
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

人工评分字段：

```text
matched_case_id
detection_match
duplicate_of_finding_uid
evidence_quality
review_notes
```

取值约束：

```text
detection_match:
- TP
- FP
- Duplicate
- Unscorable

evidence_quality:
- Sufficient
- Insufficient
- Fabricated
- Unsupported
- Unclear
```

注意：

```text
不直接使用 final_answer.json 作为人工评分表。
final_answer.json 作为原始输出证据保留，finding_review.csv 是人工评分主表。
```

### 2.3 validate_finding_review.py

作用：

```text
校验人工填写后的 finding_review.csv 是否满足评分规则。
```

输入：

```text
evaluation_results/gt_cases.csv
evaluation_results/<method_name>/<model_family>/finding_review.csv
```

检查规则：

```text
finding_uid 不能重复；
matched_case_id 如果非空，必须存在于 gt_cases.csv；
detection_match 必须为 TP / FP / Duplicate / Unscorable；
evidence_quality 必须为 Sufficient / Insufficient / Fabricated / Unsupported / Unclear；
TP 必须填写 matched_case_id；
FP 不应填写 matched_case_id；
Duplicate 必须填写 duplicate_of_finding_uid；
Duplicate 不进入主指标计算；
Unscorable 不进入主指标计算；
不允许出现 Partial。
```

输出：

```text
控制台校验报告
```

如果存在错误，脚本应返回非零退出码。

### 2.4 compute_single_run_metrics.py

作用：

```text
按 single-run mean 口径计算指标。
```

输入：

```text
evaluation_results/gt_cases.csv
evaluation_results/<method_name>/<model_family>/finding_review.csv
```

输出：

```text
evaluation_results/<method_name>/<model_family>/single_run/single_run_metrics.csv
evaluation_results/<method_name>/<model_family>/single_run/single_run_model_summary.csv
```

计算逻辑：

```text
1. 对同一 method + model，按 repetition 分组。
2. 每个 repetition 应覆盖完整数据集。
3. 每个 repetition 单独计算 5 个指标。
4. 对多个 repetition 的指标取 mean。
```

每个 repetition 计算：

```text
Precision = TP_findings / (TP_findings + FP_findings)
Recall = TP_cases / (TP_cases + FN_cases)
F1-score = 2 * Precision * Recall / (Precision + Recall)
Evidence Sufficiency Rate = Sufficient_TP_findings / TP_findings
Fabricated / Unsupported Evidence Rate = Fabricated_or_Unsupported_findings / Scored_findings
```

其中：

```text
Scored_findings = TP_findings + FP_findings
```

`Duplicate` 和 `Unscorable` 不进入主指标计算。

### 2.5 compute_anyhit3_metrics.py

作用：

```text
按 any-hit@3 口径计算指标。
```

输入：

```text
evaluation_results/gt_cases.csv
evaluation_results/<method_name>/<model_family>/finding_review.csv
```

输出：

```text
evaluation_results/<method_name>/<model_family>/anyhit3/anyhit3_case_hits.csv
evaluation_results/<method_name>/<model_family>/anyhit3/anyhit3_model_summary.csv
```

计算逻辑：

```text
1. 对同一 method + model + input_scope + case_id 分组。
2. 如果 3 次 repetition 中任意一次存在 TP finding 命中该 case，则该 case 记为 TP。
3. 如果 3 次 repetition 都没有 TP finding 命中该 case，则该 case 记为 FN。
4. 对每个被命中的 case 选择一条代表性 TP finding。
5. 基于代表性 TP findings 和 FP findings 计算 5 个指标。
```

代表性 TP finding 选择规则：

```text
优先选择 evidence_quality 最好的 finding。
质量优先级：
Sufficient > Insufficient > Unclear > Unsupported > Fabricated
```

输出 `anyhit3_case_hits.csv` 用于审计每个 GT case 是否被命中。

输出 `anyhit3_model_summary.csv` 作为 any-hit@3 口径下的最终实验结果表。

### 2.6 build_failure_candidates.py

作用：

```text
从 gt_cases.csv 和 finding_review.csv 中自动生成每次 run 的失败候选事件。
```

输入：

```text
evaluation_results/gt_cases.csv
evaluation_results/<method_name>/<model_family>/finding_review.csv
runs/<method>/<batch_id>/
```

输出：

```text
evaluation_results/<method_name>/<model_family>/failure_analysis/run_failure_candidates.csv
```

候选事件包括：

```text
FP finding
FN case
TP finding with Insufficient evidence
TP/FP finding with Fabricated evidence
TP/FP finding with Unsupported evidence
Duplicate finding
Unscorable finding
```

输出字段：

```text
failure_uid
model_family
method_name
input_scope
repetition
run_id
failure_object_type
related_finding_uid
related_case_id
detection_match
evidence_quality
summary
final_answer_path
tool_trace_path
candidate_reason
```

该表不参与主指标计算，只用于失败分析。

### 2.7 init_failure_analysis.py

作用：

```text
从 run_failure_candidates.csv 初始化人工填写用的 run_failure_analysis.csv。
```

输入：

```text
evaluation_results/<method_name>/<model_family>/failure_analysis/run_failure_candidates.csv
```

输出：

```text
evaluation_results/<method_name>/<model_family>/failure_analysis/run_failure_analysis.csv
```

输出字段：

```text
failure_uid
model_family
method_name
input_scope
repetition
run_id
failure_object_type
related_finding_uid
related_case_id
detection_match
evidence_quality
summary
final_answer_path
tool_trace_path
candidate_reason
failure_manifestation
failure_mechanism
evidence_from_output
tool_trace_observation
likely_cause
method_implication
review_notes
```

注意：

```text
该脚本只初始化人工分析表，不自动判断 failure_mechanism。
如果 run_failure_analysis.csv 已存在，默认不覆盖，除非显式指定 overwrite。
```

### 2.8 summarize_failure_mechanisms.py

作用：

```text
基于人工填写后的 run_failure_analysis.csv 汇总失败机制分布。
```

输入：

```text
evaluation_results/<method_name>/<model_family>/failure_analysis/run_failure_analysis.csv
```

输出：

```text
evaluation_results/<method_name>/<model_family>/failure_analysis/failure_mechanism_summary.csv
```

输出字段：

```text
model_family
method_name
failure_mechanism
failure_count
affected_input_scopes
representative_failure_uids
method_implication_summary
```

### 2.9 collect_model_summaries.py

作用：

```text
跨方法、跨模型收集最终结果，生成论文横向比较表。
```

输入：

```text
evaluation_results/<method_name>/<model_family>/single_run/single_run_model_summary.csv
evaluation_results/<method_name>/<model_family>/anyhit3/anyhit3_model_summary.csv
evaluation_results/<method_name>/<model_family>/failure_analysis/failure_mechanism_summary.csv
```

输出：

```text
evaluation_results/summary/single_run_all_models.csv
evaluation_results/summary/anyhit3_all_models.csv
evaluation_results/summary/failure_mechanism_all_models.csv
```

## 3. 最小可运行闭环

第一阶段先实现主指标计算闭环：

```text
1. build_gt_cases.py
2. build_finding_review.py
3. 人工填写 finding_review.csv
4. validate_finding_review.py
5. compute_single_run_metrics.py
6. compute_anyhit3_metrics.py
```

完成后可以得到：

```text
single_run_model_summary.csv
anyhit3_model_summary.csv
```

这两张表分别对应两种评估口径的最终实验结果。

## 4. 完整实现顺序

推荐按以下顺序实现：

```text
1. build_gt_cases.py
2. build_finding_review.py
3. validate_finding_review.py
4. compute_single_run_metrics.py
5. compute_anyhit3_metrics.py
6. build_failure_candidates.py
7. init_failure_analysis.py
8. summarize_failure_mechanisms.py
9. collect_model_summaries.py
```

理由：

```text
先建立 GT 和 finding review 两张基础表；
再实现两套主指标计算；
最后实现失败分析和跨模型汇总。
```

## 5. 测试要求

每个脚本都应配套最小单元测试。

重点测试：

```text
1. final_answer.json 到 finding_review_draft.csv 的字段抽取是否正确；
2. TP / FP / Duplicate / Unscorable 校验规则是否生效；
3. single-run mean 指标计算是否正确；
4. any-hit@3 命中规则是否正确；
5. failure candidates 是否只列失败或可疑事件；
6. run_failure_analysis.csv 是否能从 candidates 正确初始化；
7. 跨模型 summary 是否正确收集各模型结果。
```

不应依赖真实完整实验结果才能测试脚本。

测试应使用小型 synthetic fixture。

## 6. 边界原则

实现时遵守以下原则：

```text
1. 不再恢复旧的 Partial 逻辑。
2. 不再生成 run × input_scope × case 的主评分表。
3. finding_review.csv 是人工评分主表。
4. gt_cases.csv 是固定答案库，不按模型和 run 展开。
5. single-run mean 和 any-hit@3 结果完全分开。
6. failure_analysis 不参与主指标计算。
7. 脚本重跑不得覆盖人工填写后的 finding_review.csv，除非显式指定 overwrite。
```
