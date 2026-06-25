# Any-hit@3 Evaluation Workflow

本文档记录 `any-hit@3` 评估流程。该流程用于评估模型在同一输入重复运行 3 次时，是否至少一次能够发现某个 GT case。

## 1. 评估含义

`any-hit@3` 的含义是：

```text
对同一模型、同一 input scope、同一 GT case，
只要 3 次 repetition 中任意一次被 TP finding 命中，
该 GT case 就算被模型发现。
```

该流程回答的问题是：

```text
如果允许模型对同一输入运行 3 次，它是否至少有一次能发现真实漏洞？
```

该流程不是评估单次运行平均表现，而是评估多次采样后的潜在发现能力。

## 2. 输入

该流程与 `single-run mean` 共用两张基础表。

### 2.1 GT case 表

全数据集一张表，一行一个真实漏洞 case。

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

人工评分方式与 `single-run mean` 相同。

步骤：

```text
1. 逐条查看模型输出 finding。
2. 对照 GT case 表，判断 finding 是否命中某个 GT case。
3. 命中则填写 matched_case_id，并标为 TP。
4. 无法匹配 GT case 则标为 FP。
5. 重复报告同一 GT case 的后续 finding 标为 Duplicate。
6. 无法稳定判断的 finding 标为 Unscorable。
7. 对 TP/FP finding 评估 evidence_quality。
```

## 4. Any-hit@3 case 命中计算

对某一个模型，按以下键分组：

```text
model_family
method_name
input_scope
case_id
```

在每个分组内查看 3 次 repetition 的 finding 匹配结果。

规则：

```text
如果任意 repetition 中存在 TP finding 命中该 case -> TP case
否则 -> FN case
```

也就是说：

```text
TP_cases = 3 次重复中至少一次被命中的 GT case 数
FN_cases = 3 次重复中一次也没有被命中的 GT case 数
```

## 5. Any-hit@3 finding 计数

为了计算 Precision 和证据指标，需要确定纳入 any-hit@3 口径的 findings。

推荐规则：

```text
1. 对每个被命中的 GT case，选择一条代表性 TP finding。
2. 代表性 TP finding 优先选择 evidence_quality 最好的 finding。
3. 其余命中同一 GT case 的 finding 视为重复项，不进入主指标。
4. FP findings 按全部 scored FP finding 计入。
```

证据质量优先级：

```text
Sufficient > Insufficient > Unclear > Unsupported > Fabricated
```

如果存在多个同等级 TP finding，可以选择 review_notes 中记录最充分的一条作为代表性 TP finding。

## 6. 主指标公式

对每个模型计算以下 5 个指标：

```text
Precision = Representative_TP_findings / (Representative_TP_findings + FP_findings)
```

```text
Recall = TP_cases / (TP_cases + FN_cases)
```

```text
F1-score = 2 * Precision * Recall / (Precision + Recall)
```

```text
Evidence Sufficiency Rate =
Sufficient_Representative_TP_findings / Representative_TP_findings
```

```text
Fabricated / Unsupported Evidence Rate =
Fabricated_or_Unsupported_findings / Scored_findings
```

其中：

```text
Scored_findings = Representative_TP_findings + FP_findings
```

`Duplicate` 和 `Unscorable` 不进入主指标计算。

## 7. 输出文件

建议输出目录：

```text
evaluation_results/<method_name>/<model_family>/anyhit3/
```

输出文件：

```text
anyhit3_model_summary.csv
anyhit3_case_hits.csv
```

两张表的角色不同：

```text
anyhit3_case_hits.csv 是 case 级审计表。
anyhit3_model_summary.csv 是 any-hit@3 口径下的最终实验结果表。
```

### 7.1 anyhit3_model_summary.csv

一行对应：

```text
model_family + method_name
```

该表表示某个模型在 any-hit@3 口径下的最终结果。

如果论文最终选择 any-hit@3 口径，该表就是论文主结果表来源。

字段：

```text
model_family
method_name
num_gt_cases
tp_cases
fn_cases
representative_tp_findings
fp_findings
precision
recall
f1_score
evidence_sufficiency_rate
fabricated_unsupported_evidence_rate
```

### 7.2 anyhit3_case_hits.csv

一行对应：

```text
model_family + method_name + input_scope + case_id
```

该表用于审计每个 GT case 是否在 3 次运行中至少一次被命中。

它不是论文最终主表，但用于支撑 any-hit@3 的 Recall 和 FN case 统计。

字段：

```text
model_family
method_name
input_scope
benchmark_id
case_id
case_result
hit_repetitions
representative_finding_uid
representative_evidence_quality
notes
```

其中：

```text
case_result:
- TP
- FN
```

`hit_repetitions` 记录该 case 在哪些 repetition 中被命中，例如：

```text
1
2;3
1;2;3
```

如果没有命中则为空。

## 8. 使用边界

该流程适合作为补充评估候选，用于回答：

```text
模型是否偶尔具备发现该漏洞的能力？
```

如果 `single-run mean` 低但 `any-hit@3` 高，说明模型可能具备一定潜在发现能力，但输出不稳定。

如果两者都低，说明模型对该类 RTL 权限漏洞检测任务本身较难。

该流程会比 single-run mean 更乐观，因此如果作为论文主结果，需要明确说明其含义是多次采样后的至少一次命中能力，而不是单次运行表现。
