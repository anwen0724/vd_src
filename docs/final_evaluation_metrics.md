# Final Evaluation Metrics

本文档记录当前实验的最终评估指标口径。后续评分表、汇总脚本和论文结果展示应以本文档为准。

## 1. 评估对象

评估对象是模型在某个 RTL input scope 上输出的漏洞分析结果。

输入包括：

- 模型输出的 findings；
- 该 input scope 对应的 hidden GT cases；
- 人工对每条 finding 的匹配与证据质量判断。

评估目标是回答：

- 模型报告的漏洞发现是否能匹配真实 GT case；
- GT 中的真实漏洞是否被模型发现；
- 被报告的漏洞是否有足够、真实、可复核的 RTL 代码证据。

## 2. 最终主指标

最终主表只展示以下 5 个指标：

```text
1. Precision
2. Recall
3. F1-score
4. Evidence Sufficiency Rate
5. Fabricated / Unsupported Evidence Rate
```

`FP`、`FN`、`TP` 等只作为中间计数，用于计算上述指标，不作为最终主表中的独立指标展示。

## 3. 中间计数定义

### TP case

某个 GT case 被模型输出的至少一条有效 finding 命中。

一条 finding 是否命中某个 GT case，由人工对照 GT 描述、相关 RTL 文件、模块、信号、寄存器和代码证据判断。

### FN case

某个 GT case 没有被模型任何有效 finding 命中。

### FP finding

模型输出的一条 finding 无法匹配任何 GT case。

例如：

- 报告了不存在的漏洞；
- 只指出泛泛风险，但无法对应具体 GT case；
- 定位到无关模块、无关信号或无关代码路径；
- 基于错误理解得出漏洞结论。

### TP finding

模型输出的一条 finding 能够匹配某个 GT case。

如果多条 finding 重复报告同一个 GT case，只选择一条最能代表该 case 的 finding 作为 TP finding，其余重复项标为 Duplicate，不用于主指标计算。

### Scored finding

纳入主指标计算的 finding。

```text
Scored findings = TP findings + FP findings
```

`Duplicate` 和 `Unscorable` 不进入主指标分母。

## 4. Finding review 表

`finding review` 表不是原始 `final_answer.json`。

`final_answer.json` 保留为原始输出证据；评分时应先由脚本从其中抽取 findings，生成扁平化的 finding review 表。人工主要在 finding review 表中完成匹配与证据质量判断，必要时再回到 `final_answer.json` 查看完整上下文。

一行对应模型输出的一条 finding。

### 4.1 追踪字段

用于定位该 finding 来自哪个模型、方法、输入和原始输出文件：

```text
finding_uid
model_family
method_name
input_scope
repetition
run_id
final_answer_path
```

### 4.2 模型输出内容字段

这些字段从 `final_answer.json` 中自动抽取。

当前模型输出中，finding 主要由 `affected_locations`、`evidence`、`reasoning_summary`、`security_impact` 等结构组成，因此 review 表应贴合该结构，而不是使用过于抽象的字段。

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

字段含义：

- `finding_id`：模型输出中的 finding 编号；
- `model_reported_status`：模型自报状态，例如 `confirmed_finding`、`potential_warning`；
- `summary`：模型对该 finding 的简要描述；
- `vulnerability_category`：模型自报漏洞类别；
- `affected_locations`：从 `affected_locations[]` 压平成可读文本，包含文件、行号、模块、信号或寄存器；
- `claimed_files`：从 affected locations 和 evidence 中抽取的文件列表；
- `claimed_modules`：从 affected locations 和 evidence 中抽取的模块列表；
- `claimed_signals_or_registers`：从 affected locations 和 evidence 中抽取的信号或寄存器列表；
- `evidence_items`：从 `evidence[]` 压平成可读文本，包含 evidence file、line、module、object、evidence_type、description、supports_claim；
- `reasoning_summary`：模型给出的推理摘要；
- `security_impact`：模型声称的安全影响；
- `confidence`：模型输出的置信度；
- `uncertainty_or_missing_evidence`：模型自述的不确定性或缺失证据。

### 4.3 人工评分字段

人工需要填写：

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

不再使用 `Partial`。

原因是：只要 finding 能够匹配 GT case，就说明检测到了该漏洞；如果证据不充分或定位不精确，应通过 evidence quality 体现，而不是再引入 Partial 作为独立命中类型。

`duplicate_of_finding_uid` 只在 `detection_match = Duplicate` 时填写，用于指向被重复报告的代表性 TP finding。

```text
evidence_quality:
- Sufficient
- Insufficient
- Fabricated
- Unsupported
- Unclear
```

含义：

- `Sufficient`：finding 给出的文件、模块、信号、寄存器或代码片段足以支撑其漏洞判断；
- `Insufficient`：finding 可能命中了真实 case，但证据不完整、不具体或不足以复核；
- `Fabricated`：finding 引用了不存在的文件、模块、信号、代码行为或证据；
- `Unsupported`：finding 的结论缺少 RTL 代码证据支撑；
- `Unclear`：人工无法稳定判断证据质量。

## 5. Case-level 评分字段

每个 GT case 在一个评估单位中只有两种主要结果：

```text
case_result:
- TP
- FN
```

不再使用 `Partial`。

其中：

- `TP`：该 GT case 被至少一条 TP finding 命中；
- `FN`：该 GT case 没有被任何 TP finding 命中。

如果存在特殊情况无法判断，可以标为 `Unscorable`，但不进入最终主指标计算。

## 6. 指标计算公式

### Precision

```text
Precision = TP_findings / (TP_findings + FP_findings)
```

含义：模型报告的漏洞 findings 中，有多少是真实漏洞。

### Recall

```text
Recall = TP_cases / (TP_cases + FN_cases)
```

含义：GT 中真实存在的漏洞 case，有多少被模型发现。

### F1-score

```text
F1-score = 2 * Precision * Recall / (Precision + Recall)
```

当 Precision 和 Recall 分母为 0，或二者无法计算时，F1-score 为空。

### Evidence Sufficiency Rate

```text
Evidence Sufficiency Rate =
Sufficient_TP_findings / TP_findings
```

含义：模型正确命中的漏洞 findings 中，有多少给出了足够、可复核的 RTL 证据。

该指标只在 TP findings 上计算，因为 FP findings 本身不对应真实 GT case。

### Fabricated / Unsupported Evidence Rate

```text
Fabricated / Unsupported Evidence Rate =
Fabricated_or_Unsupported_findings / Scored_findings
```

其中：

```text
Fabricated_or_Unsupported_findings =
evidence_quality 为 Fabricated 或 Unsupported 的 TP/FP findings
```

含义：模型输出中有多少 finding 存在编造证据或无代码证据支撑的问题。

## 7. 重复运行处理

如果同一模型对同一 input scope 运行多次，最终论文主结果可以采用合并口径：

```text
同一 model + input_scope + case_id：
任一次命中 -> TP case
全部未命中 -> FN case
```

finding-level 的 Precision 和 evidence 指标仍基于纳入该合并评估口径的 TP/FP findings 计算。

per-run 结果可以保留，用于分析模型稳定性，但不作为最终主表的默认展示口径。

## 8. 最终主表建议格式

最终实验结果表取决于采用哪一种重复运行评估口径。

两种口径共用同一类人工评分来源表：

```text
finding_review.csv
```

但 `finding_review.csv` 属于具体方法和模型，应放在：

```text
evaluation_results/<method_name>/<model_family>/finding_review.csv
```

最终结果表也不能共用。

### 8.1 Single-run mean 口径

如果采用 `single-run mean`，最终主表为：

```text
single_run_model_summary.csv
```

一行对应：

```text
model_family + method_name
```

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

可以额外保留标准差字段，用于分析重复运行稳定性：

```text
precision_std
recall_std
f1_score_std
evidence_sufficiency_rate_std
fabricated_unsupported_evidence_rate_std
```

该表的数值来自：

```text
rep_1、rep_2、rep_3 分别计算完整数据集指标后取平均。
```

### 8.2 Any-hit@3 口径

如果采用 `any-hit@3`，最终主表为：

```text
anyhit3_model_summary.csv
```

一行对应：

```text
model_family + method_name
```

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

该表的数值来自：

```text
同一模型、同一 input scope、同一 GT case 的 3 次运行中，
任意一次命中就视为该 case 被命中。
```

`single_run_model_summary.csv` 和 `anyhit3_model_summary.csv` 含义不同，不能直接混用。

### 8.3 最终评估产物结构

最终评估产物按两条线组织：

```text
1. 指标评估：计算最终实验指标。
2. 失败分析：解释每次 run 为什么出错，服务方法设计优化。
```

建议目录结构：

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

其中：

- 顶层 `gt_cases.csv`：固定 GT case 表，一行一个真实漏洞 case，全方法和全模型共用；
- `<method_name>/<model_family>/finding_review.csv`：某个方法和模型的人工评分主表，一行一个模型输出 finding；
- `<method_name>/<model_family>/single_run/`：该方法和模型在 single-run mean 口径下的指标结果；
- `<method_name>/<model_family>/anyhit3/`：该方法和模型在 any-hit@3 口径下的指标结果；
- `<method_name>/<model_family>/failure_analysis/`：该方法和模型的每次 run 失败诊断结果，不参与主指标计算；
- `summary/`：跨方法、跨模型的最终汇总表，用于论文横向比较。

## 9. 评分原则

评分时遵守以下原则：

1. 先判断 finding 是否能匹配 GT case，再判断证据质量。
2. 命中 GT case 但证据不足，记为 `TP + Insufficient`，不是 Partial。
3. 无法匹配 GT case 的 finding 记为 FP。
4. 引用不存在的文件、模块、信号或代码行为，证据质量记为 Fabricated。
5. 只有结论、没有可复核 RTL 代码证据，证据质量记为 Unsupported。
6. 重复报告同一 GT case 的 finding 不重复增加 TP。
