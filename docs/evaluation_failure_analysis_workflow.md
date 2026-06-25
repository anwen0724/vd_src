# Evaluation Failure Analysis Workflow

本文档记录每次 run 的失败分析流程。

该流程不用于计算论文主指标，而是用于解释模型为什么产生误报、漏报或证据不可靠输出，并据此支持后续方法设计优化。

## 1. 与主指标评估的关系

当前评估分为两条线：

```text
1. 指标评估：计算 Precision、Recall、F1-score、Evidence Sufficiency Rate、Fabricated / Unsupported Evidence Rate。
2. 失败分析：分析每次 run 中的典型失败原因，服务方法设计。
```

失败分析不改变主指标结果，也不参与主指标公式计算。

它使用主指标评估过程中已经得到的：

```text
gt_cases.csv
finding_review.csv
```

同时额外查看：

```text
final_answer.json
tool_trace.jsonl
run_metadata.json
RTL source files
```

## 2. 输入

### 2.1 GT case 表

```text
evaluation_results/gt_cases.csv
```

用途：

```text
确定每个 input scope 中有哪些真实漏洞 case；
判断某个 case 是否被当前 run 漏掉；
查看 case 的漏洞语义、关键文件、模块、信号和参考证据。
```

### 2.2 Finding review 表

```text
evaluation_results/<method_name>/<model_family>/finding_review.csv
```

用途：

```text
查看每条 finding 是否为 TP、FP、Duplicate 或 Unscorable；
查看 finding 匹配了哪个 GT case；
查看 evidence_quality；
定位需要进一步分析的失败 finding。
```

### 2.3 原始 run 产物

每个 run 的目录中至少包括：

```text
final_answer.json
tool_trace.jsonl
run_metadata.json
```

用途：

- `final_answer.json`：查看模型原始漏洞结论、证据、推理、置信度和不确定性表达；
- `tool_trace.jsonl`：查看模型实际读取、搜索过哪些文件，以及是否遗漏关键上下文；
- `run_metadata.json`：确认模型、方法、input scope、repetition 和运行配置。

## 3. 输出目录

失败分析结果单独放在：

```text
evaluation_results/<method_name>/<model_family>/failure_analysis/
```

建议输出：

```text
run_failure_candidates.csv
run_failure_analysis.csv
failure_mechanism_summary.csv
```

## 4. run_failure_candidates.csv

该表由脚本自动生成，用于列出每个 run 中值得人工分析的失败候选项。

它不是最终论文主表，也不参与指标计算。

一行对应一个失败候选事件。

候选事件来源包括：

```text
FP finding
FN case
TP finding with Insufficient evidence
TP/FP finding with Fabricated evidence
TP/FP finding with Unsupported evidence
Duplicate finding
Unscorable finding
```

建议字段：

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

字段含义：

- `failure_uid`：失败候选事件唯一编号；
- `failure_object_type`：失败对象类型；
- `related_finding_uid`：相关 finding；
- `related_case_id`：相关 GT case；
- `candidate_reason`：脚本生成该候选项的原因。

`failure_object_type` 取值：

```text
FP_finding
FN_case
Evidence_failure
Duplicate
Unscorable
```

## 5. run_failure_analysis.csv

该表由人工在 `run_failure_candidates.csv` 基础上填写，用于记录失败原因判断。

一行对应一个经过人工确认和分析的失败事件。

建议字段：

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
failure_manifestation
failure_mechanism
evidence_from_output
tool_trace_observation
likely_cause
method_implication
review_notes
```

字段含义：

- `failure_manifestation`：失败表象，例如漏报、误报、泛化结论、证据不足、证据编造；
- `failure_mechanism`：归入的问题机制；
- `evidence_from_output`：来自模型输出的关键证据或原文摘要；
- `tool_trace_observation`：从工具调用轨迹观察到的现象；
- `likely_cause`：人工判断的可能原因；
- `method_implication`：对后续方法设计的启示；
- `review_notes`：补充说明。

## 6. failure_mechanism 取值

失败机制应与当前论文方法设计中的问题机制保持一致。

当前建议使用：

```text
隐式权限语义识别困难
跨模块安全约束保持性推理不足
证据组织与结论校准不足
```

如果某个失败事件无法归入上述机制，可以暂时标为：

```text
Other
Unclear
```

但应在 `review_notes` 中说明原因，后续再决定是否扩展机制分类。

## 7. 每次 run 的分析流程

对某个 run，按以下步骤分析：

```text
1. 从 finding_review.csv 中筛选该 run 的所有 findings。
2. 查看 detection_match 和 evidence_quality，找出 FP、Duplicate、Unscorable 和证据失败 findings。
3. 根据 gt_cases.csv 查看该 input scope 对应的 GT cases。
4. 找出该 run 中未被任何 TP finding 命中的 GT cases，作为 FN cases。
5. 打开 final_answer.json，查看模型原始结论、证据、推理和不确定性表达。
6. 打开 tool_trace.jsonl，查看模型是否读取了关键文件、搜索了关键术语、遗漏了关键模块或路径。
7. 将典型失败事件记录到 run_failure_analysis.csv。
8. 根据失败事件归纳 failure_mechanism 和 method_implication。
```

## 8. 典型分析示例

### 8.1 FN case

现象：

```text
GT case H18-009 存在，但该 run 没有任何 TP finding 命中它。
```

分析：

```text
查看 tool_trace.jsonl，发现模型没有读取 password/passchk/correct/bitindex 相关逻辑。
查看 final_answer.json，发现模型只泛泛报告 JTAG debug 无认证，没有识别 password check 语义。
```

可能记录：

```text
failure_object_type = FN_case
failure_manifestation = missed GT case
failure_mechanism = 隐式权限语义识别困难
likely_cause = 未识别 password check 相关状态和计数逻辑的安全语义
method_implication = 方法需要提供权限语义知识与代码结构辅助，帮助定位 password/auth/debug 相关逻辑
```

### 8.2 FP finding

现象：

```text
模型报告某个 GPIO 写路径缺少权限检查，但 GT case 表中没有对应漏洞。
```

分析：

```text
查看 final_answer.json，发现模型只引用了写使能信号，没有说明该寄存器为何应受保护。
查看 RTL 和 GT，无法确认该路径对应真实权限漏洞。
```

可能记录：

```text
failure_object_type = FP_finding
failure_manifestation = unsupported vulnerability claim
failure_mechanism = 证据组织与结论校准不足
likely_cause = 将普通控制路径误判为权限保护缺失
method_implication = 方法需要要求 finding 绑定 subject-operation-object-guard-violation 证据链
```

### 8.3 Evidence failure

现象：

```text
finding 命中了某个 GT case，但引用的行号为空或证据描述不足。
```

分析：

```text
该 finding 可能说明了正确方向，但无法提供可复核 RTL 证据。
```

可能记录：

```text
failure_object_type = Evidence_failure
failure_manifestation = insufficient evidence
failure_mechanism = 证据组织与结论校准不足
likely_cause = 模型没有把结论绑定到具体代码位置和约束违背条件
method_implication = 方法需要增加 evidence chain construction 和 verdict gate
```

## 9. failure_mechanism_summary.csv

该表由脚本基于 `run_failure_analysis.csv` 汇总生成。

用途：

```text
观察不同模型、不同方法、不同 input scope 中的主要失败机制分布；
支持论文中的 failure analysis；
指导 proposed method 的模块设计和消融实验。
```

建议字段：

```text
model_family
method_name
failure_mechanism
failure_count
affected_input_scopes
representative_failure_uids
method_implication_summary
```

## 10. 使用边界

失败分析结果用于：

```text
方法设计动机
错误类型归纳
case study
消融实验解释
论文定性分析
```

失败分析结果不用于直接计算：

```text
Precision
Recall
F1-score
Evidence Sufficiency Rate
Fabricated / Unsupported Evidence Rate
```

如果发现某个 failure analysis 与 finding review 的基础评分冲突，应先修正 finding review，再重新生成候选失败项和汇总结果。
