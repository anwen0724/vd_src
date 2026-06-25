# Finding-GT Matching Principles

本文档规定如何人工对照模型输出 finding 与 GT case，并填写 `finding_review.csv`。

后续无论由人工评分，还是由 agent 辅助评分，都应按本文档执行。

## 0. 评估方式约束

最终评分必须是逐条 finding 的人工判断或人工等价复核，不能只依赖自动规则、关键词匹配、文件名匹配或脚本生成的候选结果。

允许使用脚本做初筛，例如：

```text
根据 input_scope 缩小候选 GT；
根据文件、模块、信号和文本相似度给出候选 matched_case_id；
标记可能的 Duplicate、FP 或证据失败项。
```

但这些结果只能作为评分草稿，不能直接作为论文实验的最终评分。

正式生成 `finding_review.csv` 前，必须逐条检查：

```text
1. finding 的漏洞语义是否能稳定对应具体 GT case；
2. 必要时打开 case_doc_path 查看完整 case 文档；
3. 必要时打开 final_answer.json 查看模型原始输出上下文；
4. 必要时打开 datasets/agent_inputs 下的源码核验证据是否真实存在；
5. evidence_quality 是否确实反映证据充分性，而不是只根据字段是否为空自动判断；
6. Duplicate 是否确实是重复报告，而不是独立命中另一个 case。
```

如果由 agent 代替人工评分，agent 也必须执行上述人工等价复核流程，并在 `review_notes` 中记录关键判断依据。

不得把“规则辅助 + 自动候选匹配”产生的结果直接当作最终评分结果。

## 1. 输入材料

评分时主要使用：

```text
evaluation_results/gt_cases.csv
evaluation_results/<method_name>/<model_family>/finding_review_draft.csv
runs/<method_name>/<batch_id>/models/<model_family>/<input_scope>/rep_<n>/final_answer.json
datasets/benchmarks/<benchmark_id>/cases/<case_id>.md
datasets/benchmarks/<benchmark_id>/evidence_gt.jsonl
datasets/agent_inputs/<benchmark_id>/<input_scope>/
```

其中：

- `gt_cases.csv` 是 GT case 入口表，用于快速定位候选 case；
- `finding_review_draft.csv` 是模型输出 finding 的扁平化表；
- `final_answer.json` 是模型原始输出；
- `case_doc_path` 指向完整 case 文档，是边界不清时的最终人工参照；
- `evidence_gt.jsonl` 和源码用于核查具体 RTL 证据。

## 2. 评分目标

评分不是判断模型是否“说了安全问题”，而是判断：

```text
模型输出的 finding 是否命中了某个具体 GT case；
模型给出的文件、模块、信号、代码证据是否足以支撑该漏洞结论；
模型是否输出了无法对应 GT 的误报、编造证据或不充分证据。
```

## 3. 基本匹配顺序

对每条 finding，按以下顺序判断。

### 3.1 先按 input_scope 缩小范围

只与同一个 `input_scope` 下的 GT cases 对照。

例如 finding 属于：

```text
input_scope = h18_debug_jtag_scope
```

则只对照 `gt_cases.csv` 中同一 `input_scope` 的 GT cases。

不要跨 input scope 匹配。

### 3.2 再判断漏洞语义是否对应

优先看 finding 中的：

```text
summary
vulnerability_category
reasoning_summary
security_impact
uncertainty_or_missing_evidence
```

对照 GT 中的：

```text
official_description
case_description
gt_evidence_notes
case_doc_path
```

判断重点是 finding 是否能合理指向某个具体 GT case，而不是关键词是否相同。

检测命中和证据质量分开判断：

```text
detection_match 判断模型是否发现了某个具体漏洞；
evidence_quality 判断模型证据是否充分、真实、可复核。
```

因此，finding 不需要完整复述 GT 的所有细节才算命中。只要它的漏洞描述、上下文、文件、模块或关键行为能够稳定落到某个具体 GT case，就可以标为 `TP`；证据不足的问题在 `evidence_quality` 中体现。

例如：

```text
泛泛报告 JTAG 未认证，可以作为 JTAG/password 相关 case 的候选匹配线索；
但不能因此自动命中所有 JTAG/password case。

如果它能根据上下文、文件、模块或关键行为合理指向 H18-028，则可以匹配 H18-028；
如果它无法稳定落到具体 case，只是宽泛安全判断，则不算 TP。
```

### 3.3 再检查代码证据是否落在相关范围

查看 finding 中的：

```text
claimed_files
claimed_modules
claimed_signals_or_registers
affected_locations
evidence_items
```

对照 GT 中的：

```text
gt_files
gt_modules
gt_signals_or_registers
```

判断原则：

```text
文件路径应使用 agent input 中的相对路径进行对照；
模块名可以辅助确认，但不要求字符串完全一致；
信号/寄存器名只作为辅助，不要求完全等值匹配；
最终以 finding 是否能合理指向具体 GT case 为 detection_match 判断依据；
证据是否充分、真实、可复核由 evidence_quality 判断。
```

## 4. detection_match 填写规则

`detection_match` 只能填写：

```text
TP
FP
Duplicate
Unscorable
```

不使用 `Partial`。

### 4.1 TP

当 finding 满足以下条件时，标为 `TP`：

```text
1. finding 的漏洞描述能合理对应某个具体 GT case；
2. finding 的上下文、文件、模块、信号、寄存器或关键行为中至少有一类能支持该对应关系；
3. 人工能够稳定判断它是在报告这个 case，而不是仅仅输出宽泛安全风险。
```

填写：

```text
matched_case_id = 对应 case_id
detection_match = TP
```

如果 finding 语义上命中 GT case，但证据不充分，不改成 FP，而是在 `evidence_quality` 中体现。

### 4.2 FP

当 finding 无法对应当前 input scope 下任何 GT case 时，标为 `FP`。

典型情况：

```text
报告了 GT 中不存在的漏洞；
只给出宽泛风险，且无法稳定对应任何具体 case；
定位到无关文件、模块、信号或代码路径；
基于错误理解得出漏洞结论；
把正常功能路径误判为权限漏洞。
```

填写：

```text
matched_case_id = 空
detection_match = FP
```

### 4.3 Duplicate

如果同一 run 中多条 findings 实际报告同一个 GT case，只保留最能代表该 case 的一条为 `TP`，其余标为 `Duplicate`。

填写：

```text
matched_case_id = 可保留对应 case_id，也可为空
detection_match = Duplicate
duplicate_of_finding_uid = 被保留为 TP 的 finding_uid
```

`Duplicate` 不进入主指标计算。

### 4.4 Unscorable

当 finding 无法可靠评分时，标为 `Unscorable`。

典型情况：

```text
输出格式损坏；
finding 内容过短或语义不完整；
字段缺失导致无法判断；
同一 finding 内部自相矛盾；
无法确认它是否真的在报告漏洞。
```

`Unscorable` 不进入主指标计算。

## 5. evidence_quality 填写规则

`evidence_quality` 只能填写：

```text
Sufficient
Insufficient
Fabricated
Unsupported
Unclear
```

### 5.1 Sufficient

证据足以支撑 finding 的漏洞结论。

要求：

```text
引用的文件、模块、信号或寄存器真实存在；
证据与漏洞语义直接相关；
解释能说明为什么该代码行为违反安全约束；
人工可基于 evidence_items、case_doc_path 和源码复核。
```

### 5.2 Insufficient

finding 可能命中正确 case，但证据不够充分。

典型情况：

```text
只定位到相关文件或模块，但没有给出关键代码路径；
只提到相关信号，但没有解释安全约束如何被破坏；
结论方向正确，但证据链不完整。
```

### 5.3 Fabricated

finding 引用了不存在的文件、模块、信号、寄存器、代码行或代码行为。

典型情况：

```text
声称存在某个 guard，但源码中没有；
引用不存在的模块名或信号名；
给出不存在的代码逻辑或行号。
```

### 5.4 Unsupported

引用的对象可能存在，但不能支撑 finding 的漏洞结论。

典型情况：

```text
文件和模块相关，但引用的代码只是普通功能逻辑；
证据存在，但不能证明权限约束缺失、错误传播或状态未保持；
把无关 reset、debug、CSR、APB 行为解释成漏洞。
```

### 5.5 Unclear

人工暂时无法可靠判断证据质量。

使用 `Unclear` 时，应在 `review_notes` 中说明缺少什么信息。

## 6. 相似 case 的处理原则

对于同一 input scope 中语义相近的 case，必须打开 `case_doc_path` 对照。

例如：

```text
H18-009：incorrect password checking logic
H18-010：incomplete password bit checking
H18-012：password check state not reset
```

它们可能共享文件和信号，但不是同一个漏洞。

判断时应看 finding 是否能稳定指向某个具体 case：

```text
只说 debug password 弱，不自动命中三者；
但如果结合文件、模块、信号或描述能合理指向其中一个 case，可以匹配该 case；
如果无法区分错误逻辑、不完整检查、成功后状态残留等不同语义，则只匹配最合理的一个 case，或标为 FP/Unscorable。
```

## 7. 一个 finding 是否可以命中多个 case

默认一个 finding 只匹配一个最主要的 GT case。

只有当 finding 能够分别合理指向多个 case 的独立漏洞语义时，才允许同一个 finding 被用于解释多个 case。

如果使用这种情况，必须在 `review_notes` 中说明原因。

实际填写时仍建议保守处理：

```text
优先匹配最具体、最稳定对应的 case；
其他相近 case 如果没有被合理覆盖，则仍可能是 FN。
```

## 8. review_notes 写法

`review_notes` 应记录人工判断依据，避免只写“对”或“错”。

建议格式：

```text
Matched <case_id> because ...
Evidence sufficient/insufficient because ...
Compared with <similar_case_id>, not matched because ...
```

示例：

```text
Matched H18-010 because the finding identifies incomplete password checking in adbg_tap_top.v and cites pass/bitindex/correct threshold logic. Not matched to H18-012 because it does not discuss residual passchk state after successful authentication.
```

## 9. 最终原则

评分应遵守：

```text
detection_match 与 evidence_quality 分开判断；
语义和上下文优先于关键词；
具体 case 优先于宽泛安全风险；
源码和 case_doc_path 优先于模型自信；
不因文件或模块相关就自动判定 TP，但也不因证据不完美就直接判为 FP。
```
