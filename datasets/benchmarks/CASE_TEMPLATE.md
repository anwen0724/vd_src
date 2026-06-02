# H18-XXX Case GT

## 1. Case Identity

| 字段 | 内容 |
|---|---|
| `case_id` | H18-XXX |
| `bug_id` | H18-XXX |
| `official_description` | TODO: copy official Hack@DAC18 description. |
| `task_category` | TODO: category from `task_gt.csv`. |
| `gt_status` | `pending_rtl_review` / `rtl_confirmed` / `partial_evidence` / `excluded` |

## 2. Expected Bug Semantics

TODO: 用 1-3 句话描述 evaluator 用于语义匹配的标准漏洞含义。

写法要求：

- 不写为什么选择该 case；
- 不写研究意义；
- 不写 agent input 设计；
- 只回答“agent 发现什么才算发现了这个 case”。

## 3. Expected RTL Evidence

| Evidence | 文件 | 行号 | 关键对象 | 评分用途 |
|---|---|---:|---|---|
| TODO | `third_party/hackatdac18/...` | TODO | TODO | TODO |

Minimum sufficient evidence:

```text
TODO: put the minimum line/range and short code excerpt that can support a hit.
```

填写要求：

- `文件` 使用相对项目根目录的路径；
- `行号` 可以是单行或范围，例如 `324-325`；
- `关键对象` 写模块、信号、寄存器、宏、状态机或接口；
- `评分用途` 说明这条 evidence 用于判断什么；
- 如果尚未完成 RTL 复核，保留 TODO，并在 `gt_status` 标为 `pending_rtl_review`。

## 4. Hit Criteria

A finding is a hit if it satisfies all of the following:

- TODO: semantic condition.
- TODO: file/module location condition.
- TODO: signal/register/interface condition.
- TODO: required evidence condition.
- TODO: why the evidence supports the bug claim.

填写要求：

- 使用可执行判定条件；
- 不写模糊表述，例如“分析得比较好”；
- 条件应能用于判断 `true_positive`。

## 5. Partial Hit Criteria

A finding can be a partial hit if it satisfies one of the following:

- TODO: partial semantic match.
- TODO: incomplete location/evidence.
- TODO: useful warning but not enough for confirmed finding.

填写要求：

- 用于区分 `partial_hit` 和 `false_positive`；
- 明确哪些情况下 agent 找到了一部分真实问题，但证据不够完整。

## 6. False Positive / False Negative Rules

False positive examples:

- TODO: example of a finding that should not match this case.
- TODO: example of wrong signal/module/claim.

False negative condition:

- If the input scope contains TODO required files/evidence and the agent does not report this issue, mark H18-XXX as false negative.

填写要求：

- false positive 规则用于避免把泛泛风险误判为 hit；
- false negative 规则必须依赖 `input_scope_gt_map.csv` 中该 case 是否 `visible`；
- 如果当前 input scope 不包含 required evidence，则不能判定 false negative。

## 7. Evaluation Notes

- Optional semantic check: source = TODO; mediation = TODO; sink = TODO.
- Core evidence: TODO.
- Supporting evidence: TODO.
- GT basis: official Hack@DAC18 bug semantics plus TODO RTL evidence status.

填写要求：

- 本节只放少量辅助评分说明；
- 不放 priority selection 理由；
- 不放 agent input 构造计划；
- 不放长篇分析过程。
