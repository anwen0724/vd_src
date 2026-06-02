# Hack@DAC18 Benchmark Ground Truth

日期：2026-05-22

## 1. 目录目的

本目录用于维护 Hack@DAC18 在本课题中的 ground truth 数据。

当前阶段只初始化 **official ground truth**，即公开来源直接给出的事实信息。后续会在此基础上继续构建 task-level ground truth 和 evidence-level ground truth。

## 2. 当前文件

```text
data/benchmarks/hackatdac18/
├─ README.md
├─ official_gt.csv
├─ task_gt.csv
├─ eval_case_set.csv
├─ priority_cases.md
├─ evidence_gt.jsonl
├─ source_refs.md
└─ cases/
```

## 3. 文件说明

### `official_gt.csv`

记录公开来源中的 Hack@DAC18 bug 信息。

当前字段包括：

- `bug_id`
- `official_description`
- `inserted_or_native`
- `related_cve`
- `spv_detected`
- `fpv_detected`
- `manual_sim_detected`
- `module_count`
- `loc`
- `states`
- `source_reference`
- `notes`

字段含义：

| 字段 | 含义 |
|---|---|
| `bug_id` | 本项目为 Hack@DAC18 bug 统一分配的编号，格式为 `H18-001` 到 `H18-031`。对应官方 README 和 HardFails Table 1 中的 bug #1 到 #31。 |
| `official_description` | 官方公开 bug 描述，主要来自 Hack@DAC18 README。该字段只记录官方一句话描述，不加入本课题的解释。 |
| `inserted_or_native` | bug 来源类型，来自 HardFails Table 1。`Inserted` 表示研究团队有意注入的漏洞；`Native` 表示原 SoC 中已经存在、由参赛者发现的漏洞。 |
| `related_cve` | HardFails Table 1 中列出的相关 CVE。含义是该 bug 设计受到这些真实 CVE 或类似问题启发，不一定表示该开源 SoC 自身有对应 CVE。多个 CVE 用分号分隔。 |
| `spv_detected` | HardFails Table 1 中 `SPV` 列的检测结果。`SPV` 指 JasperGold Security Path Verification，用于检查安全路径或非法信息流。`yes` 表示该方法检测到了该 bug，`no` 表示未检测到。 |
| `fpv_detected` | HardFails Table 1 中 `FPV` 列的检测结果。`FPV` 指 JasperGold Formal Property Verification，即基于形式化属性的验证。`yes` 表示该方法检测到了该 bug，`no` 表示未检测到。 |
| `manual_sim_detected` | HardFails Table 1 中 `M&S` 列的检测结果。`M&S` 指 manual inspection and simulation，即参赛团队使用人工 RTL 检查和仿真等方式的检测结果。`yes` 表示该类方法检测到了该 bug，`no` 表示未检测到。 |
| `module_count` | HardFails Table 1 中的 `Modules` 列，表示尝试检测该 bug 需要涉及的模块数量。该数值来自论文，不是本课题重新统计。 |
| `loc` | HardFails Table 1 中的 `LOC` 列，表示尝试检测该 bug 相关模块的代码行数。该数值来自论文。 |
| `states` | HardFails Table 1 中的 `# States` 列，表示尝试检测该 bug 时相关逻辑状态空间规模。`N/A` 表示论文未给出适用数值。 |
| `source_reference` | 当前记录使用的来源。通常包括 Hack@DAC18 README 和 HardFails Table 1。 |
| `notes` | 记录抽取时的备注，例如 PDF 表格换行导致的 CVE 歧义、后续需要视觉复核的字段等。 |

该文件只记录官方公开事实，不记录本课题的权限相关判断、跨模块判断、RTL evidence 或 agent hit criteria。

### `source_refs.md`

记录本数据集使用的公开来源、访问日期和来源用途。

### `priority_cases.md`

记录第一批优先复核的 Hack@DAC18 cases。

该文件用于说明：

- 哪些 case 被选入第一批 priority cases；
- 选择这些 case 的理由；
- 每个 case 对应的初始权限语义类别；
- 后续可能组合成哪些 input scope；
- 哪些 case 暂作为 reserve cases。

该文件属于 hidden GT，不应放入 agent input。

### `evidence_gt.jsonl`

记录 evidence-level ground truth。

当前为初版，占位记录第一批 priority cases 的待复核证据入口。

字段含义：

| 字段 | 含义 |
|---|---|
| `case_id` | 本课题内部 case 编号。 |
| `bug_id` | 对应官方 bug 编号。 |
| `evidence_status` | evidence 状态。当前主要为 `pending_rtl_review`，表示尚未完成源码复核。 |
| `suspected_files` | 候选源码文件线索，不等于已确认 evidence。 |
| `suspected_modules` | 候选模块线索，不等于已确认 evidence。 |
| `expected_evidence_types` | 后续复核时需要寻找的 evidence 类型。 |
| `source_entity` | 预期访问来源或触发实体。 |
| `mediation_or_guard` | 预期权限调解点或保护条件。 |
| `sink_resource` | 预期被保护资源。 |
| `notes` | 复核备注。 |

后续完成 RTL evidence 复核后，应补充或更新：

- 确认文件；
- 模块名；
- 信号名；
- 行号；
- 代码 excerpt；
- source / mediation / sink trace；
- hit criteria 关联。

### `task_gt.csv`

记录本课题对 Hack@DAC18 bug 是否适合纳入“ SoC RTL 权限相关漏洞分析/检测”任务的描述级初步判断。

注意：

- 这是 task-level GT 的初版，不是最终 gold label；
- 当前主要迁移自历史描述级 mapping；
- 所有记录的 `label_status` 均为 `needs_review`；
- 后续必须通过 RTL evidence 复核后才能升级状态。

字段含义：

| 字段 | 含义 |
|---|---|
| `case_id` | 本课题内部 case 编号。当前与 `bug_id` 保持一致，格式为 `H18-001` 到 `H18-031`。 |
| `bug_id` | 对应 `official_gt.csv` 中的官方 bug 编号。 |
| `include_in_task` | 描述级判断该 bug 是否纳入当前任务候选。可取 `yes`、`no`、`borderline`。`yes` 表示候选纳入，`no` 表示暂不纳入，`borderline` 表示边界案例。 |
| `permission_related` | 描述级判断该 bug 是否与权限、特权、访问控制、debug authorization、保护资源等相关。可取 `yes`、`no`、`borderline`。 |
| `permission_category` | 描述级权限语义类别，例如 `debug_authorization`、`privilege/CSR`、`address_map/protected_resource` 等。该字段不是官方分类，也不是最终分类。 |
| `cross_module` | 描述级判断是否涉及跨模块、inter-IP 或跨控制域关系。可取 `yes`、`no`、`borderline`。 |
| `task_relevance_reason` | 为什么该 bug 可能与当前任务相关的简短说明。该说明是本课题描述级判断，不是官方文本。 |
| `label_status` | 标签状态。当前均为 `needs_review`，表示需要 RTL evidence 复核。后续可升级为 `rtl_confirmed`、`excluded`、`needs_more_evidence` 等。 |
| `review_notes` | 复核备注。当前主要说明该记录来自描述级 mapping，后续需要 RTL evidence。 |

### `eval_case_set.csv`

记录 Hack@DAC18 当前可用于后续实验评分的 case 集合。

该文件只包含 `task_gt.csv` 中已经完成 RTL evidence 复核、且 `label_status = rtl_confirmed` 的正例 case。它用于后续将 agent output 与 GT 比对时确定可评分正例，不替代 `official_gt.csv` 或 `task_gt.csv`。

当前 H18 evaluation subset 包含 12 个 confirmed positive cases：

- `H18-001`
- `H18-004`
- `H18-005`
- `H18-006`
- `H18-008`
- `H18-009`
- `H18-010`
- `H18-012`
- `H18-017`
- `H18-025`
- `H18-027`
- `H18-028`

`H18-031` 保留在官方和任务候选记录中，但当前状态为 `source_unconfirmed`，不进入本文件，也不作为实验评分正例。

### `cases/`

维护 case-level 人工复核文件，例如 `H18-004.md`。

当前已完成 case-level 复核的文件包括：

- `H18-001.md`
- `H18-004.md`
- `H18-005.md`
- `H18-006.md`
- `H18-008.md`
- `H18-009.md`
- `H18-010.md`
- `H18-012.md`
- `H18-017.md`
- `H18-025.md`
- `H18-027.md`
- `H18-028.md`
- `H18-031.md`

这些文件记录每个 case 的官方描述、预期漏洞语义、RTL evidence、hit criteria、partial hit criteria 和 FP/FN 判定规则。

它们属于 hidden GT，不应放入 agent input。

后续新增或更新 case 文档时，应优先按照 `data/benchmarks/CASE_TEMPLATE.md` 的 7 节结构编写。

## 4. 后续计划

后续应继续补充：

- `task_gt.csv`：本课题任务级标签；
- `evidence_gt.jsonl`：RTL evidence 索引；
- `cases/H18-xxx.md`：逐 case 人工复核说明；
- 本地源码镜像路径和 commit hash。

## 5. 数据隔离原则

baseline agent 运行时不应读取本目录下的 GT 文件。

后续实验中应区分：

- agent input：RTL 源码、任务说明、允许工具；
- evaluator input：agent 输出、official/task/evidence GT、人工复核记录。
