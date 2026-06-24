# Hack@DAC18 Benchmark Data

本目录保存 Hack@DAC18 在本课题中的 evaluator-side benchmark 资产。

这些文件用于后续对模型/agent 输出进行人工或脚本辅助评估，不应复制到 agent 可见输入目录。

## 当前状态

- `official_gt.csv`：31 个官方公开 bug 描述，来源包括 Hack@DAC18 README 和 HardFails。
- `task_gt.csv`：31 个 case 的任务相关性标注与源码复核状态。
- `eval_case_set.csv`：当前可用于评分的 12 个 `rtl_confirmed` case。
- `cases/`：12 个评分 case 的 case-level GT 文档。
- `evidence_gt.jsonl`：12 个评分 case 的 evidence-level GT，使用当前统一 schema。
- `non_scoring_cases/`：暂不参与评分的候选 case。
- `non_scoring_evidence_gt.jsonl`：暂不参与评分的候选 evidence 记录。
- `source_refs.md`：公开来源、源码镜像和引用依据。
- `priority_cases.md`：早期 priority case 选择记录，仅作历史参考。

## 当前评分集

当前 Hack@DAC18 评分集包含 12 个 case：

- H18-001
- H18-004
- H18-005
- H18-006
- H18-008
- H18-009
- H18-010
- H18-012
- H18-017
- H18-025
- H18-027
- H18-028

评分入口以 `eval_case_set.csv` 为准。

## 非评分候选

`H18-031` 已移入：

```text
data/benchmarks/hackatdac18/non_scoring_cases/H18-031.md
```

原因：

- 官方描述指向 GPIO 读写 instruction/data cache；
- 当前源码复核只定位到 GPIO APB 连接和 cache 相关上下文；
- 尚未确认具体 GPIO-to-cache read/write RTL 路径。

因此，H18-031 当前不进入 `eval_case_set.csv`，不参与 baseline 评分。

## 使用原则

- agent 不应读取本目录。
- 评分时使用 `eval_case_set.csv`、`cases/*.md` 和 `evidence_gt.jsonl` 作为隐藏事实参照。
- 如果后续要启用 `non_scoring_cases/` 中的 case，必须先补齐 RTL evidence，更新 `task_gt.csv`、`eval_case_set.csv`、`evidence_gt.jsonl` 和全局 inventory。
