# Hack@DAC19 Benchmark Data

本目录保存 Hack@DAC19 在本课题中的 evaluator-side benchmark 资产。

这些文件用于后续对模型/agent 输出进行人工或脚本辅助评估，不应复制到 agent 可见输入目录。

## 当前状态

- `official_gt.csv`：66 个官方公开 bug 描述，来源为 Hack The Silicon DAC19 bug list。
- `task_gt.csv`：66 个 case 的任务相关性标注与源码复核状态。
- `batch_plan.md`：当前批次选择和 deferred case 记录。
- `eval_case_set.csv`：当前可用于评分的 21 个 `rtl_confirmed` case。
- `cases/`：21 个评分 case 的 case-level GT 文档。
- `evidence_gt.jsonl`：21 个评分 case 的 evidence-level GT，使用当前统一 schema。
- `source_refs.md`：公开来源、源码镜像和 seed mapping 记录。

## 当前评分集

当前 Hack@DAC19 评分集包含 21 个 case：

- H19-001
- H19-005
- H19-009
- H19-010
- H19-011
- H19-014
- H19-015
- H19-017
- H19-020
- H19-024
- H19-025
- H19-041
- H19-045
- H19-047
- H19-048
- H19-049
- H19-050
- H19-051
- H19-054
- H19-056
- H19-058

评分入口以 `eval_case_set.csv` 为准。

## 使用原则

- agent 不应读取本目录。
- 评分时使用 `eval_case_set.csv`、`cases/*.md` 和 `evidence_gt.jsonl` 作为隐藏事实参照。
- `task_gt.csv` 中尚未 `rtl_confirmed` 的 case 不能直接进入评分集。

## 2026-06-22 Expansion Update

Current scored eval cases after expansion: 26.

