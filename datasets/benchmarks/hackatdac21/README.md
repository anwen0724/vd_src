# Hack@DAC21 Benchmark Data

本目录保存 Hack@DAC21 在本课题中的 evaluator-side benchmark 资产。

这些文件用于后续对模型/agent 输出进行人工或脚本辅助评估，不应复制到 agent 可见输入目录。

## 当前状态

- `official_gt.csv`：99 个官方公开 bug 描述，来源为 Hack@DAC21 GitHub README bug list。
- `task_gt.csv`：99 个 case 的任务相关性标注与源码复核状态。
- `batch_plan.md`：当前批次选择和 deferred case 记录。
- `eval_case_set.csv`：当前可用于评分的 22 个 `rtl_confirmed` case。
- `cases/`：22 个评分 case 的 case-level GT 文档。
- `evidence_gt.jsonl`：22 个评分 case 的 evidence-level GT，已转换为当前统一 schema。
- `source_refs.md`：公开来源、源码镜像和 seed mapping 记录。

## 当前评分集

当前 Hack@DAC21 评分集包含 22 个 case：

- H21-005
- H21-013
- H21-031
- H21-035
- H21-036
- H21-039
- H21-042
- H21-043
- H21-047
- H21-048
- H21-049
- H21-059
- H21-060
- H21-073
- H21-074
- H21-075
- H21-078
- H21-079
- H21-080
- H21-097
- H21-098
- H21-099

评分入口以 `eval_case_set.csv` 为准。

## 使用原则

- agent 不应读取本目录。
- 评分时使用 `eval_case_set.csv`、`cases/*.md` 和 `evidence_gt.jsonl` 作为隐藏事实参照。
- `task_gt.csv` 中尚未 `rtl_confirmed` 的 case 不能直接进入评分集。

## 2026-06-22 Expansion Update

Current scored eval cases after expansion: 47.

