# RQ3 Ours Cost Analysis

本目录只分析 ours 方法的执行开销，不包含 baseline。

## 数据范围

- input scope 数量：15
- permission context 总数：1049
- source snippet 总数：10516

## 模型运行汇总

| model | scopes | chains | runtime | input tokens | output tokens | total tokens |
|---|---:|---:|---:|---:|---:|---:|
| claude_sonnet_4-6 | 15 | 1049 | 25005.2s (6.95h) | 24666476 | 1127453 | 25793929 |
| gemini_3.1_pro_preview | 15 | 1049 | 30361.4s (8.43h) | 25076922 | 3416449 | 28493371 |

## 关键相关性

| level | model | analysis | n | Pearson | Spearman |
|---|---|---|---:|---:|---:|
| scope | all | repo scale vs generated context count | 15 | 0.538 | 0.625 |
| scope | all | context count vs scope runtime | 30 | 0.906 | 0.853 |
| scope | all | source snippets vs scope runtime | 30 | 0.905 | 0.853 |
| scope | all | context count vs scope total tokens | 30 | 0.948 | 0.948 |
| scope | all | source snippets vs scope total tokens | 30 | 0.959 | 0.897 |
| scope | claude_sonnet_4-6 | repo scale vs generated context count | 15 | 0.538 | 0.625 |
| scope | claude_sonnet_4-6 | context count vs scope runtime | 15 | 0.969 | 0.893 |
| scope | claude_sonnet_4-6 | source snippets vs scope runtime | 15 | 0.948 | 0.907 |
| scope | claude_sonnet_4-6 | context count vs scope total tokens | 15 | 0.954 | 0.968 |
| scope | claude_sonnet_4-6 | source snippets vs scope total tokens | 15 | 0.965 | 0.907 |
| scope | gemini_3.1_pro_preview | repo scale vs generated context count | 15 | 0.538 | 0.625 |
| scope | gemini_3.1_pro_preview | context count vs scope runtime | 15 | 0.906 | 0.814 |
| scope | gemini_3.1_pro_preview | source snippets vs scope runtime | 15 | 0.921 | 0.814 |
| scope | gemini_3.1_pro_preview | context count vs scope total tokens | 15 | 0.954 | 0.971 |
| scope | gemini_3.1_pro_preview | source snippets vs scope total tokens | 15 | 0.966 | 0.911 |
| chain | all | chain input tokens vs chain runtime | 2098 | 0.366 | 0.482 |
| chain | claude_sonnet_4-6 | chain input tokens vs chain runtime | 1049 | 0.562 | 0.540 |
| chain | gemini_3.1_pro_preview | chain input tokens vs chain runtime | 1049 | 0.334 | 0.459 |

## 生成文件

- `data/`：scope-level、chain-level 和相关性 CSV。
- `figures/`：repo scale/context count/runtime/token 关系散点图。

## 解释口径

repo scale 与 context count 的关系用于观察模块1/2是否把仓库规模直接转化为 LLM 输入规模；context count、snippet count 与 runtime/tokens 的关系用于解释模块3的主要开销来源。
当前结果显示，模块3运行时间和 token 数量与 context 数量、source snippet 数量高度相关，因此 RQ3 更适合表述为：执行开销主要由被选中的权限链路上下文规模驱动，而不是由原始 repo 总规模单独决定。
