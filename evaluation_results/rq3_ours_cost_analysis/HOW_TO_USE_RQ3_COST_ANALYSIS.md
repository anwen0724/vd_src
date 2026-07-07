# RQ3 执行开销分析使用说明

本文档记录 `rq3_ours_cost_analysis` 目录下图表和数据的用途，避免后续写论文时不清楚这些结果应该如何解释和使用。

## 1. 分析目标

本次分析只针对 ours 方法，不包含 baseline。

RQ3 的问题是：

```text
我们方法的执行开销由哪些因素决定？
```

这里的重点不是 Precision、Recall、F1，而是解释：

- 方法运行起来主要慢在哪里；
- 开销主要随什么因素增长；
- 原始 RTL 仓库规模是否直接决定 LLM 开销；
- 生成的 permission context 数量和源码片段规模是否才是主要成本来源。

本次分析的核心结论是：

```text
ours 方法的执行开销主要由生成出的权限链路 context 数量及其源码片段规模决定，
而不是由原始 RTL repo 图规模单独决定。
```

这个结论与 VerilogLAVD 中“执行时间主要由检测逻辑复杂度决定，而不是由无关代码规模决定”的分析思路类似，但我们这里对应的是 permission context 数量和内容规模。

## 2. 结果目录结构

结果目录：

```text
src/evaluation_results/rq3_ours_cost_analysis/
```

主要内容：

```text
rq3_ours_cost_analysis/
  README.md
  HOW_TO_USE_RQ3_COST_ANALYSIS.md
  data/
    scope_level_ours_claude_sonnet_4-6.csv
    scope_level_ours_gemini_3.1_pro_preview.csv
    scope_level_ours_combined.csv
    chain_level_ours_claude_sonnet_4-6.csv
    chain_level_ours_gemini_3.1_pro_preview.csv
    chain_level_ours_combined.csv
    correlation_summary.csv
  figures/
    repo_scale_vs_context_count.png
    claude_context_count_vs_runtime.png
    claude_context_count_vs_total_tokens.png
    claude_snippet_count_vs_runtime.png
    claude_chain_input_tokens_vs_runtime.png
    gemini_context_count_vs_runtime.png
    gemini_context_count_vs_total_tokens.png
    gemini_snippet_count_vs_runtime.png
    gemini_chain_input_tokens_vs_runtime.png
    combined_context_count_vs_runtime.png
    combined_snippet_count_vs_runtime.png
    combined_chain_input_tokens_vs_runtime.png
```

可复现脚本：

```text
src/scripts/evaluation/12_analyze_rq3_ours_cost.py
```

重新生成命令：

```powershell
cd C:\Users\anwen\Desktop\vulnerability_detection\src
python scripts\evaluation\12_analyze_rq3_ours_cost.py
```

## 3. 数据范围

本次分析使用的是 ours 方法当前完整运行结果：

- input scope 数量：15；
- permission context 总数：1049；
- 每个模型分别分析这 1049 条 context；
- Claude 和 Gemini 使用同一批 context 输入；
- chain-level 总记录数为 2098，即 `1049 * 2`。

模型运行汇总：

| model | scopes | chains | runtime | input tokens | output tokens | total tokens |
|---|---:|---:|---:|---:|---:|---:|
| Claude | 15 | 1049 | 25005.2s, 约 6.95h | 24666476 | 1127453 | 25793929 |
| Gemini | 15 | 1049 | 30361.4s, 约 8.43h | 25076922 | 3416449 | 28493371 |

## 4. CSV 文件怎么用

### 4.1 scope-level CSV

文件：

```text
data/scope_level_ours_claude_sonnet_4-6.csv
data/scope_level_ours_gemini_3.1_pro_preview.csv
data/scope_level_ours_combined.csv
```

每一行表示一个 input scope 在某个模型下的总体开销。

适合回答：

- 每个 repo/scope 生成了多少 context；
- 每个 repo/scope 有多少源码片段；
- 每个 repo/scope 在 Claude/Gemini 上耗时多少；
- 每个 repo/scope 消耗多少 input/output/total tokens；
- context 数量和总耗时、总 token 是否相关。

重要字段：

| 字段 | 含义 |
|---|---|
| `scope_id` | 输入范围 ID |
| `benchmark` | Hack@DAC18/19/21 |
| `rtl_files` | 图中涉及的 RTL 文件数量 |
| `graph_loc_approx` | 根据图中源码位置估算的 RTL 行数 |
| `graph_nodes` | 模块1 repo 图节点数 |
| `graph_edges` | 模块1 repo 图边数 |
| `graph_scale_nodes_edges` | `graph_nodes + graph_edges` |
| `context_count` | 模块2/3最终使用的 permission context 数量 |
| `source_snippet_count` | context 中携带的源码片段总数 |
| `runtime_seconds` | 该 scope 的模块3总耗时 |
| `llm_call_count` | LLM 调用次数，通常等于 context 数 |
| `input_tokens` | 输入 token 总数 |
| `output_tokens` | 输出 token 总数 |
| `total_tokens` | 总 token 数 |

### 4.2 chain-level CSV

文件：

```text
data/chain_level_ours_claude_sonnet_4-6.csv
data/chain_level_ours_gemini_3.1_pro_preview.csv
data/chain_level_ours_combined.csv
```

每一行表示一条 permission context 的一次 LLM 分析。

适合回答：

- 单条 context 越大，单次 LLM 调用是否越慢；
- 单条 context 的 input tokens 与 runtime 的关系；
- Claude 和 Gemini 在单条 context 粒度上的开销差异。

重要字段：

| 字段 | 含义 |
|---|---|
| `scope_id` | 输入范围 ID |
| `chain_id` | permission context / chain ID |
| `chain_nodes` | 单条 context 中的图节点数 |
| `chain_edges` | 单条 context 中的图边数 |
| `source_snippet_count` | 单条 context 携带的源码片段数 |
| `source_snippet_chars` | 单条 context 源码片段字符数 |
| `elapsed_seconds` | 单条 context 的 LLM 分析耗时 |
| `input_tokens` | 单条 context 输入 token |
| `output_tokens` | 单条 context 输出 token |
| `total_tokens` | 单条 context 总 token |

### 4.3 correlation_summary.csv

文件：

```text
data/correlation_summary.csv
```

这是已经计算好的相关性表，包含 Pearson 和 Spearman。

论文写作时优先使用这几个关系：

| 分析项 | 用途 |
|---|---|
| `repo scale vs generated context count` | 说明 repo 图规模和 context 数量只是中等相关 |
| `context count vs scope runtime` | 说明总耗时主要随 context 数量增长 |
| `source snippets vs scope runtime` | 说明源码片段数量也会影响总耗时 |
| `context count vs scope total tokens` | 说明 token 成本主要随 context 数量增长 |
| `source snippets vs scope total tokens` | 说明 token 成本也随源码片段规模增长 |
| `chain input tokens vs chain runtime` | 补充说明单条 context 输入长度与单次调用耗时的关系 |

## 5. 图怎么用

### 5.1 主文建议放图 1：repo_scale_vs_context_count.png

文件：

```text
figures/repo_scale_vs_context_count.png
```

这张图的横轴是：

```text
Repo Graph Scale = graph_nodes + graph_edges
```

纵轴是：

```text
Generated Permission Context Count
```

每个点表示一个 input scope，共 15 个点。

颜色区分 Hack@DAC18、Hack@DAC19、Hack@DAC21。这里区分 benchmark 的原因是：这张图和模型无关，Claude/Gemini 还没有参与；颜色只是帮助观察不同 benchmark 的分布差异。

这张图要说明：

```text
原始 repo 图规模和生成的 permission context 数量有中等相关，
但不是强线性关系。
```

对应数据：

```text
Pearson r = 0.538
Spearman rho = 0.625
```

可以支撑的论文表述：

```text
生成的权限上下文数量与仓库图规模呈中等相关，说明方法并非简单按原始仓库规模扩大 LLM 输入。
context 数量还受到权限相关结构密度影响。
```

不要过度解读为：

```text
repo 越大，context 一定越多。
```

这张图的价值在于说明 ours 不是直接把完整 repo 交给 LLM，而是先把 repo 转换成有限数量的权限链路上下文。

### 5.2 主文建议放图 2：combined_context_count_vs_runtime.png

文件：

```text
figures/combined_context_count_vs_runtime.png
```

这张图的横轴是：

```text
Generated Permission Context Count
```

纵轴是：

```text
Runtime (s)
```

每个点表示某个模型在某个 input scope 上的运行结果。由于有 Claude 和 Gemini 两个模型，所以共有 30 个点。

颜色区分 Claude 和 Gemini。这里区分模型的原因是：runtime 是模型相关的，同一批 context 在不同模型上的耗时不同。

这张图要说明：

```text
模块3总耗时与 permission context 数量高度相关。
```

对应数据：

```text
combined Pearson r = 0.906
combined Spearman rho = 0.853
Claude Pearson r = 0.969
Gemini Pearson r = 0.906
```

可以支撑的论文表述：

```text
总运行时间与权限上下文数量高度相关，说明方法的主要执行开销来自 LLM 对权限链路上下文的逐条分析，
而不是原始 RTL 仓库规模本身。
```

这张图是 RQ3 最重要的图。

### 5.3 补充图：combined_snippet_count_vs_runtime.png

文件：

```text
figures/combined_snippet_count_vs_runtime.png
```

这张图的横轴是：

```text
Source Snippet Count
```

纵轴是：

```text
Runtime (s)
```

这张图要说明：

```text
不仅 context 数量影响运行时间，context 中携带的源码片段数量也会影响运行时间。
```

对应数据：

```text
combined Pearson r = 0.905
combined Spearman rho = 0.853
Claude Pearson r = 0.948
Gemini Pearson r = 0.921
```

这张图可以放附录，也可以在主文中作为第二张图的补充。

### 5.4 补充图：context count vs total tokens

文件：

```text
figures/claude_context_count_vs_total_tokens.png
figures/gemini_context_count_vs_total_tokens.png
```

这两张图说明：

```text
context 数量不仅决定 runtime，也强烈影响 total tokens。
```

对应数据：

```text
Claude context count vs total tokens: Pearson r = 0.954
Gemini context count vs total tokens: Pearson r = 0.954
```

如果论文正文篇幅有限，可以不放图，只在文字或表格中报告相关性。

### 5.5 补充图：chain input tokens vs runtime

文件：

```text
figures/combined_chain_input_tokens_vs_runtime.png
figures/claude_chain_input_tokens_vs_runtime.png
figures/gemini_chain_input_tokens_vs_runtime.png
```

这类图是 chain-level 粒度，每个点是一条 context 的一次 LLM 调用。

它最像 VerilogLAVD 中 execution time vs executed primitives 的散点图。

这张图要说明：

```text
单条 context 的 input tokens 越多，单次 LLM 调用通常越慢，但相关性只是中等。
```

对应数据：

```text
combined Pearson r = 0.366
combined Spearman rho = 0.482
Claude Pearson r = 0.562
Gemini Pearson r = 0.334
```

这说明单条调用耗时除了 input tokens 外，还受模型服务延迟、输出长度、网络波动、模型内部生成策略影响。

因此这类图不建议作为主结论，只适合作为补充分析。

## 6. 推荐论文组织方式

RQ3 章节可以按以下顺序写。

### 6.1 先给总体开销表

报告：

- input scope 数量；
- context 总数；
- Claude/Gemini 总耗时；
- Claude/Gemini total tokens；
- 每个模型的 LLM call 数。

示例表述：

```text
在 15 个 input scope 上，模块2共生成 1049 条 permission context。
Claude 和 Gemini 分别对同一批 context 进行分析，因此二者的 LLM 调用次数均为 1049。
Claude 总耗时约 6.95 小时，消耗约 25.79M tokens；
Gemini 总耗时约 8.43 小时，消耗约 28.49M tokens。
```

### 6.2 再分析 repo scale 是否直接决定 context 数

使用：

```text
figures/repo_scale_vs_context_count.png
```

核心结论：

```text
repo 图规模和 context 数量只有中等相关，说明 context 数量不只是原始代码规模的函数，
还取决于权限相关结构密度。
```

### 6.3 再分析真正 runtime/token 的来源

使用：

```text
figures/combined_context_count_vs_runtime.png
```

必要时补充：

```text
figures/combined_snippet_count_vs_runtime.png
```

核心结论：

```text
运行时间和 token 成本与 context 数量、source snippet 数量高度相关。
因此方法的主要开销来自模块3对 permission context 的逐条 LLM 分析。
```

### 6.4 最后给出优化启示

可以写：

```text
RQ3 结果表明，后续优化重点不应只是减少原始 repo 规模，
而应集中在减少冗余 permission context、控制 source snippet 长度、
合并重复链路、缓存重复上下文分析结果等方面。
```

## 7. 建议放入论文正文的图

优先级最高：

```text
figures/repo_scale_vs_context_count.png
figures/combined_context_count_vs_runtime.png
```

如果正文还能放第三张：

```text
figures/combined_snippet_count_vs_runtime.png
```

如果只能放一张：

```text
figures/combined_context_count_vs_runtime.png
```

原因是这张图最直接回答 RQ3：执行开销主要由 context 数量驱动。

## 8. 不建议怎么写

不要写：

```text
repo 越大，我们方法一定越慢。
```

因为 repo scale vs context count 只是中等相关。

不要写：

```text
单条 context input tokens 完全决定 LLM runtime。
```

因为 chain-level input tokens 与 runtime 只有中等相关。

不要写：

```text
Gemini 比 Claude 更差/更好，所以方法开销如何。
```

模型间差异可以作为补充观察，但 RQ3 的核心是方法开销机制，不是模型优劣比较。

## 9. 推荐结论表述

可以在 RQ3 小节末尾使用类似表述：

```text
RQ3 的结果表明，ours 方法的执行开销主要由生成出的 permission context 数量及其源码片段规模决定。
repo graph scale 与 context count 仅呈中等相关，说明方法并未简单按原始仓库规模扩大 LLM 输入。
相比之下，context count 与总运行时间、总 token 数高度相关，并且该趋势在 Claude 和 Gemini 上均成立。
因此，ours 方法的可扩展性瓶颈主要来自模块3对权限链路上下文的逐条 LLM 分析；
后续优化应优先减少冗余 context、控制源码片段长度并缓存重复链路分析结果。
```

## 10. 当前结果的局限

需要在写作时注意：

1. scope-level 样本只有 15 个，因此 repo scale vs context count 的统计解释要克制。
2. chain-level 有 2098 个点，但同一 scope 内的 chain 并非完全独立样本，因此不能把它当成完全独立的大样本统计实验。
3. runtime 受模型服务状态、网络延迟、输出长度影响，因此 chain-level runtime 不可能只由 input tokens 决定。
4. 本分析只包含 ours，不包含 baseline；如果后续要做方法间开销对比，需要单独补 baseline 的统一 token/runtime 统计。

