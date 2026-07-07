# 第一版评分结果结构分析

本文档分析第一版评分结果中 baseline 与 proposed 的结构性差异。这里的“第一版”指人工复核前的结果，主要来自：

- `evaluation_results/summary/anyhit3_all_models.csv`
- `evaluation_results/summary/single_run_all_models.csv`
- `evaluation_results/<method>/<model>/anyhit3/anyhit3_case_hits.csv`

本文只分析第一版结果本身呈现出的结构，不把它作为最终可信结论。

## 1. 总体指标结构

### 1.1 Any-hit@3 口径

| method | model | Precision | Recall | F1 | TP cases | FP findings |
|---|---|---:|---:|---:|---:|---:|
| baseline | deepseek_v4_pro | 0.850 | 0.600 | 0.703 | 51 | 9 |
| baseline | gpt_5_5 | 1.000 | 0.553 | 0.712 | 47 | 0 |
| proposed | deepseek_v4_pro | 0.591 | 0.647 | 0.618 | 55 | 38 |
| proposed | gpt_5_5 | 0.816 | 0.729 | 0.770 | 62 | 14 |

从第一版结果看，proposed 相比 baseline 的主要变化是：

| model | Precision 变化 | Recall 变化 | F1 变化 | TP cases 变化 | FP findings 变化 |
|---|---:|---:|---:|---:|---:|
| deepseek_v4_pro | -0.259 | +0.047 | -0.085 | +4 | +29 |
| gpt_5_5 | -0.184 | +0.176 | +0.058 | +15 | +14 |

第一版结果显示 proposed 能提升召回，尤其是 GPT；但 DeepSeek 的 F1 下降，GPT 的 F1 上升。这个差异说明 proposed 在不同模型上的收益并不一致。

### 1.2 Single-run mean 口径

| method | model | Precision mean | Recall mean | F1 mean |
|---|---|---:|---:|---:|
| baseline | deepseek_v4_pro | 0.920 | 0.408 | 0.565 |
| baseline | gpt_5_5 | 1.000 | 0.384 | 0.555 |
| proposed | deepseek_v4_pro | 0.768 | 0.494 | 0.601 |
| proposed | gpt_5_5 | 0.918 | 0.584 | 0.713 |

single-run mean 口径下，proposed 对两个模型都提高了 recall 和 F1，但 precision 均下降。

这说明第一版结果给出的主要趋势是：

```text
proposed 增强了模型检出更多 GT case 的能力；
但这种增强伴随更多 finding 输出和更高 FP 风险。
```

## 2. Baseline 结果结构

第一版 baseline 的 precision 很高，尤其 GPT baseline 的 any-hit@3 precision 为 1.000，FP findings 为 0。

这个结果从评估结构上不合理。原因是模型实际会输出多个泛化安全风险，而第一版评分几乎没有把这些 unmatched findings 纳入 FP。也就是说，第一版 baseline 更像是“只统计命中的 finding”，而不是完整统计“所有模型输出 finding 中哪些无法匹配 GT”。

因此，第一版 baseline 的高 precision 不应理解为模型没有误报，而应理解为第一版评分对 FP 的覆盖不足。

从 recall 分布看，baseline 在不同 input scope 上差异明显：

- 表现较高的 scope：`h18_fc_core_security_scope`、`h19_access_control_fabric_scope`、部分 debug/JTAG 相关 scope；
- 表现较低的 scope：`h21_jtag_auth_expansion_scope`、`h21_dma_pmp_expansion_scope`、部分 crypto/security scope；
- 这说明 baseline 更容易命中语义较直接、命名明显、路径较短的权限问题，而对状态保持、PMP/DMA、JTAG authentication 细粒度机制覆盖不足。

## 3. Proposed 结果结构

第一版 proposed 的主要结构是 recall 上升、precision 下降。

### 3.1 DeepSeek

DeepSeek proposed 相比 baseline：

- TP cases 从 51 增加到 55；
- FP findings 从 9 增加到 38；
- recall 从 0.600 增加到 0.647；
- precision 从 0.850 降到 0.591；
- F1 从 0.703 降到 0.618。

DeepSeek 的 proposed 没有形成整体收益。它只是多命中了 4 个 case，但同时增加了 29 个 FP finding。

主要 recall 提升来自：

- `h21_dma_pkt_scope`: +0.667
- `h19_aes_rom2_security_scope`: +0.429
- `h18_gpio_apb_scope`: +0.400
- `h21_jtag_auth_expansion_scope`: +0.286

但也出现明显退化：

- `h21_crypto_security_scope`: -0.333
- `h21_access_lock_scope`: -0.286
- `h21_access_reglock_reset_expansion_scope`: -0.222

这说明 proposed 对 DeepSeek 的引导并不稳定，可能扩大了候选搜索范围，但没有稳定帮助其完成精确 case 对应。

### 3.2 GPT

GPT proposed 相比 baseline：

- TP cases 从 47 增加到 62；
- FP findings 从 0 增加到 14；
- recall 从 0.553 增加到 0.729；
- precision 从 1.000 降到 0.816；
- F1 从 0.712 增加到 0.770。

第一版结果中，GPT 是 proposed 的主要受益模型。它在 recall 上有明显提升，同时 FP 增加相对有限，因此 F1 上升。

主要 recall 提升来自：

- `h21_access_reglock_reset_expansion_scope`: +0.444
- `h19_aes_rom2_security_scope`: +0.429
- `h18_gpio_apb_scope`: +0.400
- `h21_fuse_rng_rsa_expansion_scope`: +0.333
- `h21_jtag_auth_expansion_scope`: +0.286

这表明 proposed 对 GPT 的初步作用更像是帮助它扩大安全相关上下文覆盖，尤其是 register lock、reset、crypto/fuse/RNG/RSA 等跨模块状态/权限传播场景。

## 4. 证据质量结构

第一版 proposed 的 fabricated/unsupported evidence rate 明显高于 baseline：

| method | model | Fabricated / Unsupported Evidence Rate |
|---|---|---:|
| baseline | deepseek_v4_pro | 0.150 |
| baseline | gpt_5_5 | 0.000 |
| proposed | deepseek_v4_pro | 0.473 |
| proposed | gpt_5_5 | 0.211 |

这个结果说明第一版 proposed 即使提高了 recall，也引入了明显证据风险。

结构上看，proposed 可能让模型更愿意输出候选漏洞链路，但其中部分链路没有被充分证据闭合，甚至被第一版评分标为 fabricated/unsupported。这与我们观察到的“输出更多、命中更多、但也更容易误导”一致。

## 5. 第一版结果的主要问题

第一版结果最核心的问题不是 proposed 是否有效，而是评分结构本身偏乐观。

### 5.1 FP 明显低估

GPT baseline 的 FP findings 为 0，precision 为 1.000。这在漏洞检测任务中不合理，尤其模型原始输出中存在大量泛化风险描述。

这说明第一版评分很可能没有把所有无法匹配 GT 的 findings 作为 FP 纳入计算，导致 baseline precision 被高估。

### 5.2 Proposed 的收益可能被高估

第一版 proposed GPT 的 F1 上升，但该结论依赖于相对较少的 FP 计数。如果 FP 统计不完整，那么 proposed 的 precision 和 F1 也会被高估。

### 5.3 证据问题与检测命中混在一起

第一版中 proposed 的 fabricated/unsupported evidence rate 明显较高，但仍然出现较高 TP 和 F1。这说明第一版虽然记录了证据问题，但对“证据不充分是否应影响 finding 可信性”的处理仍不够稳定。

## 6. 从第一版结果能得到的有效信息

第一版结果不能作为最终实验结论，但仍有分析价值。

可以保留的结构性观察是：

1. proposed 确实倾向于提升 recall，尤其对 GPT 明显；
2. proposed 会增加 finding 数量和 FP 风险；
3. proposed 对不同模型影响不同，GPT 受益更明显，DeepSeek 更容易出现 FP 增加超过 TP 增加的问题；
4. proposed 的证据质量风险更高，说明后续方法不能只增强上下文和知识，还需要更强的候选收敛和证据门控。

因此，第一版结果更适合用作“初步趋势观察”，不适合作为论文中的最终定量结果。

