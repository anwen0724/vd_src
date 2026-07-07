# 第二版人工复核结果结构分析

本文档分析人工复核后的 baseline 与 proposed 结果结构。这里的“第二版”指根据 `finding_gt_matching_principles.md` 逐条复核 finding 与 GT case 匹配后生成的结果，主要来自：

- `evaluation_results/manual_summary/manual_anyhit3_model_summary.csv`
- `evaluation_results/manual_summary/manual_single_run_model_summary.csv`
- `evaluation_results/manual_summary/manual_review_counts.csv`
- `evaluation_results/<method>/<model>/finding_review_manual.csv`
- `evaluation_results/<method>/<model>/anyhit3_manual/anyhit3_case_hits.csv`

相比第一版，第二版把更多无法稳定匹配 GT case 的 finding 计入 FP，因此结果更严格，也更接近后续论文应采用的评估口径。

## 1. 总体指标结构

### 1.1 Any-hit@3 口径

| method | model | Precision | Recall | F1 | TP cases | FP findings |
|---|---|---:|---:|---:|---:|---:|
| baseline | deepseek_v4_pro | 0.321 | 0.424 | 0.365 | 36 | 76 |
| baseline | gpt_5_5 | 0.347 | 0.388 | 0.367 | 33 | 62 |
| proposed | deepseek_v4_pro | 0.236 | 0.541 | 0.329 | 46 | 149 |
| proposed | gpt_5_5 | 0.230 | 0.647 | 0.340 | 55 | 184 |

人工复核后，proposed 相比 baseline 的变化如下：

| model | Precision 变化 | Recall 变化 | F1 变化 | TP cases 变化 | FP findings 变化 |
|---|---:|---:|---:|---:|---:|
| deepseek_v4_pro | -0.086 | +0.118 | -0.037 | +10 | +73 |
| gpt_5_5 | -0.117 | +0.259 | -0.027 | +22 | +122 |

核心结构是：

```text
proposed 明显提高 recall；
但 FP 增加更快，precision 下降；
在 any-hit@3 口径下，F1 没有超过 baseline。
```

这说明当前 proposed 初版方法不是“整体效果已经更好”，而是“更像 recall-oriented 的候选扩展方法”。它帮助模型发现更多真实漏洞，但没有足够控制误报。

### 1.2 Single-run mean 口径

| method | model | Precision mean | Recall mean | F1 mean |
|---|---|---:|---:|---:|
| baseline | deepseek_v4_pro | 0.474 | 0.267 | 0.341 |
| baseline | gpt_5_5 | 0.538 | 0.282 | 0.370 |
| proposed | deepseek_v4_pro | 0.348 | 0.310 | 0.328 |
| proposed | gpt_5_5 | 0.409 | 0.498 | 0.449 |

single-run mean 口径下，GPT proposed 的 F1 高于 GPT baseline，但 DeepSeek proposed 低于 DeepSeek baseline。

这与 any-hit@3 的结论不同，原因是两种口径对重复运行的 FP 处理不同：

- single-run mean：每次运行单独算，再取平均；
- any-hit@3：3 次运行中任一次命中即算该 case 命中，但 FP findings 会在合并表中累积。

因此，proposed 这种“多报候选”的方法在 any-hit@3 下会受到更强 FP 惩罚。这个现象说明 proposed 的主要问题不是完全检不出漏洞，而是每次运行都会产生大量无法匹配 GT 的额外 finding。

## 2. 输出规模结构

人工复核表中的 finding 数量如下：

| method | model | Total findings | TP findings | FP findings | Duplicate findings |
|---|---|---:|---:|---:|---:|
| baseline | deepseek_v4_pro | 149 | 68 | 76 | 5 |
| baseline | gpt_5_5 | 136 | 72 | 62 | 2 |
| proposed | deepseek_v4_pro | 272 | 79 | 149 | 44 |
| proposed | gpt_5_5 | 389 | 127 | 184 | 78 |

proposed 的输出规模明显更大：

- DeepSeek：272 vs 149，约为 baseline 的 1.83 倍；
- GPT：389 vs 136，约为 baseline 的 2.86 倍。

但 TP finding 的增长没有 FP 和 Duplicate 增长快：

- DeepSeek TP findings 增加 11，但 FP findings 增加 73；
- GPT TP findings 增加 55，但 FP findings 增加 122，Duplicate 增加 76。

这说明当前 proposed 的主要结构问题是候选生成过宽，缺少足够强的去重、合并和最终结论过滤。

## 3. Recall 提升来自哪些 scope

### 3.1 DeepSeek

人工复核后，DeepSeek proposed 的主要 recall 提升来自：

| input_scope | baseline recall | proposed recall | 变化 |
|---|---:|---:|---:|
| h18_gpio_apb_scope | 0.200 | 0.800 | +0.600 |
| h19_access_control_fabric_scope | 0.000 | 0.500 | +0.500 |
| h19_csr_privilege_scope | 0.500 | 1.000 | +0.500 |
| h21_dma_pkt_scope | 0.667 | 1.000 | +0.333 |
| h18_debug_jtag_scope | 0.250 | 0.500 | +0.250 |
| h19_debug_jtag_scope | 0.375 | 0.625 | +0.250 |

DeepSeek proposed 在 GPIO/APB 地址范围、access-control fabric、CSR privilege、DMA/PKT、debug/JTAG 等场景中确实多命中了一些 GT case。

但多个 scope 没有提升：

- `h21_access_lock_scope`
- `h21_access_reglock_reset_expansion_scope`
- `h21_crypto_security_scope`
- `h21_dma_pmp_expansion_scope`
- `h21_fuse_rng_rsa_expansion_scope`
- `h21_jtag_auth_expansion_scope`

这说明 proposed 对 DeepSeek 的帮助主要集中在结构较清晰、命名较明显、路径可追踪的问题上；对 crypto 状态保持、PMP/DMA 检查、JTAG authentication 细节机制的帮助有限。

### 3.2 GPT

人工复核后，GPT proposed 的主要 recall 提升来自：

| input_scope | baseline recall | proposed recall | 变化 |
|---|---:|---:|---:|
| h21_fuse_rng_rsa_expansion_scope | 0.000 | 1.000 | +1.000 |
| h19_access_control_fabric_scope | 0.500 | 1.000 | +0.500 |
| h19_csr_privilege_scope | 0.500 | 1.000 | +0.500 |
| h21_crypto_security_scope | 0.000 | 0.500 | +0.500 |
| h21_access_reglock_reset_expansion_scope | 0.222 | 0.667 | +0.444 |
| h18_gpio_apb_scope | 0.400 | 0.800 | +0.400 |
| h19_aes_rom2_security_scope | 0.429 | 0.714 | +0.286 |

GPT proposed 的提升范围比 DeepSeek 更广，尤其在 fuse/RNG/RSA、crypto、access-reglock-reset、CSR privilege 等需要跨模块状态和权限语义理解的场景中更明显。

这说明方法中的结构化引导、权限知识和证据组织对 GPT 有实际帮助，能够让 GPT 覆盖 baseline 漏掉的 case。

但 GPT proposed 同时产生 184 个 FP findings 和 78 个 Duplicate findings。也就是说，它不是更精确地输出了少量正确漏洞，而是输出了大量候选，其中一部分命中了 GT。

## 4. Precision 下降的结构原因

人工复核后，precision 下降不是偶然，而是由 proposed 的输出结构决定的。

### 4.1 候选生成过宽

proposed 会鼓励模型从权限知识、代码结构和安全义务角度枚举潜在风险。这提升了覆盖率，但也导致模型把很多“安全上值得关注的代码路径”直接转化为漏洞 finding。

典型表现：

- 把普通 debug 可达路径报告为漏洞；
- 把未完全闭合的 reset/lock 风险报告为 confirmed finding；
- 把同一类 access-control 风险在多个模块上重复报告；
- 把 GT 之外的泛化安全风险也作为漏洞输出。

这些 finding 在工程分析中可能有启发意义，但在当前 benchmark GT 评估中必须计为 FP。

### 4.2 Duplicate 明显增加

proposed 的 Duplicate findings 明显多于 baseline：

- DeepSeek proposed: 44
- GPT proposed: 78

这说明方法让模型围绕同一个真实 case 生成多个相近 finding。对 case-level recall 有帮助，但对最终报告质量不利。

如果一个工程师阅读这样的报告，会看到多条语义重叠的风险描述，需要额外人工合并判断。这本身就是可靠性问题。

### 4.3 Evidence gate 不够强

人工复核后，proposed 的 evidence quality 中出现较多 `Insufficient` 和 `Unclear`：

| method | model | Insufficient | Unclear |
|---|---|---:|---:|
| proposed | deepseek_v4_pro | 29 | 63 |
| proposed | gpt_5_5 | 90 | 100 |

这说明当前 proposed 还没有有效要求模型在输出 finding 前完成证据闭合。

它能帮助模型形成更多候选漏洞假设，但不能保证每个候选都具备：

- 清楚的 source/operation/object；
- 明确的 expected guard；
- 真实可复核的 RTL evidence；
- 与具体 GT case 稳定对应的漏洞语义。

## 5. 与第一版结果的关键差异

人工复核后，所有模型和方法的 precision 明显下降。主要原因是第二版把无法稳定匹配 GT case 的 finding 正式计入 FP。

例如：

- 第一版 GPT baseline any-hit@3 precision 为 1.000，FP findings 为 0；
- 人工复核后 GPT baseline precision 为 0.347，FP findings 为 62。

这说明第一版并不是模型真的没有误报，而是评分流程没有充分统计误报。

因此，人工复核后的结果更接近真实情况：

```text
baseline 本身也存在大量 FP；
proposed 能提高 recall；
proposed 进一步放大 FP 和 Duplicate；
当前 proposed 不是最终有效方法，而是一个 recall 提升但 precision 控制不足的初版。
```

## 6. 对当前方法设计的直接结论

从人工复核结果出发，当前 proposed 初版方法的作用和问题可以概括为：

### 6.1 已经有效的部分

proposed 对 recall 有真实提升：

- DeepSeek: 36 -> 46 个 TP cases；
- GPT: 33 -> 55 个 TP cases。

这说明结构化引导、权限知识和代码结构辅助确实帮助模型发现 baseline 漏掉的漏洞。

### 6.2 尚未解决的问题

proposed 没有提升整体 F1，核心原因是 precision 下降：

- DeepSeek FP findings: 76 -> 149；
- GPT FP findings: 62 -> 184。

这说明当前方法还缺少三个关键能力：

1. 候选漏洞收敛：不能把所有潜在风险都输出为 finding；
2. 证据闭合检查：没有足够证据时不能给出确定结论；
3. 重复/泛化 finding 合并：同一 case 或同一风险链路需要合并成一个稳定结论。

### 6.3 后续方法优化方向

下一版方法不应继续只增强 code map、知识库或候选生成能力。当前最需要补的是：

```text
Candidate filtering
Evidence closure
Verdict consolidation
```

也就是说，方法应从“帮助模型看得更多”转向“帮助模型只报告证据闭合、能稳定对应具体漏洞语义的 finding”。

## 7. 当前结果是否说明 proposed 不如 baseline

如果只看 any-hit@3 F1，当前 proposed 确实没有超过 baseline。

但更准确的结论不是“方法无效”，而是：

```text
当前 proposed 初版有效提升了漏洞覆盖率；
但没有控制报告质量；
因此不满足最终论文中‘提高可靠性’的目标。
```

它目前更像一个 recall-enhancing 方法，而不是一个 reliability-improving 方法。

要让它符合论文目标，需要在现有方法基础上增加更强的 verdict gate，使最终输出从“多候选报告”变为“少量、证据闭合、可复核的漏洞结论”。

