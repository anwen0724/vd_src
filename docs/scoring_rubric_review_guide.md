# Scoring Rubric Review Guide

本文档记录人工抽查 baseline 评分口径时需要看什么、确认什么。

适用对象：

```text
results/baseline/<batch_id>/scoring_reviewed_scope_<input_scope>/
results/baseline/<batch_id>/scoring_reviewed_all/
```

## 1. 抽查目标

人工抽查不是逐行重新评分所有 CSV，而是确认当前评分边界是否符合研究目标。

核心问题：

```text
我们的评分是否在衡量 agent 对具体漏洞的可靠检测，
而不是奖励 agent 输出泛泛安全味道很强的结论。
```

当前默认评分原则：

```text
只有模型输出匹配具体 GT 语义和关键 RTL 证据路径，才算 TP；
大方向相关但证据、定位或路径不完整，算 Partial；
无法对应 visible GT case，算 FP；
visible GT case 没有被命中，算 FN。
```

## 2. 需要重点看的文件

每个 reviewed scope 目录下优先看：

```text
scope_evaluation_summary.md
finding_level_scores.csv
case_level_scores.csv
failure_analysis.csv
run_summary.csv
```

建议阅读顺序：

```text
1. scope_evaluation_summary.md
2. finding_level_scores.csv
3. case_level_scores.csv
4. failure_analysis.csv
5. run_summary.csv
```

## 3. 先看 scope summary

重点看：

```text
Main Observations
Notes for Later Scoring
Per-run Results
```

需要确认：

```text
1. summary 对该 scope 的主要结论是否客观；
2. 是否存在过度解释模型能力或失败原因；
3. 评分边界说明是否符合该 scope 的 GT 定义；
4. Per-run Results 是否与 CSV 中 case-level 评分一致。
```

如果 summary 结论过于主观、过于保守或与 GT 不一致，需要回到对应 CSV 修改评分。

## 4. 确认 TP / Partial / FN / FP 边界

重点抽查 `finding_level_scores.csv`。

需要确认：

```text
1. 一个 finding 被标为 TP 时，是否真的匹配具体 GT case；
2. 一个 finding 被标为 Partial 时，是否只是方向相关但证据不完整；
3. 一个 finding 被标为 FP 时，是否确实无法对应当前 visible GT case；
4. 一个 case 被标为 FN 时，是否确实没有被任何 finding 命中。
```

典型边界问题：

```text
泛泛说“JTAG 没认证”，不能自动命中所有 JTAG/password 相关 case；
泛泛说“GPIO/APB 没权限控制”，不能自动命中 REG_GPIOLOCK 可写、reset 清锁、地址重叠等不同 case；
泛泛说“ROM2 可读写”，不能自动命中 AES key readout、JTAG hardcoded key、access-control mutable 等不同 case；
泛泛说“crypto peripheral accessible”，不能自动命中具体 AES/SHA/HMAC state residue 或 register-lock case。
```

## 5. 确认一个 finding 是否能对应多个 case

默认采用保守口径：

```text
同一个 finding 不自动扩展成多个 TP。
```

只有当该 finding 明确覆盖多个 case 的关键语义和证据时，才可以在 `case_level_scores.csv` 中让多个 case 引用同一个 finding。

需要确认：

```text
1. 如果一个 broad finding 被用于多个 case，是否每个 case 都有足够证据；
2. 如果只是共享同一根因，但没有分别解释每个漏洞语义，不应扩展成多个 TP；
3. 对于只部分覆盖的 case，应标为 Partial，而不是 TP。
```

示例：

```text
“ROM2 secure registers are readable/writable”
可能与多个 case 相关，但不能自动算作：
- AES key hardcoded
- AES key readout
- access-control mutable
- JTAG key hardcoded
- secure register exposure

除非输出分别给出了对应路径和证据。
```

## 6. 确认相邻问题是否被正确拆分

很多 scope 中多个 case 位于同一代码区域，但漏洞语义不同。

抽查时需要确认这些相邻 case 没有被混算。

示例：

```text
H18-004: GPIO lock register 可写
H18-005: reset 清空 GPIO lock
H18-008: GPIO/SPI/SoC control 地址范围重叠
```

模型只抓到 lock 可写时，不能算命中 reset 清锁或地址重叠。

示例：

```text
H19-005: debug module always authenticated
H19-047: DMI write path lacks password guard
H19-051: pass_chk reset state residue
H19-054: JTAG key hardcoded
```

这些都属于 debug/JTAG 方向，但不是同一个漏洞。

## 7. 确认 failure flags

重点抽查 `finding_level_scores.csv` 中这些字段：

```text
wrong_localization
insufficient_evidence
fabricated_evidence
unsupported_claim
overconfidence
```

当前判定规则：

| 字段 | 何时为 yes |
|---|---|
| `wrong_localization` | finding 方向相关，但文件、模块、信号、寄存器或跨文件路径定位错误或明显不完整。 |
| `insufficient_evidence` | 证据真实存在，但不足以支撑该 finding 的主要结论。 |
| `fabricated_evidence` | 引用的文件、模块、信号、寄存器、行号或行为不存在。 |
| `unsupported_claim` | 输出有安全结论，但没有提供有效代码证据。 |
| `overconfidence` | finding 是 FP、Partial、证据不足或不确定问题，但模型仍以高置信度或确定语气输出。 |

需要确认：

```text
1. Partial finding 是否通常伴随 insufficient_evidence 或 wrong_localization；
2. FP finding 是否保留了 matched_case_id，若有则需要修正为空；
3. 高置信度但证据不足的 finding 是否标记 overconfidence=yes；
4. 没有真实证据的结论是否标记 unsupported_claim=yes。
```

## 8. 建议优先抽查的 scope

优先抽查：

```text
h18_debug_jtag_scope
h19_aes_rom2_security_scope
h21_crypto_security_scope
```

原因：

| scope | 抽查重点 |
|---|---|
| `h18_debug_jtag_scope` | 泛化 debug risk 与具体 password-check bugs 是否被正确区分。 |
| `h19_aes_rom2_security_scope` | ROM2/key/secure register 多个相邻 case 是否被拆开评分。 |
| `h21_crypto_security_scope` | broad access-control finding 是否被过度扩展成多个 crypto case。 |

如果这三个 scope 的评分口径可以接受，再抽查其他 scope。

## 9. 抽查后的处理

如果发现评分不合理：

```text
1. 修改对应 scoring_reviewed_scope_<input_scope>/ 下的 CSV；
2. 重新运行 aggregate_scores.py 更新该 scope 的 run_summary.csv；
3. 修改该 scope 的 scope_evaluation_summary.md；
4. 重新运行 merge_reviewed_scopes.py 生成 scoring_reviewed_all/。
```

命令示例：

```powershell
python -m evaluation.aggregate_scores `
  --scoring-dir results/baseline/<batch_id>/scoring_reviewed_scope_<input_scope>

python -m evaluation.merge_reviewed_scopes `
  --batch-results-dir results/baseline/<batch_id>
```

不要直接只改 `scoring_reviewed_all/`，因为它是合并产物，会被重新生成覆盖。
