# Hack@DAC 2018 完整映射工作表

> Phase 2 子任务文档，版本 v0.2，2026-05-12。

## 1. 口径说明

本文档是 Hack@DAC 2018 PULPissimo benchmark 全部 31 个 bug 的描述级初筛入口。

表中的 `v0.2 参考标签` 只表示与早期特征草稿 F1-F10 的参考性相似关系，不代表最终分类，也不作为 case 纳入或排除依据。

后续复核每个 case 时，应先填写开放编码现象和 RTL 证据，再讨论它对旧 F1-F10 的影响：支持、修订、合并、拆分、删除或新增。

## 2. 筛选目标

本表回答三个问题：

- 哪些 Hack@DAC 2018 bug 属于权限相关漏洞候选？
- 哪些 bug 可能涉及跨模块 / inter-IP / 跨控制域交互？
- 哪些 bug 值得优先进入 RTL 证据分析？

## 3. 状态定义

- **候选：** 与权限相关，且可能涉及跨模块交互，后续应进入语料分析。
- **边界候选：** 与安全或权限有一定关系，但是否符合本课题范围需要 RTL 证据确认。
- **暂不纳入：** 当前描述更像纯功能、DoS、密码算法、可用性或与权限交互关系较弱的问题。

## 4. 全量描述级初筛

| Bug ID | 原始描述 | 是否权限相关 | 是否跨模块 | 初始类别 | 开放编码现象（待复核） | v0.2 参考标签 | 纳入状态 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| #1 | Address range overlap between peripherals SPI Master and SoC. | 是 | 边界 | address map / protected resource | 地址映射边界冲突使 requester 获得非预期 resource 访问路径 | F2/F7 | 候选 |
| #2 | Addresses for L2 memory is out of the specified range. | 是 | 边界 | address map / memory protection | 受保护内存范围与解码/配置边界不一致 | 待定 | 候选 |
| #3 | Processor assigns privilege level of execution incorrectly from CSR. | 是 | 边界 | privilege / CSR | CSR 中的权限状态被错误解释或传播到执行权限 | F1/F9 | 候选 |
| #4 | Register that controls GPIO lock can be written to with software. | 是 | 边界 | lock / write protection | 保护机制的控制状态可被同一访问路径改写 | F5/F1 | 候选 |
| #5 | Reset clears the GPIO lock control register. | 是 | 边界 | reset / lock / lifecycle | reset/lifecycle 与权限状态维护不一致，保护状态被清除 | F4/F1 | 候选 |
| #6 | Incorrect address range for APB allows memory aliasing. | 是 | 是 | address map / bus | 总线地址别名产生非预期访问路径 | F2/F7 | 候选 |
| #7 | AXI address decoder ignores errors. | 是 | 是 | bus / address decoder | 下游错误未被上游 mediation 采纳，错误访问继续传播 | F5/F9 | 候选 |
| #8 | Address range overlap between GPIO, SPI, and SoC control peripherals. | 是 | 是 | address map / peripheral isolation | 多个外设与 SoC control 地址空间重叠，破坏隔离边界 | F2/F7 | 候选 |
| #9 | Incorrect password checking logic in debug unit. | 是 | 边界 | debug authorization | debug 认证 guard 的逻辑条件错误 | F5 | 候选 |
| #10 | Advanced debug unit only checks 31 of the 32 bits of the password. | 是 | 边界 | debug authorization / partial check | 认证比较在位宽粒度上丢失安全语义 | F5 | 候选 |
| #11 | Able to access debug register when in halt mode. | 是 | 边界 | debug authorization / processor state | 一个模块状态被误当作 debug 授权条件 | F1/F6 | 候选 |
| #12 | Password check for the debug unit does not reset after successful check. | 是 | 边界 | debug authorization / state residue | debug 认证状态在权限转换后残留 | F10/F4 | 候选 |
| #13 | Faulty decoder state machine logic in RISC-V core results in a hang. | 否 | 否 | functional / hang | 更像纯功能 hang，暂无权限语义 | 无 | 暂不纳入 |
| #14 | Incomplete case statement in ALU can cause unpredictable behavior. | 否 | 否 | functional | 更像 ALU 局部功能缺陷 | 无 | 暂不纳入 |
| #15 | Faulty logic in RTC causing inaccurate time for security-critical flows, e.g. DRM. | 边界 | 边界 | timing / security flow | 安全关键流程依赖的时间状态错误 | 待定 | 边界候选 |
| #16 | Reset for advanced debug unit not operational. | 是 | 边界 | debug / reset | debug 安全状态无法被 reset 正确恢复 | F4/F10 | 候选 |
| #17 | Memory-mapped register file allows code injection. | 是 | 是 | memory-mapped register / code injection | memory-mapped resource 暴露可写路径并影响执行内容 | F1/F7 | 候选 |
| #18 | Non-functioning cryptography module causes DOS. | 边界 | 边界 | crypto / DoS | 更像可用性或安全功能失效，需要确认权限关系 | 无 | 边界候选 |
| #19 | Insecure hash function in cryptography module. | 否 | 否 | crypto algorithm | 算法强度问题，不是 RTL 权限交互缺陷 | 无 | 暂不纳入 |
| #20 | Cryptographic key for AES stored in unprotected memory. | 是 | 是 | key / protected memory | key asset 与 memory protection 边界不匹配 | F1/F7 | 候选 |
| #21 | Temperature sensor is muxed with cryptography modules. | 边界 | 是 | mux / side channel | 共享 mux 可能造成安全域耦合，但权限语义待确认 | F7/待定 | 边界候选 |
| #22 | ROM size too small preventing execution of security code. | 边界 | 边界 | boot / security code | 安全代码无法执行，可能是配置/容量问题 | 待定 | 边界候选 |
| #23 | Disabled ability to activate security-enhanced core. | 是 | 边界 | security mode / lifecycle | 安全增强能力无法被激活，可能是 lifecycle/配置链路失效 | F4/F8 | 候选 |
| #24 | GPIO enable always high. | 是 | 边界 | lock / enable control | enable 控制失去安全约束，资源长期暴露 | F5/F8 | 候选 |
| #25 | Unprivileged user-space code can write to privileged CSR. | 是 | 边界 | privilege / CSR | requester 权限状态没有正确约束 CSR 写操作 | F1 | 候选 |
| #26 | Advanced debug unit password is hard-coded and set on reset. | 是 | 边界 | debug authorization / reset | reset 将 debug 认证状态设为可预测值 | F4/F10 | 候选 |
| #27 | Secure mode is not required to write to interrupt registers. | 是 | 边界 | secure mode / interrupt register | 安全模式状态未参与受保护寄存器写入 mediation | F1/F6 | 候选 |
| #28 | JTAG interface is not password protected. | 是 | 是 | debug authorization / external interface | 外部 debug requester 缺少认证 mediation | F1 | 候选 |
| #29 | Output of MAC is not erased on reset. | 是 | 边界 | reset / data residue | reset 后安全相关数据残留 | F10 | 候选 |
| #30 | Supervisor mode signal of a core is floating preventing use of SMAP. | 是 | 边界 | privilege signal / protection mechanism | 权限状态信号未被可靠驱动，导致保护机制失效 | F4/F9 | 候选 |
| #31 | GPIO is able to read/write to instruction and data cache. | 是 | 是 | peripheral / cache access | 外设 requester 获得对 cache 的非预期读写路径 | F1/F7 | 候选 |

## 5. 初筛统计

- **候选：** 23 个。
- **边界候选：** 4 个。
- **暂不纳入：** 4 个。

这个统计是描述级结果，不是最终语料统计。后续 RTL 证据分析可能改变纳入状态。

## 6. 优先分析批次

优先进入 RTL evidence 分析的 case：

1. **Debug authorization：** #9, #10, #11, #12, #16, #26, #28
2. **Lock / write protection：** #4, #5, #24, #27
3. **Privilege / CSR：** #3, #25, #30
4. **Address map / protected memory：** #1, #2, #6, #7, #8, #17, #20, #31

## 7. 后续工作

- 对优先批次逐个填写 `bug_case_analysis_template.md`。
- 每个 case 先写开放编码现象，再写 v0.2 参考标签。
- 对每个候选 case 记录 RTL evidence、证据等级和可信度。
- 在完成第一轮 15-20 个 case 后，回到特征框架，讨论 F1-F10 的保留、合并、拆分、删除和新增。
