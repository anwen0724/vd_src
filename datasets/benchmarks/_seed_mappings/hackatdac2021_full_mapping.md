# Hack@DAC 2021 完整映射工作表

> Phase 2 子任务文档，版本 v0.1，2026-05-12。

## 1. 口径说明

本文档是 Hack@DAC 2021 OpenPiton + Ariane/RISC-V benchmark 全部 99 个 inserted bugs 的描述级初筛入口。

表中的 `v0.2 参考标签` 只表示与早期特征草稿 F1-F10 的参考性相似关系，不代表最终分类，也不作为 case 纳入或排除依据。后续复核每个 case 时，应先补 RTL evidence，再讨论它对旧 F1-F10 的影响。

## 2. 来源

- GitHub 仓库：`https://github.com/HACK-EVENT/hackatdac21`
- Bug list 位置：仓库 `README.md`
- 设计对象：OpenPiton + Ariane/RISC-V
- 本地浅克隆：`tmp/hackatdac21`

## 3. 状态定义

- **候选：** 与权限相关，且可能涉及跨模块 / inter-IP / 跨控制域交互。
- **边界候选：** 与安全或权限有一定关系，但是否符合本课题范围需要 RTL 证据确认。
- **暂不纳入：** 当前描述更像纯功能、DoS、算法强度、可用性或与权限交互关系较弱的问题。

## 4. 全量描述级初筛

| Bug ID | 原始描述 | 是否权限相关 | 是否跨模块 | 初始类别 | 开放编码现象（待复核） | v0.2 参考标签 | 纳入状态 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| #1 | JTAG password flag not reset properly | 是 | 是 | JTAG / reset / auth state | JTAG 认证状态 reset 后残留 | F10/F4 | 候选 |
| #2 | Able to write using JTAG without password | 是 | 是 | JTAG authorization | JTAG write operation 缺少 password mediation | F1/F5 | 候选 |
| #3 | JTAG is padded to be 256 bits | 是 | 边界 | JTAG auth strength | JTAG 认证字段填充/位宽处理改变认证强度 | F5 | 候选 |
| #4 | JTAG not temporarily disabled after several continuous wrong password attempts | 是 | 是 | JTAG policy | 认证失败策略缺失，debug mediation 不完整 | F5/F6 | 候选 |
| #5 | Processor access to HMAC grants it access to PKT regardless of PKT access configuration | 是 | 是 | access control / peripheral coupling | 访问 HMAC 时错误获得 PKT 访问能力 | F1/F7 | 候选 |
| #6 | UART cannot be accessed from user mode | 边界 | 边界 | over-restrictive access control | 用户态访问被错误拒绝，权限状态与资源策略不一致 | F9 | 边界候选 |
| #7 | Incorrect access control setting leaving debug enabled | 是 | 是 | debug / access control | access-control 配置错误使 debug 能力保持开启 | F1/F8 | 候选 |
| #8 | Fan speed can be controlled from unprivileged application | 是 | 是 | peripheral control | 低权限软件控制安全相关外设状态 | F1/F7 | 候选 |
| #9 | PLIC registers are not protected by access control | 是 | 是 | PLIC / access control | 中断控制寄存器缺少访问 mediation | F1 | 候选 |
| #10 | ROM registers are not protected by access control | 是 | 是 | ROM / access control | ROM 相关寄存器缺少访问 mediation | F1 | 候选 |
| #11 | DMA registers are not protected by access control | 是 | 是 | DMA / access control | DMA 控制寄存器缺少访问 mediation | F1/F7 | 候选 |
| #12 | UART registers are not protected by access control | 是 | 边界 | UART / access control | UART 控制寄存器缺少访问 mediation | F1 | 候选 |
| #13 | AES internal registers are visible externally | 是 | 是 | crypto internal state exposure | AES 内部状态通过外部接口暴露 | F7 | 候选 |
| #14 | Counter register in AES CTR mode does not increase | 边界 | 否 | crypto state | CTR 状态更新错误，权限交互不明显 | F4 | 边界候选 |
| #15 | Crypto oracle for encrypt/decrypt is exposed to unprivileged applications | 是 | 是 | crypto oracle / privilege | 低权限软件可调用受保护 crypto oracle | F1/F7 | 候选 |
| #16 | SHA is not properly checked during Boot test | 边界 | 是 | boot integrity | boot 阶段 SHA 检查 mediation 不完整 | F5/F6 | 边界候选 |
| #17 | Boot ROM code performs insufficient checks on PRNG core | 边界 | 是 | boot / PRNG integrity | BootROM 对 PRNG core 的安全检查不足 | F5/F6 | 边界候选 |
| #18 | Access to CSRs from lower privilege level | 是 | 边界 | CSR / privilege | 低权限 requester 可访问高权限 CSR | F1 | 候选 |
| #19 | Receive CSR interrupts when committing atomic instructions | 边界 | 边界 | CSR / atomic / interrupt | CSR interrupt 与 atomic commit 状态耦合异常 | F6/F9 | 边界候选 |
| #20 | Commit the second instruction even if the first is atomic instruction | 边界 | 否 | pipeline / atomic | 原子指令提交顺序错误，权限语义不明显 | 无 | 暂不纳入 |
| #21 | Same cycle counter used for both CSR mcycle and cycle | 边界 | 边界 | CSR counter | 不同权限视图共享同一 counter | F8/F9 | 边界候选 |
| #22 | Instruction retired counters are updated in non-debug mode | 边界 | 边界 | debug / counter | debug 状态与计数器更新条件不一致 | F6/F9 | 边界候选 |
| #23 | IRQ source input badly connected | 边界 | 是 | interrupt wiring | 中断源连接错误导致安全事件路由异常 | F7/F9 | 边界候选 |
| #24 | SoC uses asynchronous resets | 边界 | 是 | reset / CDC | 异步 reset 可能造成安全状态跨模块不一致 | F3/F4 | 边界候选 |
| #25 | DMA does not clear the local memory after a transfer request is complete | 是 | 是 | DMA / state residue | DMA transfer 后 local memory 残留可被后续访问 | F10 | 候选 |
| #26 | The implementation of strcmp system call is not constant in time | 边界 | 否 | timing side channel | system call 时间侧信道，跨模块权限语义不明显 | 无 | 边界候选 |
| #27 | Protected memory regions can be accessed through system call address pointer arguments | 是 | 是 | syscall / protected memory | system call 指针参数绕过 protected memory mediation | F1/F5 | 候选 |
| #28 | AES key stored in memory at bootup and is not cleared before exiting from firmware setup | 是 | 是 | boot / secret residue | boot 阶段 secret 未清除，后续权限阶段可见 | F10/F4 | 候选 |
| #29 | Debug module does not reset on a system reset | 是 | 是 | debug / reset | system reset 未同步清理 debug module 状态 | F4/F10 | 候选 |
| #30 | JTAG key is hardcoded | 是 | 边界 | JTAG secret | debug authentication secret 固定化 | F4/F10 | 候选 |
| #31 | DMA registers are not locked | 是 | 是 | DMA / register lock | DMA 控制寄存器缺少 lock mediation | F1/F5 | 候选 |
| #32 | PLIC registers are not locked | 是 | 是 | PLIC / register lock | PLIC 控制寄存器缺少 lock mediation | F1/F5 | 候选 |
| #33 | ROM registers are not locked | 是 | 是 | ROM / register lock | ROM 相关寄存器缺少 lock mediation | F1/F5 | 候选 |
| #34 | UART registers are not locked | 是 | 边界 | UART / register lock | UART 控制寄存器缺少 lock mediation | F1/F5 | 候选 |
| #35 | Reg locks are disabled by default when reset | 是 | 是 | reset / register lock | reset 默认状态关闭 register lock | F4/F10 | 候选 |
| #36 | SHA input data not cleared after HASH computation | 是 | 是 | SHA / state residue | HASH 后输入数据残留 | F10 | 候选 |
| #37 | The SHA wrapper uses non-blocking assignment for variables which can cause timing issues | 边界 | 边界 | SHA / timing | wrapper 时序语义错误可能造成安全状态采样异常 | F3/F6 | 边界候选 |
| #38 | HMAC can only use messages of 512-bits | 边界 | 否 | crypto limitation | HMAC 消息长度限制，权限交互不明显 | 无 | 边界候选 |
| #39 | AES plain text is left uncleared after the encryption is over in the peripheral registers | 是 | 是 | AES / state residue | AES plaintext 在 peripheral register 中残留 | F10 | 候选 |
| #40 | One of AES user keys is all zeros | 是 | 边界 | weak key / secret | AES user key 默认弱值 | F4/F10 | 边界候选 |
| #41 | AES encryption system calls can cause race condition between different users | 是 | 是 | syscall / race / crypto | 多用户通过 AES syscall 共享状态产生竞态 | F6/F9 | 候选 |
| #42 | At reset, the access control values are set to full access | 是 | 是 | reset / access control | reset 默认 access-control 值开放所有访问 | F4/F8 | 候选 |
| #43 | Reg locks are not set for some of the ACCT registers | 是 | 是 | register lock / ACCT | 部分 access-control 寄存器未被 lock 保护 | F5/F9 | 候选 |
| #44 | HMAC only works correctly for strings of size < 448 bits | 边界 | 否 | crypto limitation | HMAC 长度边界处理错误，权限交互不明显 | 无 | 边界候选 |
| #45 | DMA transfer does not check for the max length condition in syscall | 是 | 是 | DMA / syscall / bounds | syscall 长度参数未被 DMA mediation 约束 | F5/F6 | 候选 |
| #46 | Not disconnecting sensitive data from fuse when in debug mode | 是 | 是 | debug / fuse / secret | debug mode 下 fuse sensitive data 未隔离 | F1/F7 | 候选 |
| #47 | Not clearing one of the AES keys when entering debug mode | 是 | 是 | debug / AES / state residue | 进入 debug mode 时 AES key 未清除 | F10/F4 | 候选 |
| #48 | JTAG unlock disables the reglocks | 是 | 是 | JTAG / register lock | JTAG unlock 破坏 register lock 安全状态 | F4/F8 | 候选 |
| #49 | Chicken bits corrupting access control value | 是 | 是 | chicken bits / access control | 测试/配置 bit 可破坏 access-control 值 | F7/F9 | 候选 |
| #50 | Chicken bits corrupting reglk value | 是 | 是 | chicken bits / register lock | 测试/配置 bit 可破坏 register lock 值 | F7/F9 | 候选 |
| #51 | Chicken bits corrupting mie csr reg value | 是 | 边界 | chicken bits / CSR | 测试/配置 bit 可破坏 mie CSR 安全状态 | F7/F9 | 候选 |
| #52 | Chicken bits corrupting pmp check in DMA | 是 | 是 | chicken bits / DMA / PMP | 测试/配置 bit 可破坏 DMA PMP check | F7/F9 | 候选 |
| #53 | Chicken bits corrupting JTAG expected password | 是 | 是 | chicken bits / JTAG auth | 测试/配置 bit 可破坏 JTAG expected password | F7/F9 | 候选 |
| #54 | DMA can do load even if store PMP check fails and vice versa | 是 | 是 | DMA / PMP / compound check | DMA load/store 权限检查条件被错误复用或互换 | F6/F9 | 候选 |
| #55 | DMA write only checks for end addr PMP access instead of entire range | 是 | 是 | DMA / PMP / range check | DMA range check 只检查末地址而非完整范围 | F5/F6 | 候选 |
| #56 | Change in PMP config does not abort existing DMA transfer | 是 | 是 | DMA / PMP / TOCTOU | DMA transfer 使用与当前 PMP 不一致的权限状态 | F6/F9 | 候选 |
| #57 | If abort is issued when there is no active command running in DMA, the DMA gets stuck in unknown state | 边界 | 是 | DMA state machine | abort 与 active command 状态组合导致未知状态 | F6/F9 | 边界候选 |
| #58 | SHA enters ignore state if start and next are enabled at same time and cannot move out | 边界 | 是 | SHA state machine | 复合控制信号导致 SHA 安全状态机卡死 | F6 | 边界候选 |
| #59 | PKT leaks fuse data because default case does not cover all possible values | 是 | 是 | PKT / fuse / default case | 不完整 default handling 导致 fuse data 泄露 | F5/F7 | 候选 |
| #60 | AES leaks secret key0 because default case does not cover all possible values | 是 | 是 | AES / secret leakage | 不完整 default handling 导致 AES key 泄露 | F5/F7 | 候选 |
| #61 | AES0 key1 has same lower 128 bits as upper 128 bits | 边界 | 否 | weak key | AES key 结构弱化，权限交互不明显 | 无 | 边界候选 |
| #62 | AES1 key2 has lower 128 bits as all zeros | 边界 | 否 | weak key | AES key 部分固定为零，权限交互不明显 | 无 | 边界候选 |
| #63 | sys_aes1_read_data length incorrect | 边界 | 是 | syscall / AES / length | AES syscall read length 与实际资源边界不一致 | F5/F6 | 边界候选 |
| #64 | DMA syscall length is used directly, but it is 64-bit words | 是 | 是 | DMA / syscall / length | syscall length 语义未经转换直接进入 DMA | F5/F6 | 候选 |
| #65 | Reset signal in one component of RNG is not correct | 边界 | 是 | RNG / reset | RNG 部件 reset 错误导致熵源状态受限 | F4 | 边界候选 |
| #66 | Signals do not get reset entirely due to unspecified size | 边界 | 是 | reset / signal width | reset 只清除部分位宽，安全状态残留 | F4/F10 | 边界候选 |
| #67 | Signals do not get reset entirely due to unspecified size | 边界 | 是 | reset / signal width | reset 只清除部分位宽，安全状态残留 | F4/F10 | 边界候选 |
| #68 | Polynomial of 32-bit RNG LFSR entropy source is 0 | 边界 | 否 | RNG weakness | LFSR 多项式错误导致 entropy 弱化 | 无 | 边界候选 |
| #69 | LFSR polynomial set by software is not checked | 是 | 边界 | RNG / software configuration | 软件可配置安全关键多项式但缺少合法性检查 | F5/F6 | 候选 |
| #70 | Polynomials stored in fuse memory are not primitive polynomials | 是 | 边界 | fuse / RNG configuration | fuse 中安全配置值弱化且未被校验 | F5/F6 | 边界候选 |
| #71 | RSA can generate 1 as encryption key | 边界 | 否 | RSA weakness | RSA key generation 可产生弱 key | 无 | 边界候选 |
| #72 | Reset controller can reset register locks and make private data readable | 是 | 是 | reset / register lock | reset controller 额外 reset 破坏 register lock 隔离 | F4/F10 | 候选 |
| #73 | AES2 registers are accessible from user mode | 是 | 是 | AES / privilege | 用户态可访问 AES2 protected registers | F1 | 候选 |
| #74 | HMAC registers are accessible from user mode | 是 | 是 | HMAC / privilege | 用户态可访问 HMAC protected registers | F1 | 候选 |
| #75 | HMAC key registers are not locked by register locks | 是 | 是 | HMAC key / register lock | HMAC key registers 缺少 lock mediation | F1/F5 | 候选 |
| #76 | Some register lock registers are not locked by register locks | 是 | 是 | register lock self-protection | lock 控制自身缺少二级保护 | F5 | 候选 |
| #77 | Some access control registers are not locked by register locks | 是 | 是 | AC register / lock | access-control registers 缺少 lock mediation | F5/F9 | 候选 |
| #78 | Some PKT registers are not locked by register locks | 是 | 是 | PKT / lock | PKT protected registers 缺少 lock mediation | F1/F5 | 候选 |
| #79 | Some SHA registers are not locked by register locks | 是 | 是 | SHA / lock | SHA protected registers 缺少 lock mediation | F1/F5 | 候选 |
| #80 | AES1 key registers are not locked by register locks | 是 | 是 | AES key / lock | AES key registers 缺少 lock mediation | F1/F5 | 候选 |
| #81 | Reset controller registers are not locked by register locks | 是 | 是 | reset controller / lock | reset controller registers 缺少 lock mediation | F1/F5 | 候选 |
| #82 | HMAC and other modules use a clock not protected for glitches | 边界 | 是 | clock / fault hardening | 安全模块共享未抗 glitch 的 clock | F3/F8 | 边界候选 |
| #83 | Incorrect indices used to get hash values from FUSE mem | 是 | 是 | fuse / hash / indexing | fuse hash 索引错误导致认证/secret 绑定错位 | F5/F7 | 候选 |
| #84 | Unreachable state WaitWriteValid in JTAG | 边界 | 是 | JTAG state machine | JTAG 状态机存在不可达状态，授权流程语义待定 | F6/F9 | 边界候选 |
| #85 | Unreachable states and don't-care transitions in FSM | 边界 | 边界 | FSM robustness | FSM 不可达/不关心转移可能破坏安全状态 | F6/F9 | 边界候选 |
| #86 | Unreachable states and don't-care transitions in FSM | 边界 | 边界 | FSM robustness | FSM 不可达/不关心转移可能破坏安全状态 | F6/F9 | 边界候选 |
| #87 | Unreachable states and don't-care transitions in FSM | 边界 | 边界 | FSM robustness | FSM 不可达/不关心转移可能破坏安全状态 | F6/F9 | 边界候选 |
| #88 | Unspecified behavior of HMAC/SHA256 I/O memory map interface | 是 | 是 | memory map / crypto IO | crypto I/O memory map 未定义行为导致访问语义不确定 | F2/F5 | 候选 |
| #89 | Power side channel on binary modular exponentiation module | 边界 | 否 | side channel | 功耗侧信道，权限交互不明显 | 无 | 边界候选 |
| #90 | Power side channel in RSA core leaks private exponent | 边界 | 否 | RSA side channel | RSA 私钥经功耗侧信道泄露 | 无 | 边界候选 |
| #91 | No bound checks are performed before function call in bootrom | 是 | 边界 | BootROM / bounds | BootROM 调用前缺少边界检查 | F5 | 候选 |
| #92 | Integer overflow in bootrom | 边界 | 边界 | BootROM / integer overflow | BootROM 整数溢出可能破坏保护边界 | F5/F6 | 边界候选 |
| #93 | Integer overflow in bootrom | 边界 | 边界 | BootROM / integer overflow | BootROM 整数溢出可能破坏保护边界 | F5/F6 | 边界候选 |
| #94 | Integer overflow in bootrom | 边界 | 边界 | BootROM / integer overflow | BootROM 整数溢出可能破坏保护边界 | F5/F6 | 边界候选 |
| #95 | Output message on RSA is not cleared after soft reset | 是 | 是 | RSA / reset / state residue | soft reset 后 RSA 输出 message 残留在 memory-mapped area | F10/F4 | 候选 |
| #96 | ROM module is hardcoded | 边界 | 边界 | ROM hardcoding | ROM 固定化可能绕过配置/更新语义 | F4 | 边界候选 |
| #97 | Some registers of HMAC are not reset | 是 | 是 | HMAC / reset residue | HMAC 部分寄存器 reset 后残留 | F10/F4 | 候选 |
| #98 | AES core exposes the keys in debug mode | 是 | 是 | AES / debug / secret | debug mode 下 AES key 暴露 | F1/F7 | 候选 |
| #99 | CLINT registers are not protected by access control | 是 | 是 | CLINT / access control | CLINT registers 缺少访问 mediation | F1 | 候选 |

## 5. 初筛统计

这是描述级初筛，后续需要用 RTL evidence 复核：

- **候选：** 65 个左右。
- **边界候选：** 33 个左右。
- **暂不纳入：** 1 个。

这里使用“左右”是因为 #63、#69、#70、#91-#94 等 case 是否纳入核心语料高度依赖 RTL evidence 和权限语义解释。

## 6. 优先分析批次

建议优先进入 RTL evidence 分析的 case：

1. **JTAG / debug authorization：** #1, #2, #3, #4, #7, #29, #30, #46, #47, #48, #53, #84, #98
2. **DMA / PMP / syscall：** #11, #25, #31, #45, #52, #54, #55, #56, #57, #64
3. **Register lock / access control：** #31-#35, #42, #43, #48-#50, #72, #75-#81, #99
4. **Privilege / CSR / memory protection：** #18, #21, #27, #41, #73, #74, #88, #91-#94
5. **Secret / crypto state residue：** #13, #15, #28, #36, #39, #46, #47, #59, #60, #83, #95, #97, #98
6. **Reset / lifecycle / state consistency：** #24, #29, #35, #42, #65-#67, #72, #95, #97

## 7. 与 2018/2019 的初步对照

2021 与 2018、2019 重复出现的开放编码现象包括：

- debug/JTAG 认证状态 reset 后残留、未初始化或被绕过。
- register lock 默认关闭、未覆盖关键寄存器、可被 JTAG/reset/chicken bits 破坏。
- DMA/PMP/syscall 之间的权限检查不完整、范围检查不足或 TOCTOU。
- secret/key/internal data 在 debug、reset、boot、HASH/encryption 后残留或泄露。
- address map / memory-mapped interface / interconnect 暴露 protected resource。
- 测试/配置/chicken bits 对安全状态具有非预期影响。

这些重复现象应作为后续 v0.3 特征候选的主要来源。
