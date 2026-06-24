# Hack@DAC 2019 完整映射工作表

> Phase 2 子任务文档，版本 v0.1，2026-05-12。

## 1. 口径说明

本文档是 Hack@DAC 2019 Ariane SoC 全部 66 个 inserted bugs 的描述级初筛入口。

表中的 `v0.2 参考标签` 只表示与早期特征草稿 F1-F10 的参考性相似关系，不代表最终分类，也不作为 case 纳入或排除依据。后续复核每个 case 时，应先补 RTL evidence，再讨论它对旧 F1-F10 的影响。

## 2. 来源

- GitHub 仓库：`https://github.com/HACK-EVENT/hackatdac19`
- Bug list 页面：`https://hackthesilicon.com/dac19-setup/`
- 设计对象：Ariane SoC
- 本地浅克隆：`tmp/hackatdac19`

## 3. 状态定义

- **候选：** 与权限相关，且可能涉及跨模块 / inter-IP / 跨控制域交互。
- **边界候选：** 与安全或权限有一定关系，但是否符合本课题范围需要 RTL 证据确认。
- **暂不纳入：** 当前描述更像纯功能、DoS、算法强度、可用性或与权限交互关系较弱的问题。

## 4. 全量描述级初筛

| Bug ID | 原始描述 | 是否权限相关 | 是否跨模块 | 初始类别 | 开放编码现象（待复核） | v0.2 参考标签 | 纳入状态 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| #1 | Processor access to CLINT grants it access to PLIC regardless of PLIC access configuration | 是 | 是 | access control / interrupt controller | 访问一个受控外设时错误获得另一个外设访问能力 | F1/F7 | 候选 |
| #2 | Peripherals can be disabled by the user | 是 | 边界 | peripheral control | 低权限 requester 可修改外设可用性/控制状态 | F1/F8 | 候选 |
| #3 | UART cannot be accessed even from Machine mode | 边界 | 边界 | over-restrictive access control | 高权限 requester 被错误拒绝，反映权限状态与资源访问不一致 | F9 | 边界候选 |
| #4 | DMA can write to inaccessible regions if privilege level changed during the DMA read | 是 | 是 | DMA / privilege / TOCTOU | DMA 操作跨周期使用过期或不一致的权限状态 | F6/F9 | 候选 |
| #5 | Incorrect access control setting leaving debug enabled | 是 | 是 | debug authorization | debug enable 安全状态配置错误导致调试能力暴露 | F1/F8 | 候选 |
| #6 | Access control registers can be accessed behind the register locks | 是 | 是 | register lock / access control | lock 保护后的控制寄存器仍存在绕过访问路径 | F5/F1 | 候选 |
| #7 | DMA can be used to access unprivileged registers | 是 | 是 | DMA / register access | DMA requester 获得普通软件不应拥有的寄存器访问能力 | F1/F7 | 候选 |
| #8 | PLIC registers are not protected by access control | 是 | 是 | interrupt controller / access control | 中断控制寄存器缺少访问 mediation | F1 | 候选 |
| #9 | Execute machine level instructions from user mode | 是 | 边界 | privilege enforcement | 用户态执行流未受特权级检查约束 | F1 | 候选 |
| #10 | AES key stored in an unprotected register | 是 | 是 | crypto key / protected register | secret key 被放入缺少访问保护的寄存器资源 | F1/F7 | 候选 |
| #11 | AES internal registers are visible externally | 是 | 是 | crypto internal state exposure | 加密模块内部状态通过外部接口暴露 | F7 | 候选 |
| #12 | Constant initial vector used for AES | 边界 | 否 | crypto configuration | 加密配置固定化导致安全弱化，但权限交互不明显 | 无 | 边界候选 |
| #13 | Counter register in AES CTR mode does not increase | 边界 | 否 | crypto functional/security | CTR 状态更新失败导致加密语义错误 | F4 | 边界候选 |
| #14 | Crypto oracle for encrypt/decrypt is exposed to unprivileged applications | 是 | 是 | crypto oracle / privilege | 低权限软件可调用受保护加解密 oracle | F1/F7 | 候选 |
| #15 | AES key is hard coded | 是 | 边界 | hardcoded secret | secret 由固定值驱动，绕过安全配置/生命周期 | F4/F10 | 边界候选 |
| #16 | SHA is not properly checked during Boot test | 边界 | 是 | boot integrity | boot 阶段完整性检查 mediation 不完整 | F5/F6 | 候选 |
| #17 | Bootrom can be corrupted by user mode applications | 是 | 是 | boot ROM / write protection | 用户态写路径破坏 boot 受保护资源 | F1/F7 | 候选 |
| #18 | Address range overlap between a protected register file and an unprotected peripheral | 是 | 是 | address map / protected register | 地址空间重叠使非受保护外设路径触达 protected register | F2/F7 | 候选 |
| #19 | CPU halts when writing to undefined address location | 否 | 边界 | availability / undefined address | 未定义地址访问导致 halt，更像可用性/功能问题 | 无 | 暂不纳入 |
| #20 | Access to CSRs from lower privilege level | 是 | 边界 | CSR / privilege | 低权限 requester 可访问高权限 CSR | F1 | 候选 |
| #21 | Receive CSR interrupts when committing atomic instructions | 边界 | 边界 | CSR / interrupt / atomic | 原子指令提交与 CSR interrupt 状态耦合异常 | F6/F9 | 边界候选 |
| #22 | Commit the second instruction even if the first is atomic instruction | 边界 | 否 | pipeline / atomic | 原子指令提交顺序错误，权限语义不明显 | 无 | 暂不纳入 |
| #23 | Pipeline not flushed after committing an atomic instruction | 边界 | 否 | pipeline / atomic | pipeline 状态未清理，可能造成状态残留但权限语义待定 | F10 | 边界候选 |
| #24 | SATP register (read) accessible in Supervisor mode even if TVM is enabled | 是 | 边界 | CSR / virtual memory privilege | TVM 安全状态未约束 SATP read | F1/F6 | 候选 |
| #25 | SATP register (write) accessible in Supervisor mode even if TVM is enabled | 是 | 边界 | CSR / virtual memory privilege | TVM 安全状态未约束 SATP write | F1/F6 | 候选 |
| #26 | Pipeline not flushed after change in virtual address translation mode | 是 | 边界 | MMU / translation state | 地址翻译模式切换后旧 pipeline 状态残留 | F10/F4 | 候选 |
| #27 | RTC is using wrong clock input | 边界 | 边界 | clock / timing | 安全相关时间源可能被错误时钟驱动 | 待定 | 边界候选 |
| #28 | Same cycle counter used for both CSR mcycle and cycle | 边界 | 边界 | CSR counter | 不同权限视图共享同一 counter，可能破坏隔离 | F8/F9 | 边界候选 |
| #29 | Instruction retired counters are updated in non-debug mode | 边界 | 边界 | debug / counter | debug 状态与性能计数器更新条件不一致 | F6/F9 | 边界候选 |
| #30 | IRQ source input badly connected | 边界 | 是 | interrupt wiring | 中断源连接错误导致安全/权限事件路由异常 | F7/F9 | 边界候选 |
| #31 | SoC uses asynchronous resets | 边界 | 是 | reset / CDC | 异步 reset 可能造成安全状态跨模块不一致 | F3/F4 | 边界候选 |
| #32 | Exception signal is not set at halt | 边界 | 边界 | halt / exception | halt 状态下异常信号丢失，可能影响 debug/exception mediation | F6/F9 | 边界候选 |
| #33 | Fan speed can be controlled from unprivileged application | 是 | 是 | peripheral control | 低权限软件控制受保护/安全相关外设状态 | F1/F7 | 候选 |
| #34 | Timing register can be accessed from lower privilege level | 是 | 边界 | timing register / privilege | 低权限 requester 可访问受保护 timing register | F1 | 候选 |
| #35 | Multiple signal drivers in interrupt handling | 边界 | 是 | interrupt signal integrity | 多驱动导致 interrupt 安全状态来源不唯一 | F7/F9 | 边界候选 |
| #36 | System functions can be overwritten by underprivileged applications | 是 | 是 | system function / write protection | 低权限写路径覆盖系统函数入口或内容 | F1/F7 | 候选 |
| #37 | Assignment to an incorrect literal value leads to incorrect memory size | 边界 | 边界 | memory size configuration | 内存尺寸配置错误可能影响保护边界 | F2 | 边界候选 |
| #38 | Traps due to usage fault and system calls have same priority in trap handler | 边界 | 边界 | trap priority | trap handler 中安全事件优先级混淆 | F6/F9 | 边界候选 |
| #39 | Data from previous DMA transfer can be copied by giving undefined read address location | 是 | 是 | DMA / state residue | 未定义地址触发 previous DMA data 残留泄露 | F10/F7 | 候选 |
| #40 | DMA will cause huge amount of bus traffic if start and clear bits are set at the same time | 边界 | 是 | DMA / bus DoS | DMA 控制位组合导致总线异常流量，权限语义弱 | F6 | 边界候选 |
| #41 | DRAM memory region is fully accessible from lower privilege level | 是 | 是 | memory protection | 低权限 requester 可访问完整 DRAM region | F1/F7 | 候选 |
| #42 | The implementation of strcmp system call is not constant in time | 边界 | 否 | timing side channel | 系统调用时间侧信道，跨模块权限语义不明显 | 无 | 边界候选 |
| #43 | Protected memory regions can be accessed through system call address pointer arguments | 是 | 是 | syscall / protected memory | system call 指针参数绕过 protected memory mediation | F1/F5 | 候选 |
| #44 | AES key stored in memory at bootup and is not cleared before exiting from firmware setup | 是 | 是 | boot / secret residue | boot 阶段 secret 未清除，后续权限阶段可见 | F10/F4 | 候选 |
| #45 | Secure registers are accessible via AXI | 是 | 是 | AXI / secure register | AXI interconnect 暴露 secure register 访问路径 | F1/F7 | 候选 |
| #46 | Jtag reference password port is not driven | 是 | 是 | JTAG authorization | JTAG password reference 信号未可靠驱动 | F4/F5 | 候选 |
| #47 | Some JTAG instructions can be accessed without password | 是 | 是 | JTAG authorization | 部分 JTAG operation 缺少 password mediation | F1/F5 | 候选 |
| #48 | Unlocking JTAG sets the processor privilege level to Machine mode | 是 | 是 | JTAG / privilege transition | debug unlock 直接提升 processor privilege | F1/F10 | 候选 |
| #49 | JTAG password is only 32 bits | 是 | 边界 | JTAG authorization strength | JTAG authentication 粒度/强度不足 | F5 | 候选 |
| #50 | Authorized debugs can access FUSE memory | 是 | 是 | debug / fuse | debug 授权域过宽，可触达 fuse protected resource | F1/F7 | 候选 |
| #51 | JTAG password flag not reset properly | 是 | 是 | JTAG / reset / state residue | JTAG authentication 状态 reset 后残留 | F10/F4 | 候选 |
| #52 | JTAG reset uninitialized | 是 | 是 | JTAG / reset | JTAG reset 状态未初始化，授权状态不确定 | F4 | 候选 |
| #53 | Debug module does not reset on a system reset | 是 | 是 | debug / reset | system reset 未同步清理 debug module 状态 | F4/F10 | 候选 |
| #54 | JTAG key is hardcoded | 是 | 边界 | JTAG secret | debug authentication secret 固定化 | F4/F10 | 候选 |
| #55 | JTAG not temporarily disabled after several continuous wrong password attempts | 是 | 是 | JTAG authorization policy | 认证失败策略缺失，debug mediation 不完整 | F5/F6 | 候选 |
| #56 | Secondary Reset Control through Debug exposed to SW | 是 | 是 | debug / reset control | debug reset 控制路径暴露给软件 requester | F1/F7 | 候选 |
| #57 | JTAG password input can be a high impedance state | 是 | 边界 | JTAG signal integrity | password 输入可处于高阻态，认证语义不确定 | F4/F5 | 候选 |
| #58 | Register locks can be reprogrammed after boot-up | 是 | 是 | register lock / lifecycle | boot 后 lock 状态仍可被重编程 | F4/F5 | 候选 |
| #59 | Register locks can be reset by triggering software reset through JTAG | 是 | 是 | JTAG / reset / register lock | JTAG-triggered reset 清除 register lock 保护 | F4/F10 | 候选 |
| #60 | DMA registers are not locked | 是 | 是 | DMA / register lock | DMA 控制寄存器缺少 lock mediation | F1/F5 | 候选 |
| #61 | UART registers are not locked | 是 | 边界 | UART / register lock | UART 控制寄存器缺少 lock mediation | F1/F5 | 候选 |
| #62 | Reg locks are disabled by default when reset | 是 | 是 | reset / register lock | reset 默认状态关闭 register lock | F4/F10 | 候选 |
| #63 | Incorrect register lock settings for Access control registers | 是 | 是 | register lock / access control | access-control registers 的 lock 设置错误 | F5/F9 | 候选 |
| #64 | SHA input data not cleared after HASH computation | 是 | 是 | SHA / state residue | HASH 后输入数据残留并可能被后续读取 | F10 | 候选 |
| #65 | Intermediate values of SHA are leaked | 是 | 是 | SHA / internal state leakage | SHA 中间状态通过接口或状态残留泄露 | F7/F10 | 候选 |
| #66 | The SHA wrapper uses non-blocking assignment for variables which can cause timing issues | 边界 | 边界 | SHA / timing | wrapper 时序语义错误可能造成安全状态采样异常 | F3/F6 | 边界候选 |

## 5. 初筛统计

- **候选：** 45 个。
- **边界候选：** 19 个。
- **暂不纳入：** 2 个。

该统计是描述级结果，不是最终语料统计。后续 RTL evidence 分析可能改变纳入状态。

## 6. 优先分析批次

建议优先进入 RTL evidence 分析的 case：

1. **DMA / memory protection / privilege：** #4, #7, #39, #40, #60
2. **Debug / JTAG authorization：** #5, #46, #47, #48, #49, #50, #51, #52, #53, #54, #55, #56, #57, #59
3. **Register lock / access control：** #6, #58, #62, #63
4. **CSR / privilege / virtual memory：** #9, #20, #24, #25, #26, #34
5. **Address map / AXI / protected resource：** #1, #18, #41, #43, #45
6. **Secret / crypto state residue：** #10, #11, #14, #44, #64, #65

## 7. 与 2018 的初步对照

2019 与 2018 重复出现的开放编码现象包括：

- debug/JTAG 授权状态未被完整 mediation 或 reset。
- register lock 本身可被改写、reset 或绕过。
- 低权限 requester 通过 DMA、AXI、system call 或地址映射触达 protected resource。
- secret/key/internal state 在跨阶段或跨接口中残留/暴露。
- privilege/CSR/security state 与实际访问检查不一致。

这些重复现象后续应优先用于反推 v0.3 特征框架。
