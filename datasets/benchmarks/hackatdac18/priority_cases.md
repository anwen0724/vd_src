# Hack@DAC18 Priority Cases v0.1

日期：2026-05-25

## 1. 目的

本文档记录 Hack@DAC18 第一批 priority cases，用于后续建立 case-level hidden GT、evidence-level GT 和 baseline pilot 评分规则。

该文件属于 hidden GT，不应出现在任何 agent input 中。

## 2. 选择原则

第一批 priority cases 不是最终全量 benchmark，而是用于跑通：

```text
case-level GT
  -> evidence-level GT
  -> sanitized input scope
  -> agent output
  -> evaluator matching
```

优先选择满足以下条件的 case：

- 描述级上与权限、特权、debug authorization、锁、寄存器保护、secure mode 或访问路径相关；
- 能覆盖不同权限失败语义；
- 源码中存在较明确的候选文件或候选模块，便于后续 RTL evidence 复核；
- 适合组合成 subsystem-like 或 IP-like agent input；
- 不需要一开始就依赖完整仿真或复杂形式化工具。

## 3. 第一批 Priority Cases

| case_id | 官方描述摘要 | 初始类别 | 选择原因 | 候选 input scope |
|---|---|---|---|---|
| H18-004 | GPIO lock control register can be written by software | lock/write_protection | 典型寄存器保护/锁失效，适合验证 agent 是否能识别软件写路径与 lock 语义。 | `gpio_peripheral_scope` |
| H18-005 | Reset clears GPIO lock control register | reset/lock_lifecycle | 覆盖 reset 与保护状态生命周期交互。 | `gpio_peripheral_scope` |
| H18-009 | Incorrect password checking logic in debug unit | debug_authorization | 覆盖 debug authentication guard。 | `debug_subsystem_scope` |
| H18-010 | Debug unit only checks 31 of 32 password bits | debug_authorization/partial_check | 覆盖部分比较/不完整授权检查，易观察 evidence 是否足够具体。 | `debug_subsystem_scope` |
| H18-012 | Debug password check does not reset after successful check | debug_authorization/state_residue | 覆盖授权状态残留和状态机复位问题。 | `debug_subsystem_scope` |
| H18-025 | Unprivileged user-space code can write privileged CSR | privilege/CSR | 直接匹配特权级与 CSR 写权限调解失败。 | `core_privilege_scope` |
| H18-027 | Secure mode not required to write interrupt registers | secure_mode/interrupt_register | 覆盖 secure mode 与 protected register write 关系。 | `interrupt_security_scope` |
| H18-028 | JTAG interface is not password protected | debug_authorization/external_interface | 覆盖外部 debug interface 未授权访问路径。 | `jtag_debug_scope` |

## 4. Reserve Cases

以下 case 暂不进入第一批 skeleton，但适合作为第二批或扩展实验候选：

| case_id | 原因 |
|---|---|
| H18-006 | APB address range memory aliasing，适合后续 bus/address-decode 类 input scope。 |
| H18-007 | AXI decoder ignores errors，适合后续 bus error handling / invalid access path。 |
| H18-008 | GPIO/SPI/SoC control address overlap，适合后续 peripheral isolation 类测试。 |
| H18-020 | AES key stored in unprotected memory，适合后续 protected asset / memory protection 类测试。 |
| H18-031 | GPIO read/write instruction/data cache，适合后续 peripheral-to-cache access path。 |

## 5. 当前状态

当前完成的是 priority selection 和 case skeleton 初始化。

已完成 RTL evidence 复核：

- H18-004：`rtl_confirmed`
- H18-005：`rtl_confirmed`
- H18-009：`rtl_confirmed`
- H18-010：`rtl_confirmed`
- H18-012：`rtl_confirmed`
- H18-025：`rtl_confirmed`
- H18-027：`rtl_confirmed`
- H18-028：`rtl_confirmed`

当前未完成：

- 第一批 priority cases 的 RTL evidence 复核已完成；
- 尚未构造任何 agent input scope；
- 尚未建立 `input_scope_gt_map.csv`。

## 6. 下一步

建议下一步按以下顺序推进：

1. 设计第一个 sanitized input scope；
2. 建立 `input_scope_gt_map.csv`；
3. 定义 baseline run 的输出格式与评分表；
4. 再执行第一轮 agent baseline run。
