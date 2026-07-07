{
  "analysis_summary": "A thorough RTL security analysis was performed on the fc_core security scope, covering the FC subsystem (fc_subsystem.sv, fc_demux.sv, fc_hwpe.sv), the zero-riscy RISC-V core (zeroriscy_core.sv, zeroriscy_cs_registers.sv, zeroriscy_controller.sv, zeroriscy_decoder.sv, zeroriscy_debug_unit.sv, zeroriscy_id_stage.sv), the APB interrupt controller (apb_interrupt_cntrl.sv), define files, and interface definitions. Five distinct permission-related security vulnerabilities were identified spanning: (1) hardcoded supervisor_mode_o signal, (2) discarded secure IRQ signal, (3) hardcoded core_secure_mode_i to 0, (4) missing privilege-level enforcement in CSR writes (mstatus.mpp always forced to M-mode on write but no privilege gating), and (5) the MRET instruction not validating or restoring privilege level from mpp (mpp field is always hardwired to PRIV_LVL_M regardless of what the software wrote).",
  "findings": [
    {
      "finding_id": "FIND-001",
      "status": "confirmed_finding",
      "summary": "supervisor_mode_o is hardcoded to 1'b1, permanently asserting supervisor mode regardless of actual core privilege state",
      "vulnerability_category": "Hardcoded Privilege Level / Missing Dynamic Privilege Tracking",
      "affected_locations": [
        {
          "file": "ips/pulp_soc/rtl/fc/fc_subsystem.sv",
          "line_start": 44,
          "line_end": 44,
          "module": "fc_subsystem",
          "signal_or_register": "supervisor_mode_o"
        },
        {
          "file": "ips/pulp_soc/rtl/fc/fc_subsystem.sv",
          "line_start": 273,
          "line_end": 273,
          "module": "fc_subsystem",
          "signal_or_register": "supervisor_mode_o"
        }
      ],
      "evidence": [
        {
          "file": "ips/pulp_soc/rtl/fc/fc_subsystem.sv",
          "line_start": 273,
          "line_end": 273,
          "module": "fc_subsystem",
          "object": "supervisor_mode_o",
          "evidence_type": "hardcoded_assignment",
          "description": "assign supervisor_mode_o = 1'b1; — the supervisor mode output is statically tied to logic 1 regardless of the current privilege level of the running core. Any downstream logic consuming this signal will perpetually believe the core is in supervisor mode.",
          "supports_claim": "No actual privilege state from the core is reflected in this output; it is a constant."
        }
      ],
      "reasoning_summary": "The fc_subsystem module declares a port `supervisor_mode_o` that is intended to communicate the current privilege level of the FC core to the rest of the SoC. Instead of being driven by the core's actual privilege-level state (e.g., from the CSR register mstatus.mpp or a dedicated privilege output), it is assigned the constant 1'b1. This means any SoC peripheral, memory protection unit, or bus infrastructure that gates access on this signal will always grant supervisor-level access, even when the core is executing unprivileged user code.",
      "security_impact": "Any memory protection or access control logic downstream that uses supervisor_mode_o to gate privileged resource access is permanently bypassed. Unprivileged code running on the FC core will be treated as supervisor-level code by the rest of the SoC, enabling unauthorized access to protected memory regions, peripherals, or system resources.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact downstream consumers of supervisor_mode_o are not present in the analyzed scope. If no downstream logic checks this signal, the impact is mitigated, but the port name strongly implies it was designed to gate privileged access.",
      "recommended_follow_up": [
        "Identify all downstream modules consuming supervisor_mode_o and determine what access gates they control.",
        "Replace the hardcoded assignment with a connection to the core's actual privilege-level output or to mstatus.mpp from zeroriscy_cs_registers.",
        "Add an assertion that supervisor_mode_o tracks the actual privilege mode of the CPU."
      ]
    },
    {
      "finding_id": "FIND-002",
      "status": "confirmed_finding",
      "summary": "Secure IRQ output (core_irq_sec_o) from apb_interrupt_cntrl is left unconnected in fc_subsystem, discarding security interrupt classification",
      "vulnerability_category": "Unconnected Security Signal / Missing Secure Interrupt Routing",
      "affected_locations": [
        {
          "file": "ips/pulp_soc/rtl/fc/fc_subsystem.sv",
          "line_start": 288,
          "line_end": 288,
          "module": "fc_subsystem",
          "signal_or_register": "core_irq_sec_o"
        },
        {
          "file": "ips/pulp_soc/rtl/fc/fc_subsystem.sv",
          "line_start": 53,
          "line_end": 53,
          "module": "fc_subsystem",
          "signal_or_register": "core_irq_sec"
        }
      ],
      "evidence": [
        {
          "file": "ips/pulp_soc/rtl/fc/fc_subsystem.sv",
          "line_start": 288,
          "line_end": 288,
          "module": "fc_subsystem",
          "object": "core_irq_sec_o",
          "evidence_type": "unconnected_port",
          "description": ".core_irq_sec_o ( /* SECURE IRQ */ ) — the secure IRQ output from the APB interrupt controller is explicitly commented as 'SECURE IRQ' but left unconnected (open port).",
          "supports_claim": "The signal that would indicate a secure vs. non-secure interrupt is dropped, so the core (riscv_core) receives irq_sec_i=1'b0 always."
        },
        {
          "file": "ips/pulp_soc/rtl/fc/fc_subsystem.sv",
          "line_start": 201,
          "line_end": 201,
          "module": "fc_subsystem",
          "object": "irq_sec_i",
          "evidence_type": "hardcoded_assignment",
          "description": ".irq_sec_i ( 1'b0 ) — the riscv_core's secure interrupt input is hardwired to 0, so all interrupts appear as non-secure regardless of their actual classification.",
          "supports_claim": "Secure interrupts are indistinguishable from non-secure interrupts at the core level."
        },
        {
          "file": "ips/pulp_soc/rtl/fc/fc_subsystem.sv",
          "line_start": 53,
          "line_end": 53,
          "module": "fc_subsystem",
          "object": "core_irq_sec",
          "evidence_type": "declared_but_undriven",
          "description": "logic core_irq_sec is declared but never assigned from core_irq_sec_o.",
          "supports_claim": "Infrastructure for secure interrupt signaling was planned but is non-functional."
        }
      ],
      "reasoning_summary": "The apb_interrupt_cntrl module produces a core_irq_sec_o signal (parameterized by ENA_SEC_IRQ=1, meaning it is enabled) that is designed to classify an interrupt as secure or non-secure. In fc_subsystem, this output is left unconnected. Additionally, the riscv_core's irq_sec_i port is hardwired to 1'b0. This means that even if the interrupt controller identifies a secure interrupt, this information is permanently lost before it reaches the processor core, so the core cannot take the interrupt in secure (M-mode) context as intended.",
      "security_impact": "Security-sensitive interrupt sources cannot be routed to the processor with their secure classification. This can enable lower-privilege interrupt handlers to process interrupts intended for the secure (machine-mode) handler, potentially leading to information disclosure or privilege escalation through interrupt handler manipulation.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact interrupt sources designated as 'secure' in the system are not visible in this scope. The impact magnitude depends on what events trigger the secure IRQ. The riscv_core (non-zero-riscy path) irq_sec_i behavior is not fully analyzable from the truncated file.",
      "recommended_follow_up": [
        "Connect core_irq_sec_o from apb_interrupt_cntrl to the declared core_irq_sec signal and route it to irq_sec_i of riscv_core.",
        "Audit which interrupt IDs trigger a secure IRQ in apb_interrupt_cntrl.",
        "Verify the riscv_core's secure interrupt handling path is fully implemented."
      ]
    },
    {
      "finding_id": "FIND-003",
      "status": "confirmed_finding",
      "summary": "core_secure_mode_i to apb_interrupt_cntrl is hardcoded to 0, disabling any secure-mode-aware interrupt masking",
      "vulnerability_category": "Hardcoded Security Mode / Missing Secure Mode Propagation",
      "affected_locations": [
        {
          "file": "ips/pulp_soc/rtl/fc/fc_subsystem.sv",
          "line_start": 283,
          "line_end": 283,
          "module": "fc_subsystem",
          "signal_or_register": "core_secure_mode_i"
        }
      ],
      "evidence": [
        {
          "file": "ips/pulp_soc/rtl/fc/fc_subsystem.sv",
          "line_start": 283,
          "line_end": 283,
          "module": "fc_subsystem",
          "object": "core_secure_mode_i",
          "evidence_type": "hardcoded_assignment",
          "description": ".core_secure_mode_i ( 1'b0 ) — the secure mode indication to the interrupt controller is permanently set to 'not secure', meaning the interrupt controller can never adapt its behavior based on the core's actual security mode.",
          "supports_claim": "The apb_interrupt_cntrl module has a core_secure_mode_i port intended to allow mode-dependent interrupt control, but it is always 0."
        },
        {
          "file": "ips/apb_interrupt_cntrl/apb_interrupt_cntrl.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "apb_interrupt_cntrl",
          "object": "core_secure_mode_i",
          "evidence_type": "port_declaration",
          "description": "input logic core_secure_mode_i — the interrupt controller declares a port for the core's secure mode status, intended to control secure-mode-aware interrupt routing.",
          "supports_claim": "The port exists and is not used internally either, but tying it to 0 prevents any future secure-mode gating from working."
        }
      ],
      "reasoning_summary": "apb_interrupt_cntrl declares core_secure_mode_i to receive the running security mode of the core. The interrupt controller may use this to mask or prioritize interrupts based on the core's current privilege/security mode. By hardwiring this to 0, the interrupt controller always operates as if the core is in non-secure mode. Combined with FIND-001 (supervisor_mode_o=1) and FIND-002 (irq_sec=0), a pattern of systematic disabling of security primitives is evident.",
      "security_impact": "If the interrupt controller uses core_secure_mode_i to gate which interrupts can fire or to route them differently (e.g., only delivering certain IRQs when in secure mode), then this hardcoding means those protections are always disabled. Non-secure code could receive interrupts intended only for secure execution contexts.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The apb_interrupt_cntrl.sv source does not show active use of core_secure_mode_i in combinational logic within the visible code (it may be unused internally too). However, the port was clearly designed for this purpose and hardcoding it to 0 prevents any implementation from using it correctly.",
      "recommended_follow_up": [
        "Determine whether apb_interrupt_cntrl uses core_secure_mode_i internally for gating.",
        "Connect core_secure_mode_i to the actual core privilege level signal (e.g., derived from mstatus).",
        "Implement the secure interrupt masking logic in apb_interrupt_cntrl if not already present."
      ]
    },
    {
      "finding_id": "FIND-004",
      "status": "confirmed_finding",
      "summary": "mstatus.mpp field is always forced to PRIV_LVL_M (machine mode) on every write and reset, preventing software-controlled privilege-level restoration via MRET",
      "vulnerability_category": "Privilege Level Escalation via Broken MPP Field / Missing Privilege Downgrade",
      "affected_locations": [
        {
          "file": "ips/zero-riscy/zeroriscy_cs_registers.sv",
          "line_start": 197,
          "line_end": 203,
          "module": "zeroriscy_cs_registers",
          "signal_or_register": "mstatus_n.mpp"
        },
        {
          "file": "ips/zero-riscy/zeroriscy_cs_registers.sv",
          "line_start": 280,
          "line_end": 300,
          "module": "zeroriscy_cs_registers",
          "signal_or_register": "mstatus_q.mpp"
        }
      ],
      "evidence": [
        {
          "file": "ips/zero-riscy/zeroriscy_cs_registers.sv",
          "line_start": 197,
          "line_end": 203,
          "module": "zeroriscy_cs_registers",
          "object": "mstatus_n.mpp",
          "evidence_type": "hardcoded_field",
          "description": "On CSR write to mstatus (12'h300), mpp is always assigned PrivLvl_t'(PRIV_LVL_M) instead of csr_wdata_int[MSTATUS_MPP_BITS]. Software cannot set mpp to user mode (PRIV_LVL_U).",
          "supports_claim": "Privilege level prior to trap is always recorded as M-mode, so MRET will always return to M-mode regardless of actual pre-trap privilege."
        },
        {
          "file": "ips/zero-riscy/zeroriscy_cs_registers.sv",
          "line_start": 281,
          "line_end": 296,
          "module": "zeroriscy_cs_registers",
          "object": "mstatus_q.mpp",
          "evidence_type": "hardcoded_reset_value",
          "description": "At reset and after update, mpp is always set to PRIV_LVL_M in both the reset block and the update always_ff. Even after trap save, mpp cannot hold U-mode.",
          "supports_claim": "The hardware permanently forces mpp=M; MRET can never return to a lower privilege level, making privilege level downgrade impossible."
        },
        {
          "file": "ips/zero-riscy/zeroriscy_cs_registers.sv",
          "line_start": 227,
          "line_end": 230,
          "module": "zeroriscy_cs_registers",
          "object": "csr_restore_mret_i",
          "evidence_type": "restore_logic",
          "description": "MRET restores mstatus.mie from mpie but does NOT restore a prior privilege level (since mpp is always M). This means the processor never transitions to a lower privilege mode after MRET.",
          "supports_claim": "MRET is broken as a privilege-downgrade mechanism."
        }
      ],
      "reasoning_summary": "In the RISC-V privileged ISA, the mstatus.mpp field records the privilege mode active before a machine-mode trap. When MRET is executed, the hart returns to the privilege mode stored in mpp. In zeroriscy_cs_registers.sv, the write logic for mstatus (CSR address 0x300) always forces mpp to PRIV_LVL_M regardless of what value software attempts to write (line 201: mpp: PrivLvl_t'(PRIV_LVL_M)). Similarly, the register update and reset always write PRIV_LVL_M for mpp. The mpp field is also never saved from the current privilege level at trap entry (no current_priv_lvl input exists). As a result, MRET can never transition the processor to user mode, making the privilege downgrade mechanism non-functional and permanently keeping the processor operating in machine mode.",
      "security_impact": "Software cannot safely drop to user-mode privilege. Any OS or security monitor that relies on MRET to enter user-mode code will instead continue executing in M-mode, giving user-mode code full machine-mode privileges. This completely defeats the RISC-V hardware privilege separation model and allows any code to access all M-mode resources (CSRs, physical memory, devices) without restriction.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The zero-riscy core is a machine-mode-only core and the RISC-V spec permits M-mode-only implementations to hardwire mpp=M. However, since the fc_subsystem instantiates riscv_core (which does support privilege levels, as evidenced by the irq_sec_i port) in the primary code path (generate if(1)), the zero-riscy path with hardcoded mpp is the backup path. The primary riscv_core's CSR behavior is not visible in the analyzed scope.",
      "recommended_follow_up": [
        "If the zero-riscy core is intentionally M-mode-only, document this explicitly and ensure the system architecture does not rely on privilege downgrade through this core.",
        "If lower privilege levels are needed, add a current_priv_lvl register and properly save/restore mpp on trap entry/exit.",
        "Review the riscv_core (primary instantiation) to verify its mpp handling."
      ]
    },
    {
      "finding_id": "FIND-005",
      "status": "confirmed_finding",
      "summary": "CSR decoder does not check or enforce privilege-level gating for CSR accesses — any code can access M-mode CSRs without privilege check",
      "vulnerability_category": "Missing CSR Access Privilege Check / Unprivileged CSR Access",
      "affected_locations": [
        {
          "file": "ips/zero-riscy/zeroriscy_decoder.sv",
          "line_start": 474,
          "line_end": 536,
          "module": "zeroriscy_decoder",
          "signal_or_register": "csr_access_o / csr_illegal"
        }
      ],
      "evidence": [
        {
          "file": "ips/zero-riscy/zeroriscy_decoder.sv",
          "line_start": 524,
          "line_end": 536,
          "module": "zeroriscy_decoder",
          "object": "csr_illegal / csr_access_o",
          "evidence_type": "missing_privilege_check",
          "description": "The OPCODE_SYSTEM decode block validates CSR operation encoding (bits [13:12]) and sets csr_status_o for mstatus accesses, but never checks the CSR address high bits [11:10] against the current privilege level. RISC-V spec requires that CSR addresses with bits[11:10]=11 (read-only) or bits[9:8] indicating required privilege must be gated by current privilege mode. No current_priv_lvl signal is present in the decoder.",
          "supports_claim": "Without a privilege check, user-mode code (if supported) can read/write M-mode CSRs such as mstatus, mepc, mcause, mtvec, mhartid."
        },
        {
          "file": "ips/zero-riscy/zeroriscy_decoder.sv",
          "line_start": 531,
          "line_end": 534,
          "module": "zeroriscy_decoder",
          "object": "csr_status_o",
          "evidence_type": "insufficient_access_control",
          "description": "Only mstatus (0x300) is specially flagged; all other M-mode CSRs (mepc 0x341, mcause 0x342, mtvec 0x305, mhartid 0xF14) are accessible without any privilege level enforcement.",
          "supports_claim": "The CSR address privilege encoding defined in RISC-V spec (bits[9:8] = privilege required) is not decoded."
        }
      ],
      "reasoning_summary": "The RISC-V privileged ISA defines that CSR addresses encode the minimum required privilege level in bits [9:8]. The zeroriscy_decoder's OPCODE_SYSTEM handling checks only whether the CSR operation bits [13:12] are valid (for CSRRW/CSRRS/CSRRC), and specially marks mstatus access. There is no comparison of the CSR address privilege encoding against the current execution privilege level. No current_priv_lvl signal is routed to the decoder. In a strict M-mode-only implementation this is acceptable, but combined with the supervisor_mode_o and irq_sec issues, this confirms there is no privilege enforcement in the memory of these CSRs. Additionally, read-only CSRs (bits[11:10]=11, e.g., 0xF14 mhartid) are not write-protected in the decoder.",
      "security_impact": "In any multi-privilege-level deployment scenario, user-mode code could directly read or modify M-mode control registers (mstatus, mepc, mtvec, mcause), enabling privilege escalation, exception handler hijacking, or denial of service. The missing read-only enforcement on CSR 0xF14 (mhartid) and others is also a correctness issue.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "Zero-riscy is documented as a machine-mode-only core, making this finding less severe in the intended deployment. However, the fc_subsystem instantiates riscv_core (not zero-riscy) in the primary `if(1)` generate branch, so zero-riscy is only used in the else branch. The actual instantiated core (riscv_core) CSR enforcement is not visible in the analyzed scope. If the zero-riscy path is truly never reached in this configuration, the direct impact is lower.",
      "recommended_follow_up": [
        "Verify which core (riscv_core vs zeroriscy_core) is actually synthesized for the FC subsystem.",
        "If zero-riscy is used, document the M-mode-only constraint explicitly in system security documentation.",
        "Add CSR address privilege-level checks to zeroriscy_decoder if lower privilege modes are ever intended to be supported.",
        "Enforce read-only protection for CSRs with bits[11:10]=11."
      ]
    }
  ],
  "no_finding_reason": "Findings were identified; this field is not applicable.",
  "global_uncertainty": "1. The primary core instantiated in fc_subsystem is riscv_core (via generate if(1)), not zeroriscy_core — the riscv_core RTL source is not present in the analyzed scope, so its CSR privilege enforcement and interrupt security handling cannot be fully evaluated. 2. Downstream consumers of supervisor_mode_o are outside the analyzed scope, so the full impact of FIND-001 depends on unseen logic. 3. The zero-riscy core is documented as M-mode-only; FIND-004 and FIND-005 may be intentional design choices for that core but are still security risks if the system ever supports user-mode software. 4. The apb_interrupt_cntrl module's internal use of core_secure_mode_i is not exercised in visible combinational logic, so it is possible the port is unused and the hardcoding has no current effect."
}