{
  "analysis_summary": "Security analysis of the HackATDAC18 GPIO APB subsystem RTL scope identified three permission-related vulnerabilities. The most critical is an AXI PROT signal cross-wire in pulp_soc.sv where the AW (write) channel protection output is driven by the AR (read) channel's prot field and vice versa, silently corrupting privilege/security metadata on every outgoing AXI transaction. A second high-severity vulnerability exists in apb_gpio.sv where the GPIO register lock mechanism (REG_GPIOLOCK) is incomplete: the PADOUTSET and PADOUTCLR registers bypass the output lock entirely, and the lock register itself is freely writable with no sticky/OTP semantics, allowing any bus master to clear and circumvent the lock. A third medium-severity issue arises from overlapping APB address ranges in periph_bus_defines.sv: the GPIO slave range (0x1A10_1000–0x1A10_AFFF) encompasses the UDMA, SOC_CTRL, and EU slave ranges, causing the APB node to assert multiple PSELs simultaneously on transactions to these addresses. The APB node contains no priority arbitration for overlapping selections, so writes to overlapping regions are broadcast to multiple slaves simultaneously and reads return undefined merged data.",
  "findings": [
    {
      "finding_id": "FIND-001",
      "status": "confirmed_finding",
      "summary": "AXI AWPROT and ARPROT signals are cross-wired on the data master output port: the write-channel protection output (data_master_aw_prot_o) is driven by the read-channel's internal prot field (s_data_master.ar_prot), and the read-channel protection output (data_master_ar_prot_o) is driven by the write-channel's internal prot field (s_data_master.aw_prot). This silently swaps AXI privilege and security attributes on every outgoing transaction.",
      "vulnerability_category": "AXI Protection Signal Misrouting (Privilege/Security Attribute Swap)",
      "affected_locations": [
        {
          "file": "ips/pulp_soc/rtl/pulp_soc/pulp_soc.sv",
          "line_start": 840,
          "line_end": 840,
          "module": "pulp_soc",
          "signal_or_register": "data_master_aw_prot_o"
        },
        {
          "file": "ips/pulp_soc/rtl/pulp_soc/pulp_soc.sv",
          "line_start": 854,
          "line_end": 854,
          "module": "pulp_soc",
          "signal_or_register": "data_master_ar_prot_o"
        }
      ],
      "evidence": [
        {
          "file": "ips/pulp_soc/rtl/pulp_soc/pulp_soc.sv",
          "line_start": 840,
          "line_end": 840,
          "module": "pulp_soc",
          "object": "data_master_aw_prot_o assignment",
          "evidence_type": "incorrect_signal_assignment",
          "description": "Line 840: 'assign data_master_aw_prot_o = s_data_master.ar_prot;' — the AW (write address) channel protection output is driven by the AR (read address) channel's internal prot field instead of s_data_master.aw_prot.",
          "supports_claim": "Confirms the write-channel PROT output carries read-channel protection attributes, swapping privilege/security bits for write transactions."
        },
        {
          "file": "ips/pulp_soc/rtl/pulp_soc/pulp_soc.sv",
          "line_start": 854,
          "line_end": 854,
          "module": "pulp_soc",
          "object": "data_master_ar_prot_o assignment",
          "evidence_type": "incorrect_signal_assignment",
          "description": "Line 854: 'assign data_master_ar_prot_o = s_data_master.aw_prot;' — the AR (read address) channel protection output is driven by the AW (write address) channel's internal prot field instead of s_data_master.ar_prot.",
          "supports_claim": "Confirms the read-channel PROT output carries write-channel protection attributes, swapping privilege/security bits for read transactions."
        },
        {
          "file": "ips/pulp_soc/rtl/pulp_soc/pulp_soc.sv",
          "line_start": 787,
          "line_end": 801,
          "module": "pulp_soc",
          "object": "slave-side PROT unpacking (reference correct pattern)",
          "evidence_type": "correct_reference_pattern",
          "description": "Lines 787 and 801 show the correct symmetric pattern on the slave side: 'assign s_data_slave.aw_prot = data_slave_aw_prot_i' and 'assign s_data_slave.ar_prot = data_slave_ar_prot_i'. The master-side output breaks this symmetry.",
          "supports_claim": "Demonstrates the expected aw→aw / ar→ar mapping convention used throughout the same file, confirming the master-side assignments at lines 840 and 854 are defects."
        },
        {
          "file": "ips/pulp_soc/rtl/pulp_soc/pulp_soc.sv",
          "line_start": 56,
          "line_end": 69,
          "module": "pulp_soc",
          "object": "port declarations for PROT signals",
          "evidence_type": "port_declaration",
          "description": "Ports data_slave_aw_prot_i [2:0] (line 56) and data_slave_ar_prot_i [2:0] (line 69) are separate inputs; data_master_aw_prot_o [2:0] (line 102) and data_master_ar_prot_o [2:0] (line 115) are separate outputs. AXI PROT[2:0] encodes privilege (bit 0), secure (bit 1), and instruction/data (bit 2) per the AXI4 specification.",
          "supports_claim": "Confirms aw_prot and ar_prot are intentionally distinct and independently significant; swapping them silently misrepresents transaction security attributes to downstream slaves."
        }
      ],
      "reasoning_summary": "In AXI4, each transaction channel (AW and AR) carries an independent PROT[2:0] field encoding the privilege level, secure vs. non-secure, and data vs. instruction nature of the transaction. The pulp_soc module correctly receives separate aw_prot and ar_prot on its slave port and correctly routes them into the internal bus matrix. However, at the master output port (lines 840 and 854), the two PROT signals are crossed: data_master_aw_prot_o is assigned from s_data_master.ar_prot and data_master_ar_prot_o is assigned from s_data_master.aw_prot. Every write transaction exiting the SoC will carry the privilege/security attributes of the most recent read transaction, and vice versa. Downstream AXI protection filters, TrustZone controllers, or MPUs that base access control decisions on PROT will receive corrupted attributes, making it impossible to enforce correct privilege-level or secure/non-secure access control on outgoing bus transactions.",
      "security_impact": "An unprivileged or non-secure write transaction may be tagged with the PROT value of a prior privileged or secure read transaction, causing a downstream access-control filter to grant access it should deny — effectively privilege escalation on write. Conversely, a legitimate privileged read may appear unprivileged, causing spurious access denials. In TrustZone-capable systems, the secure-world bit (PROT[1]) can be silently cleared or set on the wrong channel, enabling non-secure software to access secure-world memory through the write channel or causing secure reads to be downgraded to non-secure. This completely undermines the trustworthiness of any hardware protection mechanism that relies on AXI PROT signaling from this SoC.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "It is theoretically possible this swap is intentional for a specific interconnect topology that physically reverses channels; however, no comment, conditional define, or asymmetric topology documentation is present in the scope, and all other signal assignments in the same block follow strict aw→aw / ar→ar symmetry, strongly indicating a copy-paste defect.",
      "recommended_follow_up": [
        "Correct line 840 to: assign data_master_aw_prot_o = s_data_master.aw_prot;",
        "Correct line 854 to: assign data_master_ar_prot_o = s_data_master.ar_prot;",
        "Audit all other signal assignments in the AXI master unpack block (lines 838–884) for similar channel cross-wiring errors.",
        "Verify downstream AXI protection filters and TrustZone controllers receive correct PROT values in a post-fix simulation."
      ]
    },
    {
      "finding_id": "FIND-002",
      "status": "confirmed_finding",
      "summary": "The GPIO register lock mechanism (REG_GPIOLOCK) in apb_gpio.sv is incomplete and bypassable. The PADOUTSET and PADOUTCLR registers modify the GPIO output register (r_gpio_out) without checking the lock bit, bypassing the protection applied to REG_PADOUT. Additionally, the lock register itself (REG_GPIOLOCK) is writable without any protection, allowing any bus master to clear the lock and then freely modify all locked registers.",
      "vulnerability_category": "Incomplete Register Lock / Protection Bypass",
      "affected_locations": [
        {
          "file": "ips/apb/apb_gpio/apb_gpio.sv",
          "line_start": 312,
          "line_end": 315,
          "module": "apb_gpio",
          "signal_or_register": "r_gpio_out (via REG_PADOUTSET / REG_PADOUTCLR)"
        },
        {
          "file": "ips/apb/apb_gpio/apb_gpio.sv",
          "line_start": 324,
          "line_end": 325,
          "module": "apb_gpio",
          "signal_or_register": "r_gpio_lock"
        }
      ],
      "evidence": [
        {
          "file": "ips/apb/apb_gpio/apb_gpio.sv",
          "line_start": 307,
          "line_end": 310,
          "module": "apb_gpio",
          "object": "REG_PADOUT write with lock check",
          "evidence_type": "protected_register_write",
          "description": "Lines 307–310: REG_PADOUT write is gated by r_gpio_lock[2]: 'if(r_gpio_lock[2] == 0) pwdata_l = PWDATA; else pwdata_l = 0; r_gpio_out <= pwdata_l;'. This is the intended protection point for r_gpio_out.",
          "supports_claim": "Establishes that r_gpio_lock[2] is the intended guard for write access to GPIO output state."
        },
        {
          "file": "ips/apb/apb_gpio/apb_gpio.sv",
          "line_start": 312,
          "line_end": 315,
          "module": "apb_gpio",
          "object": "REG_PADOUTSET and REG_PADOUTCLR write — no lock check",
          "evidence_type": "missing_access_control_check",
          "description": "Lines 312–315: 'REG_PADOUTSET: r_gpio_out <= r_gpio_out | PWDATA;' and 'REG_PADOUTCLR: r_gpio_out <= r_gpio_out & ~PWDATA;' — both modify r_gpio_out unconditionally with no check of r_gpio_lock[2].",
          "supports_claim": "Proves that an attacker can use atomic bit-set or bit-clear operations to modify GPIO output register state even when r_gpio_lock[2] is set, completely bypassing the REG_PADOUT lock."
        },
        {
          "file": "ips/apb/apb_gpio/apb_gpio.sv",
          "line_start": 324,
          "line_end": 325,
          "module": "apb_gpio",
          "object": "REG_GPIOLOCK write — no protection",
          "evidence_type": "unprotected_lock_register_write",
          "description": "Lines 324–325: 'REG_GPIOLOCK: r_gpio_lock <= PWDATA;' — the lock register is writable by any APB master without restriction. There is no sticky-lock, OTP, or privilege check.",
          "supports_claim": "Any bus master can write 0 to REG_GPIOLOCK (offset 0x48) to clear all lock bits, then freely modify any locked register. The lock provides no security against a software attacker."
        },
        {
          "file": "ips/apb/apb_gpio/apb_gpio.sv",
          "line_start": 292,
          "line_end": 292,
          "module": "apb_gpio",
          "object": "r_gpio_lock reset value",
          "evidence_type": "register_reset_value",
          "description": "Line 292: 'r_gpio_lock <= 0;' on reset — all lock bits initialize to 0 (unlocked), meaning the lock must be explicitly set after reset to take effect.",
          "supports_claim": "Confirms there is no default-locked state; if the boot sequence is compromised or skipped, all GPIO registers remain unprotected."
        },
        {
          "file": "ips/apb/apb_gpio/apb_gpio.sv",
          "line_start": 316,
          "line_end": 323,
          "module": "apb_gpio",
          "object": "REG_INTEN, REG_INTTYPE0/1, REG_GPIOEN — no lock checks",
          "evidence_type": "missing_access_control_check",
          "description": "Lines 316–323: REG_INTEN, REG_INTTYPE0, REG_INTTYPE1, REG_GPIOEN writes are all unconditional with no lock guard, despite controlling interrupt enables and GPIO enable per-pin.",
          "supports_claim": "Demonstrates that the lock mechanism is inconsistently applied; critical control registers beyond PADDIR and PADOUT are entirely unprotected."
        }
      ],
      "reasoning_summary": "The apb_gpio module implements a 32-bit r_gpio_lock register with selective bit-guards on REG_PADDIR (bit 0) and REG_PADOUT (bit 2) writes, and on REG_PADDIR (bit 0), REG_PADIN (bit 1), and REG_PADOUT (bit 2) reads. However, the register has two fundamental security flaws. First, PADOUTSET (atomic bit-set on r_gpio_out) and PADOUTCLR (atomic bit-clear on r_gpio_out) both unconditionally modify r_gpio_out without checking r_gpio_lock[2], making the PADOUT write-lock trivially bypassable via these alternate write paths. Second, REG_GPIOLOCK itself is unconditionally writable by any APB master; there is no once-written-sticky behavior, no privilege gating, and no hardware enforcement preventing an attacker from clearing the lock before modifying protected registers. The combination means the lock offers no security guarantee against a software adversary with APB access.",
      "security_impact": "An attacker with APB bus access can: (1) directly drive GPIO output pins to arbitrary states using PADOUTSET/PADOUTCLR regardless of the lock state, potentially controlling power rails, external reset lines, RF PA controls, or other security-critical GPIO-driven signals; (2) clear the lock register, then modify GPIO direction (PADDIR) to convert input-only GPIOs to outputs, enabling physical side-channel or fault-injection attacks; (3) disable or redirect GPIO interrupts by freely writing REG_INTEN and REG_INTTYPE0/1, causing denial of security-event notifications. The practical impact depends on which physical signals are connected to GPIO pins, but the missing lock enforcement makes all GPIO-controlled signals vulnerable to software manipulation.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The threat model for the lock register is not documented within the scope; it may have been intended as a soft accidental-write protection rather than a security boundary. However, even under that weaker interpretation, the PADOUTSET/PADOUTCLR bypass is an unambiguous defect because these alternate paths modify the same register that the lock is supposed to protect.",
      "recommended_follow_up": [
        "Add r_gpio_lock[2] checks to REG_PADOUTSET and REG_PADOUTCLR write cases to prevent bypassing the PADOUT lock.",
        "Implement a sticky/write-once semantic for REG_GPIOLOCK: once a lock bit is set to 1, it should only be clearable by a hardware reset (HRESETn), not by a subsequent APB write.",
        "Extend lock bit coverage to REG_INTEN, REG_INTTYPE0, REG_INTTYPE1, REG_GPIOEN, and PADCFG registers if these are intended to be protected.",
        "Consider adding privilege-level gating (if a PPROT signal is available on the APB bus) so that the lock register itself can only be modified by privileged software."
      ]
    },
    {
      "finding_id": "FIND-003",
      "status": "confirmed_finding",
      "summary": "The APB peripheral bus address map in periph_bus_defines.sv defines overlapping address ranges: the GPIO slave range (0x1A10_1000–0x1A10_AFFF) fully encompasses the UDMA (0x1A10_2000–0x1A10_4FFF), SOC_CTRL (0x1A10_4000–0x1A10_4FFF), and EU (0x1A10_9000–0x1A10_AFFF) slave ranges. The APB node performs parallel, non-prioritized address decode, causing multiple PSEL signals to assert simultaneously for addresses in the overlapping regions, which broadcasts writes to multiple slaves and returns undefined read data.",
      "vulnerability_category": "APB Address Range Overlap / Unintended Multi-Slave Access",
      "affected_locations": [
        {
          "file": "rtl/includes/periph_bus_defines.sv",
          "line_start": 24,
          "line_end": 45,
          "module": "periph_bus_wrap (via periph_bus_defines.sv)",
          "signal_or_register": "GPIO_END_ADDR, UDMA_START_ADDR, SOC_CTRL_START_ADDR, EU_START_ADDR"
        },
        {
          "file": "ips/apb/apb_node/apb_node.sv",
          "line_start": 59,
          "line_end": 64,
          "module": "apb_node",
          "signal_or_register": "psel_o"
        }
      ],
      "evidence": [
        {
          "file": "rtl/includes/periph_bus_defines.sv",
          "line_start": 24,
          "line_end": 34,
          "module": "periph_bus_wrap",
          "object": "GPIO, UDMA, SOC_CTRL address range definitions",
          "evidence_type": "overlapping_address_ranges",
          "description": "GPIO_START_ADDR=0x1A10_1000, GPIO_END_ADDR=0x1A10_AFFF; UDMA_START_ADDR=0x1A10_2000, UDMA_END_ADDR=0x1A10_4FFF; SOC_CTRL_START_ADDR=0x1A10_4000, SOC_CTRL_END_ADDR=0x1A10_4FFF. UDMA and SOC_CTRL ranges fall entirely within the GPIO range. Any address in 0x1A10_2000–0x1A10_4FFF simultaneously matches GPIO and UDMA; 0x1A10_4000–0x1A10_4FFF matches GPIO, UDMA, and SOC_CTRL.",
          "supports_claim": "Directly proves overlapping address decode windows that will cause multi-PSEL assertion in the APB node."
        },
        {
          "file": "rtl/includes/periph_bus_defines.sv",
          "line_start": 44,
          "line_end": 45,
          "module": "periph_bus_wrap",
          "object": "EU address range overlapping GPIO",
          "evidence_type": "overlapping_address_ranges",
          "description": "EU_START_ADDR=0x1A10_9000, EU_END_ADDR=0x1A10_AFFF — these addresses fall within GPIO_START_ADDR=0x1A10_1000 to GPIO_END_ADDR=0x1A10_AFFF. Any access to 0x1A10_9000–0x1A10_AFFF simultaneously selects both GPIO and EU slaves.",
          "supports_claim": "Extends the overlap finding to include the Event Unit slave, creating additional unintended dual-slave access windows."
        },
        {
          "file": "ips/apb/apb_node/apb_node.sv",
          "line_start": 59,
          "line_end": 64,
          "module": "apb_node",
          "object": "psel_o parallel decode",
          "evidence_type": "no_arbitration_logic",
          "description": "Lines 59–64: 'for(i=0; i<NB_MASTER; i++) assign psel_o[i] = (paddr_i >= START_ADDR_i[i]) && (paddr_i <= END_ADDR_i[i]);' — all PSEL signals are asserted in parallel with no mutual exclusion, priority encoding, or overlap detection.",
          "supports_claim": "Confirms that when address ranges overlap, multiple psel_o bits are simultaneously asserted, and there is no hardware mechanism to prevent this from propagating to both slaves."
        },
        {
          "file": "ips/apb/apb_node/apb_node.sv",
          "line_start": 131,
          "line_end": 142,
          "module": "apb_node",
          "object": "PRDATA mux — non-prioritized for loop",
          "evidence_type": "undefined_behavior_on_overlap",
          "description": "Lines 131–142: PRDATA mux iterates all masters with no break; last matching slave's data wins in simulation due to loop ordering, but in synthesized hardware with parallel combinational logic the result is implementation-defined. PREADY and PSLVERR muxes have the same structure.",
          "supports_claim": "Demonstrates that read data returned to the initiator during an overlapping access is non-deterministic, which can be exploited for information disclosure or cause incorrect control flow."
        },
        {
          "file": "ips/pulp_soc/rtl/pulp_soc/periph_bus_wrap.sv",
          "line_start": 49,
          "line_end": 80,
          "module": "periph_bus_wrap",
          "object": "slave address range bindings",
          "evidence_type": "address_range_binding",
          "description": "periph_bus_wrap binds s_masters[1] (gpio) to GPIO_START/END_ADDR, s_masters[2] (udma) to UDMA_START/END_ADDR, s_masters[3] (soc_ctrl) to SOC_CTRL_START/END_ADDR, s_masters[6] (eu) to EU_START/END_ADDR, all sourced from periph_bus_defines.sv.",
          "supports_claim": "Confirms the overlapping defines are actively instantiated in the working bus topology and not dead code."
        },
        {
          "file": "ips/apb/apb_gpio/apb_gpio.sv",
          "line_start": 35,
          "line_end": 35,
          "module": "apb_gpio",
          "object": "APB_ADDR_WIDTH parameter",
          "evidence_type": "address_width_mismatch_indicator",
          "description": "Line 35: 'parameter APB_ADDR_WIDTH = 12' — GPIO module decodes only 12 bits of address (4 KB slave space), but GPIO_END_ADDR - GPIO_START_ADDR = 0xA000 - 0x1000 = 0x9000 (36 KB), indicating GPIO_END_ADDR is likely misconfigured and should be 0x1A10_1FFF.",
          "supports_claim": "Supports the hypothesis that GPIO_END_ADDR=0x1A10_AFFF is a typo/misconfiguration, and the intended value would not encompass UDMA, SOC_CTRL, or EU ranges."
        }
      ],
      "reasoning_summary": "The GPIO slave end address (0x1A10_AFFF) is 36 KB above its start address (0x1A10_1000), but the GPIO module itself only decodes 12 bits (4 KB, consistent with APB_ADDR_WIDTH=12). This strongly suggests the GPIO_END_ADDR should be 0x1A10_1FFF (a 4 KB window). As configured, the GPIO range engulfs the UDMA (0x1A10_2000–0x1A10_4FFF), SOC_CTRL (0x1A10_4000–0x1A10_4FFF), and EU (0x1A10_9000–0x1A10_AFFF) slave ranges. The APB node asserts PSEL in parallel for all slaves whose range contains the incoming address, with no arbitration or mutual exclusion. On any write to an address in the overlap zone, both the GPIO slave and the other matched slave (UDMA, SOC_CTRL, EU) will receive and accept the write transaction simultaneously. The SOC_CTRL slave controls security-critical registers including cluster boot address, cluster reset, and JTAG output, making unintended dual writes to SOC_CTRL particularly hazardous.",
      "security_impact": "Writes to UDMA register addresses (0x1A10_2000–0x1A10_4FFF) are simultaneously forwarded to the GPIO slave, corrupting GPIO state (output levels, direction, interrupt config) with data intended for DMA channel registers. Writes to SOC_CTRL addresses (0x1A10_4000–0x1A10_4FFF) — which control cluster power, cluster boot address, cluster reset, fetch-enable, and JTAG — are simultaneously forwarded to both GPIO and UDMA, potentially triggering unintended cluster resets, boot address corruption, or JTAG register modification as a side effect of routine UDMA/GPIO operations. Reads from overlapping addresses return a non-deterministic mix of two slaves' register data, which could be exploited to infer otherwise inaccessible register state of a co-located slave. The most severe scenario is that a routine DMA configuration write inadvertently modifies the cluster boot address or disables cluster reset in SOC_CTRL.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "It is possible that higher-level system routing (e.g., address filtering before the peripheral bus) ensures no transaction with an address in the overlap zone is ever forwarded to this bus; however, no such filtering is visible within the provided scope. The EU_END_ADDR (0x1A10_AFFF) coinciding exactly with GPIO_END_ADDR adds to the suspicion that GPIO_END_ADDR is a configuration error rather than an intentional large allocation.",
      "recommended_follow_up": [
        "Correct GPIO_END_ADDR from 0x1A10_AFFF to 0x1A10_1FFF to match the GPIO module's 12-bit (4 KB) address space and eliminate all address overlaps.",
        "Add an assertion or simulation check in apb_node.sv to detect when more than one psel_o bit is asserted simultaneously and flag this as an error.",
        "Audit all slave address ranges in periph_bus_defines.sv to ensure they are non-overlapping and correctly sized to match each peripheral module's APB_ADDR_WIDTH parameter.",
        "If a larger GPIO address window is intentional (e.g., for per-pin GPIO banks), document the intended layout and confirm UDMA, SOC_CTRL, and EU ranges are moved outside it."
      ]
    }
  ],
  "no_finding_reason": "N/A — findings were identified.",
  "global_uncertainty": "The analysis is limited to the RTL source files present in the scope. No simulation, formal verification, synthesis netlist, or system-level integration context (e.g., upstream address filtering, TrustZone configuration, downstream AXI protection filters) was accessible. It is possible that system-level mitigations external to this scope partially compensate for some findings, particularly FIND-003 (address overlap). FIND-001 (PROT cross-wire) and FIND-002 (GPIO lock bypass) are structural defects in the RTL itself and cannot be masked by external mitigations without modifying the affected modules. No APB PPROT signal is present in the peripheral bus interface, so privilege-based gating of APB register accesses is architecturally absent throughout the peripheral subsystem."
}