{
  "analysis_summary": "The input scope contains a RISC-V debug module and ROM2 key storage subsystem. Analysis of the RTL reveals several permission-related security vulnerabilities: (1) the Debug Module unconditionally sets the authenticated bit in dmstatus to 1, completely bypassing the RISC-V debug authentication protocol; (2) the JTAG password check latch (pass_chk) is never cleared once set, granting permanent debug access after a single successful authentication; (3) ROM2 secure key registers, which hold JTAG and AES keys fused at reset, are writable via the AXI bus interface, allowing any bus master to overwrite critical security keys. These issues collectively allow an attacker to gain unauthorized debug access, escalate to machine-mode privilege, and tamper with cryptographic key material.",
  "findings": [
    {
      "finding_id": "F01",
      "status": "confirmed_finding",
      "summary": "Debug Module dmstatus.authenticated is unconditionally hardcoded to 1, bypassing the RISC-V debug authentication protocol",
      "vulnerability_category": "Permission / Authentication Bypass",
      "affected_locations": [
        {
          "file": "src/debug/dm_csrs.sv",
          "line_start": 171,
          "line_end": 171,
          "module": "dm_csrs",
          "signal_or_register": "dmstatus.authenticated"
        },
        {
          "file": "src/debug/dm_pkg.sv",
          "line_start": 104,
          "line_end": 105,
          "module": "",
          "signal_or_register": "dmstatus_t.authenticated, dmstatus_t.authbusy"
        }
      ],
      "evidence": [
        {
          "file": "src/debug/dm_csrs.sv",
          "line_start": 167,
          "line_end": 171,
          "module": "dm_csrs",
          "object": "csr_read_write always_comb block",
          "evidence_type": "Source code (combinational assignment)",
          "description": "Line 168-171: dmstatus is cleared to '0, then dmstatus.authenticated is unconditionally set to 1'b1. There is no state machine, no password comparison, and no condition under which authenticated can become 0.",
          "supports_claim": "The authenticated bit is always 1 regardless of whether any authentication handshake occurred."
        },
        {
          "file": "src/debug/dm_pkg.sv",
          "line_start": 96,
          "line_end": 108,
          "module": "",
          "object": "dmstatus_t struct",
          "evidence_type": "Package definition",
          "description": "The dmstatus_t struct defines both 'authenticated' (bit 7) and 'authbusy' (bit 6) fields, indicating the spec expects an authentication protocol. The authbusy field and AuthData register (0x30) are defined but never implemented in dm_csrs.sv.",
          "supports_claim": "The hardware definition includes authentication infrastructure that is completely bypassed in the implementation."
        },
        {
          "file": "src/debug/dm_csrs.sv",
          "line_start": 236,
          "line_end": 236,
          "module": "dm_csrs",
          "object": "resp_queue_data assignment",
          "evidence_type": "Source code",
          "description": "DMStatus register read returns the dmstatus struct with authenticated=1, making the bypass visible to any debugger reading the status register.",
          "supports_claim": "The always-authenticated status is observable by the debugger."
        }
      ],
      "reasoning_summary": "The RISC-V Debug Specification 0.13 defines an authentication mechanism via the AuthData register and the authbusy/authenticated fields in dmstatus. The dm_pkg.sv package defines all the necessary types (dmstatus_t with authenticated and authbusy bits, AuthData register at address 0x30). However, in dm_csrs.sv, the csr_read_write always_comb block hardcodes dmstatus.authenticated = 1'b1 unconditionally. There is no FSM, no AuthData handling, and no condition under which authenticated could be 0. This means any debugger connecting via JTAG sees the DM as already authenticated without ever providing credentials, completely bypassing the hardware-level debug authentication.",
      "security_impact": "An attacker with physical JTAG access to the chip can use the debug module to halt harts, read/write registers and memory, and execute arbitrary code in debug mode without any authentication. This provides full system compromise including extraction of secrets and manipulation of secure state.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The dm_csrs.sv file was read only partially; the full register write logic for DMControl and abstract commands was visible. No evidence of any authentication FSM was found in any of the debug module files (dm_top.sv, dm_csrs.sv, dmi_jtag.sv, dmi_jtag_tap.sv, dmi_cdc.sv). The AuthData register is never referenced in dm_csrs.sv.",
      "recommended_follow_up": [
        "Implement the AuthData-based authentication FSM in dm_csrs.sv per RISC-V Debug Spec 0.13 Section 3.6",
        "Drive dmstatus.authenticated from the FSM output, defaulting to 0",
        "Add timeout or reset for the authenticated state"
      ]
    },
    {
      "finding_id": "F02",
      "status": "confirmed_finding",
      "summary": "JTAG password check latch (pass_chk) is set once and never cleared, granting permanent privileged access after a single successful authentication",
      "vulnerability_category": "Permission Persistence / Privilege Escalation",
      "affected_locations": [
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 79,
          "line_end": 79,
          "module": "dmi_jtag",
          "signal_or_register": "pass_chk"
        },
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 110,
          "line_end": 120,
          "module": "dmi_jtag",
          "signal_or_register": "pass_chk (DTM_PASS handling)"
        },
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 177,
          "line_end": 182,
          "module": "dmi_jtag",
          "signal_or_register": "umode_o"
        },
        {
          "file": "src/csr_regfile.sv",
          "line_start": 938,
          "line_end": 938,
          "module": "csr_regfile",
          "signal_or_register": "priv_lvl_o"
        }
      ],
      "evidence": [
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 79,
          "line_end": 79,
          "module": "dmi_jtag",
          "object": "pass_chk declaration",
          "evidence_type": "Source code (signal declaration)",
          "description": "pass_chk is declared as 'logic pass_chk;' with no reset value and is not inside an always_ff block. It is assigned only in the always_comb block inside the DTM_PASS case when data_d == pass. When not in that branch, pass_chk is not assigned, inferring a latch that retains its previous value forever.",
          "supports_claim": "pass_chk behavior is that of a latch: once set to 1, it remains 1 until the next power cycle or trst_n assertion."
        },
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 110,
          "line_end": 120,
          "module": "dmi_jtag",
          "object": "DTM_PASS handling in Idle state",
          "evidence_type": "Source code (always_comb case)",
          "description": "The DTM_PASS operation sets pass_chk = 1'b1 when the input data matches the stored password (pass). The pass register is loaded from jtag_key on reset. Once pass_chk is set, the DTM_READ condition on line 110 (pass_chk == 1'b1) gates all subsequent read operations.",
          "supports_claim": "Password check is a one-time gate; once unlocked, all future accesses are allowed."
        },
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 177,
          "line_end": 182,
          "module": "dmi_jtag",
          "object": "umode_o assignment",
          "evidence_type": "Source code (always_comb)",
          "description": "When pass_chk == 1'b1, umode_o is driven to 1'b1. This signal propagates to the CSR register file.",
          "supports_claim": "Successful JTAG password authentication elevates the processor to machine mode."
        },
        {
          "file": "src/csr_regfile.sv",
          "line_start": 938,
          "line_end": 938,
          "module": "csr_regfile",
          "object": "priv_lvl_o assignment",
          "evidence_type": "Source code (continuous assignment)",
          "description": "assign priv_lvl_o = (debug_mode_q || umode_i) ? riscv::PRIV_LVL_M : priv_lvl_q; When umode_i is high, the privilege level is forced to M-mode regardless of the actual CSR privilege setting.",
          "supports_claim": "umode_o from dmi_jtag directly escalates the CPU privilege to Machine mode."
        }
      ],
      "reasoning_summary": "The dmi_jtag module implements a password-based gate for JTAG access. The jtag_key is stored in ROM2 (a fuse-like structure) and loaded into a register on reset. When a DTM_PASS operation with the correct key is received, the pass_chk signal is asserted. However, pass_chk is implemented as a latch-like logic signal that is never cleared. Once a correct password is supplied once, pass_chk remains 1 forever (until power cycle or trst_n reset), granting permanent debug access and forcing the processor into Machine mode via the umode_o signal. There is no timeout, no session invalidation, and no mechanism to re-lock the debug interface.",
      "security_impact": "After a single correct password entry (or if the key is leaked/extracted), the debug interface remains permanently unlocked. The attacker retains machine-mode privilege escalation for the entire uptime of the device. Combined with F01 (always authenticated DM), the password check may be entirely irrelevant, but if it were fixed, this latch behavior would still be a vulnerability.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact reset behavior of pass_chk is unclear because it is a latch inferred from a combinational block. It may power up in an unknown state, but after reset (trst_ni low) the state machine goes to Idle but pass_chk is not explicitly assigned. The dr_q is reset to '0 which indirectly means the state machine starts fresh, but pass_chk latch state after trst_n de-assertion depends on synthesis.",
      "recommended_follow_up": [
        "Make pass_chk a registered signal with explicit reset to 0",
        "Add a mechanism to clear pass_chk on debug session disconnect or timeout",
        "Consider tying the DM authenticated state to the JTAG pass_chk state"
      ]
    },
    {
      "finding_id": "F03",
      "status": "confirmed_finding",
      "summary": "ROM2 secure registers holding cryptographic keys are writable via the AXI bus interface, allowing key tampering",
      "vulnerability_category": "Permission / Insecure Key Storage",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 28,
          "line_end": 40,
          "module": "rom2",
          "signal_or_register": "secure_reg"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 36,
          "line_end": 38,
          "module": "rom2",
          "signal_or_register": "we_i write path"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 18,
          "line_end": 22,
          "module": "rom2",
          "object": "mem constant (fuse values)",
          "evidence_type": "Source code (const declaration)",
          "description": "Four 192-bit key values are stored as const: JTAG key (location 1, 192'h2b7e1516...), AES key (location 0, 192'h55555555...), and two access control master keys (locations 2 and 3).",
          "supports_claim": "Sensitive key material is present in the ROM2 module."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 28,
          "line_end": 40,
          "module": "rom2",
          "object": "secure_reg write logic",
          "evidence_type": "Source code (always_ff block)",
          "description": "On reset, secure_reg <= mem (copies fuse values to registers). However, the else branch allows writing to secure_reg[addr_i[...]] <= wdata_i when req_i and we_i are asserted. There is no access control, privilege check, or lock bit preventing writes.",
          "supports_claim": "Any bus master with access to the ROM2 AXI address range can overwrite the cryptographic keys after reset."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 42,
          "line_end": 44,
          "module": "rom2",
          "object": "rdata_o assignment",
          "evidence_type": "Source code (continuous assignment)",
          "description": "rdata_o = (raddr_q < RomSize) ? secure_reg[raddr_q] : '0; Keys are readable via the bus interface with no access restrictions.",
          "supports_claim": "Keys can be read by any bus master."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 215,
          "module": "ariane_peripherals",
          "object": "jtag_key assignment",
          "evidence_type": "Source code",
          "description": "assign jtag_key = key_reg_out[1][31:0]; The JTAG key fed to dmi_jtag comes from ROM2 location 1, bits [31:0].",
          "supports_claim": "The writable ROM2 register directly controls the JTAG authentication password."
        }
      ],
      "reasoning_summary": "The ROM2 module is designed to hold fused key values that should be immutable after manufacture. The keys are stored as a SystemVerilog const array (modeling fuses) and are copied to secure_reg registers on reset. However, the always_ff block unconditionally allows bus writes (we_i) to modify any secure_reg entry. This means any bus master (e.g., a compromised CPU core, a DMA-capable peripheral, or the debug module via SBA) can overwrite the JTAG key, AES key, or access control keys at runtime. Since the JTAG key is used for debug authentication, an attacker could write a known key and then authenticate via JTAG.",
      "security_impact": "Cryptographic keys intended to be immutable after fuse programming can be modified at runtime. An attacker can replace the JTAG key with a known value to gain debug access, overwrite the AES key to compromise encrypted data, or modify access control keys to escalate peripheral permissions. This undermines the root of trust.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The AXI address map and access control (e.g., whether ROM2 is accessible only from certain bus masters) is not defined in the provided scope. However, within the ROM2 module itself, there is no internal protection mechanism. The tb and fpga wrappers connect ROM2 to the general AXI crossbar.",
      "recommended_follow_up": [
        "Add a lock bit to secure_reg that is set after initial key load and prevents further writes",
        "Implement write-once or write-protect until reset behavior for secure_reg",
        "Consider making secure_reg read-only after initialization or adding a privileged-access-only gate",
        "Add integrity checks (e.g., CRC or MAC) on the key values"
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The analysis is limited to the files under the input scope. Key missing context includes: the full AXI address decode and bus fabric (to understand which masters can access ROM2 and debug module), the ariane_soc package defining address bases and peripheral constants, the ariane_pkg defining DebugHartInfo and other constants, the dm_sba module (System Bus Access module that allows debugger-initiated memory accesses), and any additional access control logic that may exist outside the provided scope. Additionally, the dm_csrs.sv file was too large to read completely in the available steps, but the critical authenticated assignment was confirmed."
}