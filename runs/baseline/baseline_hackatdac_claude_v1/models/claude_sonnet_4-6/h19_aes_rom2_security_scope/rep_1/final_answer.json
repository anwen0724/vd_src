{
  "analysis_summary": "Analysis of the HackAtDAC 2019 SoC RTL (h19_aes_rom2 variant) covering aes_wrapper.sv, rom2.sv, axi_node_intf_wrap.sv, ariane_peripherals.sv, ariane_testharness.sv, ariane_soc_pkg.sv, and bootrom.sv. The design implements an AES-192 cryptographic accelerator, a ROM2 fuse-key store, an AXI interconnect with privilege-level-based access control, and top-level SoC harness integration. Five confirmed permission-related security vulnerabilities were identified: (1) the full 192-bit AES key is readable through the AES peripheral register bus with no access control; (2) the ROM2 \"secure\" register is fully writable from the AXI bus with no write-protection; (3) the AXI fabric access-control bitmasks are loaded from the writable ROM2 register, creating a circular trust failure where write access to ROM2 allows rewriting the access policy itself; (4) ROM2 key material is returned unconditionally on reads from the bus with no read-gating; and (5) AES intermediate computation state is exposed via bus-readable registers, enabling cryptanalytic attacks.",
  "findings": [
    {
      "finding_id": "FIND-001",
      "status": "confirmed_finding",
      "summary": "Full 192-bit AES key readable from bus-mapped registers with no access control or privilege check",
      "vulnerability_category": "Sensitive Data Exposure / Missing Read Access Control",
      "affected_locations": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 96,
          "line_end": 148,
          "module": "aes_wrapper",
          "signal_or_register": "key_big / external_bus_io.rdata"
        }
      ],
      "evidence": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 57,
          "line_end": 57,
          "module": "aes_wrapper",
          "object": "key_big",
          "evidence_type": "signal_assignment",
          "description": "key_big is directly assigned from key_in (the 192-bit fuse key from ROM2 secure_reg[0]): 'assign key_big = key_in;'",
          "supports_claim": "The full secret key is driven into the readable register bank without masking."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 127,
          "line_end": 139,
          "module": "aes_wrapper",
          "object": "external_bus_io.rdata",
          "evidence_type": "combinational_read_path",
          "description": "Read-side always@(*) case statement at addr offsets 16–21 assigns all six 32-bit slices of the 192-bit key_big unconditionally to external_bus_io.rdata: case indices 16→key_big[191:160], 17→key_big[159:128], 18→key_big[127:96], 19→key_big[95:64], 20→key_big[63:32], 21→key_big[31:0]. No privilege check, no masking, no error response.",
          "supports_claim": "Any bus master that can address the AES peripheral can read back all 192 bits of the secret key in six 32-bit reads."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 463,
          "line_end": 468,
          "module": "ariane_peripherals",
          "object": "key_reg_out[0]",
          "evidence_type": "instantiation_connection",
          "description": "aes_wrapper is instantiated with key_in driven by key_reg_out[0], which is the AES key slot from ROM2 secure_reg[0].",
          "supports_claim": "The ROM2 AES key flows directly and without gating into the AES peripheral's readable register space."
        }
      ],
      "reasoning_summary": "The AES wrapper's read-side logic unconditionally maps the full 192-bit secret key (key_big, sourced from ROM2 fuse slot 0) onto six consecutive bus-readable 32-bit registers (offsets 16–21 in the address space starting at AESBase = 0x1010_0000). There is no privilege-level check, no key-lock bit, no 'key-not-readable' policy, and no error signaling. Any software running on the SoC that can issue reads to those addresses recovers the complete AES-192 key. The comment in the write-side case correctly protects ciphertext registers from writes ('// no write access to ct registers!!'), but no equivalent protection exists for the key read path, confirming this is an implementation error rather than deliberate design.",
      "security_impact": "Complete AES-192 key compromise. Any software with access to the AES peripheral address space can exfiltrate the full secret key in six 32-bit reads (192 bits total). This defeats all AES encryption confidentiality guarantees provided by this SoC.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The upstream AXI access-control connectivity map (axi_node, not in scope) may restrict which bus masters can reach the AES peripheral at all; however, since the connectivity map is itself derived from writable ROM2 registers (see FIND-003), this mitigation is bypassable.",
      "recommended_follow_up": [
        "Remove key_big from all readable register offsets in the read-side case statement.",
        "If key readback is required for diagnostics, gate reads behind a secure privilege-level check (e.g., only allow M-mode reads) and add a one-way lock bit.",
        "Add a formal property asserting that key_big never appears on rdata."
      ]
    },
    {
      "finding_id": "FIND-002",
      "status": "confirmed_finding",
      "summary": "ROM2 'secure' fuse register is unconditionally writable from the AXI bus with no write-protection mechanism",
      "vulnerability_category": "Missing Write Access Control / Insecure Mutable Secure Storage",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 26,
          "line_end": 42,
          "module": "rom2",
          "signal_or_register": "secure_reg / we_i"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 1,
          "line_end": 4,
          "module": "rom2",
          "object": "secure_reg",
          "evidence_type": "design_comment",
          "description": "Module header comment states: 'ROM2: Which have all the keys.' and internal comment 'Secure registers. Key values copied from fuse to these registers on reset.' The design intent is that secure_reg holds immutable fuse-like key values.",
          "supports_claim": "The module is intended to hold read-only fuse key values, but the implementation allows writes."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 36,
          "line_end": 42,
          "module": "rom2",
          "object": "secure_reg",
          "evidence_type": "sequential_write_path",
          "description": "In the always_ff block: 'if (!we_i) begin raddr_q <= ...; end else begin secure_reg[addr_i[...]] <= wdata_i; end'. When we_i is asserted, any of the four 192-bit key slots is overwritten with wdata_i with no additional access check.",
          "supports_claim": "All four key slots in secure_reg are fully writable by any AXI master that can assert we_i to the ROM2 address space."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 17,
          "line_end": 17,
          "module": "rom2",
          "object": "mem",
          "evidence_type": "signal_declaration",
          "description": "'const logic [RomSize-1:0][191:0] mem = {...}' — the const qualifier makes mem read-only, but the writable secure_reg is a separate register array loaded from mem at reset. After reset, secure_reg is not protected.",
          "supports_claim": "The immutability of mem does not protect secure_reg from post-reset writes."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 191,
          "line_end": 211,
          "module": "ariane_peripherals",
          "object": "rom2_we / i_axi2rom2",
          "evidence_type": "instantiation_connection",
          "description": "axi2mem adapter instantiated with .we_o(rom2_we) connected to rom2 .we_i(rom2_we). The write-enable signal is passed directly from the AXI transaction to the ROM2 port with no interlock, masking, or privilege check inserted.",
          "supports_claim": "AXI write transactions to ROM2Base (0x0021_0000) directly assert we_i on rom2, enabling overwrite of any key slot."
        }
      ],
      "reasoning_summary": "ROM2 is described as a fuse/key store holding the AES key, JTAG authentication key, and two access-control master configuration words. The const mem array is genuinely read-only, but after reset these values are copied into a regular register array (secure_reg) which is exposed as a writable register bank via the AXI bus. No hardware write-protection (lock bit, fuse-blown flag, privilege check, or one-time-program semantics) is implemented in the RTL. The axi2mem adapter unconditionally passes write-enables from the AXI fabric to rom2.we_i.",
      "security_impact": "An attacker with AXI bus access to ROM2Base can overwrite: (1) the AES key (slot 0), defeating all AES encryption; (2) the JTAG authentication key (slot 1), allowing debug interface authentication bypass; (3) the access-control bitmasks for master 0 and master 1 (slots 2 and 3), allowing the AXI interconnect access policy to be rewritten arbitrarily. This is a root-level compromise of all security assets on the chip.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The AXI connectivity map may initially restrict which masters can reach ROM2Base; however, since the connectivity map is derived from ROM2 secure_reg itself (FIND-003), any master that can first read the current access-control values can craft a write to expand its own access—a bootstrapping escalation.",
      "recommended_follow_up": [
        "Implement a write-lock bit (cleared only by hardware reset) that permanently disables writes to secure_reg after the initial boot window.",
        "Replace the writable secure_reg with a truly read-only memory or OTP macro.",
        "Gate we_i in rom2 behind a hardware privilege check (e.g., only allow writes when priv_lvl == M-mode AND a dedicated lock register has not been set).",
        "Add a formal property asserting that secure_reg is stable after the first N cycles following reset deassertion."
      ]
    },
    {
      "finding_id": "FIND-003",
      "status": "confirmed_finding",
      "summary": "AXI access-control policy is loaded from the writable ROM2 register, creating a circular trust failure that enables full access control bypass",
      "vulnerability_category": "Circular Trust / Access Control Policy Stored in Mutable Register",
      "affected_locations": [
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "access_ctrl_reg / key_reg_out"
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 444,
          "line_end": 453,
          "module": "ariane_testharness",
          "signal_or_register": "access_ctrl"
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 424,
          "line_end": 434,
          "module": "connectivity_mapping",
          "signal_or_register": "connectivity_map_o / access_ctrl_i"
        }
      ],
      "evidence": [
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "access_ctrl_reg",
          "evidence_type": "signal_assignment",
          "description": "'assign jtag_key = key_reg_out[1][31:0]; assign access_ctrl_reg[0] = key_reg_out[2][47:0]; assign access_ctrl_reg[1] = key_reg_out[3][47:0];' — The access-control bitmasks for both AXI masters come directly from rom2.secure_reg slots 2 and 3.",
          "supports_claim": "The AXI access-control policy is sourced entirely from writable ROM2 register slots."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 444,
          "line_end": 453,
          "module": "ariane_testharness",
          "object": "access_ctrl",
          "evidence_type": "signal_assignment",
          "description": "Nested generate loop: 'assign access_ctrl[i][j] = access_ctrl_reg[i][4*j +: 4]' — slices of access_ctrl_reg are distributed into the per-(master,peripheral) per-privilege-level access control input of the AXI crossbar.",
          "supports_claim": "The connectivity map fed to the AXI crossbar is derived 1:1 from the writable ROM2 register content."
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "connectivity_mapping",
          "object": "connectivity_map_o",
          "evidence_type": "combinational_logic",
          "description": "'assign connectivity_map_o[i][j] = access_ctrl_i[i][j][priv_lvl_i] || ((j==6) && access_ctrl_i[i][7][priv_lvl_i]);' — Access permission for each (master i, peripheral j) at the current privilege level is read directly from access_ctrl_i, which is driven by access_ctrl_reg, which is driven by ROM2 secure_reg.",
          "supports_claim": "The AXI interconnect enforces access control using a bitmask that is fully controlled by the content of a writable bus-accessible register."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 36,
          "line_end": 42,
          "module": "rom2",
          "object": "secure_reg[2], secure_reg[3]",
          "evidence_type": "sequential_write_path",
          "description": "secure_reg slots 2 and 3 (the access-control words) are written whenever we_i is asserted to the corresponding address, with no access restriction. Overwriting these slots immediately changes the connectivity_map_o on the next evaluation.",
          "supports_claim": "An attacker who can write to ROM2 rewrites the access control policy that governs future accesses, including access to ROM2 itself."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 18,
          "line_end": 21,
          "module": "rom2",
          "object": "mem",
          "evidence_type": "constant_declaration",
          "description": "ROM2 mem content: slot 2 = 192'h...0000fff8_ff6ff00f (access control master 0), slot 3 = 192'h...0000f8f8_ff6fe00f (access control master 1). Comments confirm: 'First 4 bits for peripheral 0, next 4 for p1 and so on.' These are the initial bitmask values.",
          "supports_claim": "The access control bitmask values are intentionally part of the ROM2 key store and are directly modifiable via AXI write transactions."
        }
      ],
      "reasoning_summary": "The AXI fabric's access-control enforcement logic (connectivity_mapping module) uses a per-(master,peripheral,privilege-level) bitmask to decide which bus transactions are permitted. This bitmask is derived solely from slots 2 and 3 of ROM2's writable secure_reg. An attacker who gains any write access to ROM2 can overwrite these bitmask slots to grant themselves access to all peripherals at all privilege levels. Critically, because ROM2 itself is a peripheral in the address map (at ROM2Base = 0x0021_0000), an attacker who already has partial ROM2 write access can immediately escalate to full system access. This is a self-defeating circular trust structure: the enforcer (connectivity map) trusts data held in the target (ROM2 secure register).",
      "security_impact": "Complete AXI access control bypass. An attacker can rewrite the access-control bitmask to all-ones, granting every bus master unrestricted access to every peripheral (AES, ROM2, JTAG key registers, PLIC, UART, etc.) at every privilege level. This fully defeats the design's multi-master privilege separation intent.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The initial access-control values in ROM2 mem may restrict unprivileged masters from writing to ROM2 in the default state; however, because the initial values are read from a system reset and the write path is unguarded, any transient window before access-control registers stabilize, or any master that starts with ROM2 write access, can exploit this path.",
      "recommended_follow_up": [
        "Store access-control policy in a truly read-only (hardware-fused or OTP) memory, not in a writable register bank.",
        "At minimum, add a one-way lock register that, when set (e.g., at end of secure boot), permanently disables all writes to ROM2 secure_reg slots 2 and 3.",
        "Implement the connectivity map from hardwired constants or a separately secured configuration store that cannot be modified at runtime.",
        "Add a formal property asserting that connectivity_map_o is stable after secure boot completes."
      ]
    },
    {
      "finding_id": "FIND-004",
      "status": "confirmed_finding",
      "summary": "ROM2 key material is returned unconditionally on AXI bus reads with no read-access gating",
      "vulnerability_category": "Sensitive Data Exposure / Missing Read Access Control on Key Store",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 43,
          "line_end": 44,
          "module": "rom2",
          "signal_or_register": "rdata_o / secure_reg"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 43,
          "line_end": 44,
          "module": "rom2",
          "object": "rdata_o",
          "evidence_type": "combinational_read_path",
          "description": "'assign rdata_o = (raddr_q < RomSize) ? secure_reg[raddr_q] : 0;' — Any valid address returns the corresponding secure_reg slot (which contains key material) with no privilege check, no lock bit, and no masking.",
          "supports_claim": "All four 192-bit key slots (AES key, JTAG key, access-ctrl 0, access-ctrl 1) are readable from the AXI bus without restriction."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 17,
          "line_end": 21,
          "module": "rom2",
          "object": "mem",
          "evidence_type": "constant_declaration",
          "description": "Slot 0 (AES): 192'h55555555_28aed2a6_abf71588_09cf4f3c_2b7e1516_28aed2a6; Slot 1 (JTAG): 192'h2b7e1516_28aed2a6_abf71588_09cf4f3c_2b7e1516_28aed2a6. Both full key values are readable.",
          "supports_claim": "Hardcoded cryptographic key values are directly accessible via bus reads."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 191,
          "line_end": 201,
          "module": "ariane_peripherals",
          "object": "i_axi2rom2 / rom2_rdata",
          "evidence_type": "instantiation_connection",
          "description": "axi2mem adapter passes rom2_rdata directly back through the AXI R-channel to the initiating bus master. No interposition, masking, or filtering is present.",
          "supports_claim": "Read data from ROM2's rdata_o flows unmodified back to the AXI bus master response channel."
        }
      ],
      "reasoning_summary": "The ROM2 module's read path returns the content of secure_reg unconditionally for any valid address. Since secure_reg contains the AES encryption key, the JTAG authentication key, and the access-control bitmasks, any bus master that can address ROM2Base can iterate addresses 0–3 and exfiltrate all four 192-bit key slots. There is no read-protection flag, no privilege-level check on reads, and no mechanism to return zeros or an error response instead of key data.",
      "security_impact": "Full disclosure of all four key slots stored in ROM2: (1) AES-192 key (192 bits), (2) JTAG authentication key (192 bits), (3) access-control master 0 bitmask (192 bits including 48-bit policy), (4) access-control master 1 bitmask. An attacker can reconstruct the entire key store with four bus reads.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The AXI connectivity map may initially restrict which masters can read from ROM2Base, providing a partial mitigation. However, the AES key is also independently readable via FIND-001 (aes_wrapper), and the connectivity map is derived from the writable ROM2 register itself (FIND-003), so this mitigation is not reliable.",
      "recommended_follow_up": [
        "Add a privilege-level check to rom2's read path: only return secure_reg content when accessed from M-mode; return all-zeros or AXI SLVERR for lower privilege levels.",
        "Separate key-slot 0 (AES key) from the AXI bus read path entirely—supply it exclusively via dedicated hardware wires to the AES accelerator, not through a bus-readable register.",
        "Implement a 'key-readable' lock bit that is cleared after boot, permanently suppressing bus reads of key slots."
      ]
    },
    {
      "finding_id": "FIND-005",
      "status": "confirmed_finding",
      "summary": "AES intermediate round state is exposed via bus-readable registers, enabling cryptanalytic side-channel attacks",
      "vulnerability_category": "Sensitive Intermediate State Exposure / Information Leakage",
      "affected_locations": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 142,
          "line_end": 148,
          "module": "aes_wrapper",
          "signal_or_register": "inter_state / external_bus_io.rdata"
        }
      ],
      "evidence": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 142,
          "line_end": 148,
          "module": "aes_wrapper",
          "object": "inter_state",
          "evidence_type": "combinational_read_path",
          "description": "Read-side case indices 22–25 map inter_state[127:96], inter_state[95:64], inter_state[63:32], inter_state[31:0] to external_bus_io.rdata. inter_state is the output of the aes_192_sed core's intermediate computation, readable mid-encryption.",
          "supports_claim": "AES intermediate state (partial round outputs) is unconditionally exposed on the bus-readable register interface."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 143,
          "line_end": 165,
          "module": "aes_wrapper",
          "object": "aes_192_sed",
          "evidence_type": "instantiation_connection",
          "description": "aes_192_sed is instantiated with .inter_state(inter_state). The inter_state port is connected to the readable register map, making internal AES pipeline state observable externally.",
          "supports_claim": "The AES hardware core's internal state signal is wired to an external bus register without any protection."
        }
      ],
      "reasoning_summary": "The AES wrapper exposes the `inter_state` signal (a 128-bit intermediate round computation output from the `aes_192_sed` core) on four consecutive bus-readable registers at offsets 22–25. This provides an attacker with visibility into the AES computation pipeline mid-encryption. Combined with FIND-001 (key readability), this is redundant in the most severe case, but represents an independent information-leakage vulnerability that could be exploited for algebraic attacks or differential fault analysis even if the direct key read vulnerability were fixed.",
      "security_impact": "Enables chosen-plaintext or differential cryptanalysis by providing observable intermediate AES round state. An attacker can use this to perform algebraic attacks on the key, or correlate intermediate states with known plaintext/key hypotheses to recover key bits without directly reading the key register (which is already exposed via FIND-001).",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact AES round at which inter_state is captured depends on the aes_192_sed implementation (not in scope). If inter_state reflects the final or a very late round, the cryptanalytic utility is lower; if it reflects an early round, the attack complexity is significantly reduced.",
      "recommended_follow_up": [
        "Remove inter_state from all bus-readable register offsets in the read-side case statement.",
        "If intermediate state observability is required for debug, gate it behind a debug-mode enable that is only active when the system is in a non-secure debug context.",
        "Add a formal security property asserting that no internal AES signal appears on the external register bus rdata output."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The axi_node core module (not present in scope) implements the actual AXI transaction blocking using cfg_connectivity_map_i; it is assumed to faithfully enforce the connectivity map, but internal gating details are not verified. The axi2mem adapter (not in scope) is assumed to pass we_o and req_o without additional privilege checks. The dmi_jtag module (not in scope) consumes jtag_key for JTAG authentication; the exact mechanism is unverified, but the key itself is sourced from the writable and bus-readable secure_reg[1]. The aes_192_sed AES core (not in scope) generates inter_state; its precise pipeline stage is unknown. No simulation, formal verification, or synthesis was performed; all findings are based solely on static RTL inspection."
}