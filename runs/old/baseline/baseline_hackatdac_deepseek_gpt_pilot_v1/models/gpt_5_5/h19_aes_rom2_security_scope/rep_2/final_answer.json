{
  "analysis_summary": "Analyzed the visible RTL/source files under the provided input scope for permission-related security vulnerabilities. The design contains an explicit AXI privilege/access-control matrix and a ROM2 block that stores AES key material, JTAG/debug key material, and access-control configuration words. Source evidence shows ROM2 secrets are exposed through a bus-connected read/write memory interface, the AES wrapper directly exposes its full key through readable registers, and the AXI connectivity-map logic grants PLIC access when CLINT permission is present.",
  "findings": [
    {
      "finding_id": "PERM-ROM2-RW-SECRET-STORE",
      "status": "confirmed_finding",
      "summary": "ROM2 stores security secrets and access-control policy but exposes the backing secure_reg array through a bus-connected read/write interface.",
      "vulnerability_category": "Improper access control for security-critical key/configuration storage",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 17,
          "line_end": 47,
          "module": "rom2",
          "signal_or_register": "mem, secure_reg, rdata_o"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 191,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "rom2_fuse, rom2_req, rom2_we, rom2_rdata, key_reg_out, jtag_key, access_ctrl_reg"
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 476,
          "line_end": 550,
          "module": "ariane_testharness",
          "signal_or_register": "master[ariane_soc::ROM2], ROM2Base, ROM2Length"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 17,
          "line_end": 25,
          "module": "rom2",
          "object": "mem",
          "evidence_type": "source_snippet",
          "description": "ROM2 stores security-sensitive values, including access-control configuration words, JTAG key material, and AES key material.",
          "supports_claim": "The ROM2 memory contains values identified by comments as access-control entries, JTAG key material, and AES key material."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 31,
          "line_end": 34,
          "module": "rom2",
          "object": "secure_reg",
          "evidence_type": "source_snippet",
          "description": "ROM2 copies the constant key/access-control store into secure_reg on reset.",
          "supports_claim": "The mutable secure_reg array is initialized from the sensitive ROM2 constants."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 35,
          "line_end": 43,
          "module": "rom2",
          "object": "req_i, we_i, secure_reg",
          "evidence_type": "source_snippet",
          "description": "ROM2 services normal requests by reading from or writing to secure_reg without a local permission check.",
          "supports_claim": "If req_i is asserted, !we_i selects a read address and we_i writes wdata_i into secure_reg indexed by addr_i."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "object": "rdata_o",
          "evidence_type": "source_snippet",
          "description": "ROM2 returns read data directly from secure_reg.",
          "supports_claim": "The output rdata_o is assigned from secure_reg[raddr_q] when raddr_q is in range."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 191,
          "line_end": 200,
          "module": "ariane_peripherals",
          "object": "i_axi2rom2",
          "evidence_type": "source_snippet",
          "description": "ROM2 is connected to an AXI memory adapter in the peripherals block.",
          "supports_claim": "The AXI-facing rom2_fuse bus drives rom2_req, rom2_we, rom2_addr, and rom2_wdata, and receives rom2_rdata."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 212,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "key_reg_out, jtag_key, access_ctrl_reg",
          "evidence_type": "source_snippet",
          "description": "ROM2 secure registers drive JTAG key and access-control outputs.",
          "supports_claim": "key_reg_out from ROM2 is used as the source of jtag_key and access_ctrl_reg."
        }
      ],
      "reasoning_summary": "ROM2 is described and implemented as the source of AES key, JTAG key, and access-control words, but its secure_reg array is readable and writable through normal request/write signals and is wired to an AXI-facing memory adapter. The module does not enforce local read/write authorization before exposing or modifying secure_reg.",
      "security_impact": "An attacker with bus access that reaches ROM2 may disclose AES/JTAG key material, overwrite security-critical key values, or rewrite the access-control policy itself. This can lead to privilege escalation, debug unlock, cryptographic compromise, or denial of service.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "A single rdata_o read appears width-truncated relative to the 192-bit secure_reg entries, and the exact width-conversion behavior of external modules was not inspected. However, visible source still shows direct bus-driven reads and writes of the sensitive storage.",
      "recommended_follow_up": [
        "Make ROM2 key and access-control storage read-protected or unreadable from software-visible buses.",
        "Remove normal bus write access to fuse-derived security registers, or restrict writes to an authenticated manufacturing/debug lifecycle state.",
        "Separate public configuration reads from secret key storage.",
        "Add explicit checks or assertions proving unprivileged bus transactions cannot read or modify ROM2 secrets."
      ]
    },
    {
      "finding_id": "PERM-AES-KEY-READOUT",
      "status": "confirmed_finding",
      "summary": "The AES peripheral exposes its full ROM2-derived key through readable MMIO registers.",
      "vulnerability_category": "Cryptographic key disclosure through readable register interface",
      "affected_locations": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 45,
          "line_end": 134,
          "module": "aes_wrapper",
          "signal_or_register": "key_in, key_big, external_bus_io.rdata"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 463,
          "line_end": 467,
          "module": "ariane_peripherals",
          "signal_or_register": "key_reg_out[0], key_in"
        }
      ],
      "evidence": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 29,
          "line_end": 29,
          "module": "aes_wrapper",
          "object": "key_in",
          "evidence_type": "source_snippet",
          "description": "AES receives a 192-bit key input.",
          "supports_claim": "The AES wrapper has input logic [191:0] key_in."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 50,
          "line_end": 50,
          "module": "aes_wrapper",
          "object": "key_big",
          "evidence_type": "source_snippet",
          "description": "AES assigns the secret key input directly to key_big.",
          "supports_claim": "assign key_big = key_in directly exposes the incoming key value inside the register read map."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 117,
          "line_end": 128,
          "module": "aes_wrapper",
          "object": "external_bus_io.rdata",
          "evidence_type": "source_snippet",
          "description": "AES register reads expose all six 32-bit words of key_big.",
          "supports_claim": "Read addresses 16 through 21 return key_big[191:160] down to key_big[31:0]."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 463,
          "line_end": 467,
          "module": "ariane_peripherals",
          "object": "i_aes_wrapper.key_in",
          "evidence_type": "source_snippet",
          "description": "The AES key input is sourced from ROM2 secure register output.",
          "supports_claim": "The AES wrapper key_in port is connected to key_reg_out[0], which is ROM2-derived key storage."
        }
      ],
      "reasoning_summary": "The AES wrapper maps the internal AES key directly into software-visible read addresses 16 through 21. There is no local permission check or redaction in the AES wrapper, so any requester permitted to read the AES peripheral can retrieve the entire 192-bit key.",
      "security_impact": "Disclosure of the full AES-192 key compromises confidentiality of all data protected by that key and defeats intended hardware key isolation.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "Access to the AES peripheral still depends on upstream AXI permissions. The finding is that once AES MMIO access is granted, the AES block itself exposes key material.",
      "recommended_follow_up": [
        "Remove key_big from the readable AES register map.",
        "Return zero or an error for key register read addresses.",
        "If key visibility is required for test, gate it behind a lifecycle/debug authorization signal that is disabled in production.",
        "Add assertions that AES key bits never appear on external_bus_io.rdata during normal operation."
      ]
    },
    {
      "finding_id": "PERM-PLIC-CLINT-BYPASS",
      "status": "confirmed_finding",
      "summary": "PLIC access can be granted by the CLINT permission bit due to a cross-index access-control expression.",
      "vulnerability_category": "Authorization bypass due to incorrect access-control mapping",
      "affected_locations": [
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "access_ctrl",
          "signal_or_register": "connectivity_map_o"
        },
        {
          "file": "tb/ariane_soc_pkg.sv",
          "line_start": 29,
          "line_end": 30,
          "module": "ariane_soc",
          "signal_or_register": "PLIC, CLINT"
        }
      ],
      "evidence": [
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "access_ctrl",
          "object": "connectivity_map_o",
          "evidence_type": "source_snippet",
          "description": "Connectivity for each subordinate/manager pair is normally derived from access_ctrl_i indexed by current privilege level.",
          "supports_claim": "The assignment uses access_ctrl_i[i][j][priv_lvl_i] as the permission bit."
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "access_ctrl",
          "object": "((j==6) && access_ctrl_i[i][7][priv_lvl_i])",
          "evidence_type": "source_snippet",
          "description": "The same assignment adds a special case that grants j==6 access when j==7 access is set.",
          "supports_claim": "For manager/peripheral index 6, connectivity is also granted by the permission bit for index 7."
        },
        {
          "file": "tb/ariane_soc_pkg.sv",
          "line_start": 29,
          "line_end": 30,
          "module": "ariane_soc",
          "object": "axi_slaves_t",
          "evidence_type": "source_snippet",
          "description": "The SoC package defines PLIC as index 6 and CLINT as index 7.",
          "supports_claim": "PLIC = 6 and CLINT = 7, so the special case grants PLIC access based on CLINT permission."
        }
      ],
      "reasoning_summary": "The access-control wrapper grants access to peripheral index 6 when either its own permission bit is set or the permission bit for index 7 is set. Since the SoC package maps index 6 to PLIC and index 7 to CLINT, software or a master authorized only for CLINT can also reach PLIC.",
      "security_impact": "Unauthorized PLIC access may allow manipulation of interrupt-controller state, weakening privilege separation and potentially enabling interrupt spoofing, masking, or denial of service.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The current hardcoded access-control constants may already grant PLIC access, so the bypass may be latent for this exact configuration. The RTL logic itself is still an access-control weakness.",
      "recommended_follow_up": [
        "Remove the special-case OR unless there is a documented and verified policy reason.",
        "Use exact per-peripheral permission bits for PLIC and CLINT.",
        "Add tests or assertions that denying PLIC while allowing CLINT actually blocks PLIC accesses."
      ]
    },
    {
      "finding_id": "PERM-ACCESSCTRL-MUTABLE-VIA-ROM2",
      "status": "potential_warning",
      "summary": "Runtime access-control policy is sourced from ROM2 entries that are writable through the ROM2 bus path.",
      "vulnerability_category": "Mutable authorization policy stored in bus-accessible memory",
      "affected_locations": [
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "access_ctrl_reg"
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 442,
          "line_end": 472,
          "module": "ariane_testharness",
          "signal_or_register": "access_ctrl"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 35,
          "line_end": 43,
          "module": "rom2",
          "signal_or_register": "secure_reg"
        }
      ],
      "evidence": [
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 216,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "access_ctrl_reg",
          "evidence_type": "source_snippet",
          "description": "Access-control registers are derived from ROM2 secure register outputs.",
          "supports_claim": "access_ctrl_reg[0] and access_ctrl_reg[1] are assigned from key_reg_out[2][47:0] and key_reg_out[3][47:0]."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 442,
          "line_end": 450,
          "module": "ariane_testharness",
          "object": "access_ctrl",
          "evidence_type": "source_snippet",
          "description": "The harness expands access_ctrl_reg nibbles into the access-control matrix used by the AXI node.",
          "supports_claim": "access_ctrl[i][j] is assigned from access_ctrl_reg[i][4*j +: 4]."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 454,
          "line_end": 472,
          "module": "ariane_testharness",
          "object": "access_ctrl_i",
          "evidence_type": "source_snippet",
          "description": "The access-control matrix is passed to the AXI node wrapper.",
          "supports_claim": "The AXI node wrapper receives access_ctrl as access_ctrl_i."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 35,
          "line_end": 43,
          "module": "rom2",
          "object": "secure_reg",
          "evidence_type": "source_snippet",
          "description": "ROM2 secure_reg can be modified by a write request.",
          "supports_claim": "On req_i with we_i set, secure_reg at the addressed index is overwritten with wdata_i."
        }
      ],
      "reasoning_summary": "The active AXI access-control matrix is sourced from ROM2 secure_reg entries, and the same secure_reg entries can be overwritten through ROM2 write requests. If an attacker can write ROM2, they can alter the permission policy that controls later bus access.",
      "security_impact": "A ROM2 write can become a self-escalating privilege bypass by rewriting the access-control matrix to permit otherwise forbidden peripheral accesses.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "This depends on an attacker being able to reach ROM2 writes through the upstream access-control settings. Because ROM2 write behavior and access-control sourcing are both visible, the design risk is credible, but exact exploitability depends on privilege configuration and request reachability.",
      "recommended_follow_up": [
        "Make access-control policy storage immutable after reset or after a one-way lock signal is asserted.",
        "Do not source runtime permission policy from a bus-writable array.",
        "Add integrity checks or lifecycle authorization for any update to access-control configuration."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The analysis is limited to visible files under the provided input scope. External module definitions such as axi2mem, axi2apb, the full AXI node internals, and RISC-V privilege enum encodings were not inspected unless present in scope and visible through the provided tools. No simulation, formal verification, lint, synthesis, or dynamic testing was performed."
}