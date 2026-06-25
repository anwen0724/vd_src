{
  "analysis_summary": "The RTL/source under the provided scope contains permission-related security vulnerabilities. The primary issue is that ROM2 is used as a security-sensitive fuse/key/access-control store, but its contents are copied into mutable registers and exposed through a normal AXI/memory write path. Two ROM2 entries are explicitly labeled as access-control values and are wired into the SoC access-control matrix that drives the AXI node connectivity permissions. Therefore, a bus master that can write ROM2 can potentially modify the hardware permission policy. A second related issue is that sensitive key material is readable via bus-accessible paths, including direct ROM2 reads and AES wrapper registers that expose the full AES key. This can undermine permission/authentication mechanisms that rely on key secrecy, such as JTAG/debug access.",
  "findings": [
    {
      "finding_id": "PERM-001",
      "status": "confirmed_finding",
      "summary": "ROM2 stores access-control policy but exposes a bus-driven write path that can modify the registers used to configure AXI permissions.",
      "vulnerability_category": "Improper access control / mutable security policy storage",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 19,
          "line_end": 20,
          "module": "rom2",
          "signal_or_register": "mem"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 35,
          "line_end": 41,
          "module": "rom2",
          "signal_or_register": "secure_reg"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 191,
          "line_end": 212,
          "module": "ariane_peripherals",
          "signal_or_register": "rom2_fuse / rom2_req / rom2_we / key_reg_out"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 216,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "access_ctrl_reg"
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 450,
          "line_end": 450,
          "module": "ariane_testharness",
          "signal_or_register": "access_ctrl"
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "axi_node_intf_wrap",
          "signal_or_register": "connectivity_map_o"
        },
        {
          "file": "tb/ariane_soc_pkg.sv",
          "line_start": 57,
          "line_end": 57,
          "module": "ariane_soc package",
          "signal_or_register": "ROM2Base"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 19,
          "line_end": 20,
          "module": "rom2",
          "object": "mem",
          "evidence_type": "source",
          "description": "ROM2 stores access-control values for master 1 and master 0. Comments state that the first 4 bits correspond to peripheral 0, next 4 to peripheral 1, and so on.",
          "supports_claim": "ROM2 contains access-control policy data, not merely ordinary memory."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 35,
          "line_end": 41,
          "module": "rom2",
          "object": "secure_reg write path",
          "evidence_type": "source",
          "description": "On reset, ROM2 copies constant fuse-like values into secure_reg, but after reset any req_i with we_i asserted writes wdata_i into secure_reg at a bus-derived address.",
          "supports_claim": "The access-control/key store is mutable through the normal request/write interface without a visible authorization check."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 191,
          "line_end": 212,
          "module": "ariane_peripherals",
          "object": "i_axi2rom2 and i_rom2",
          "evidence_type": "source",
          "description": "ariane_peripherals connects an AXI-facing axi2mem instance to the rom2 module, forwarding rom2_req, rom2_we, rom2_addr, and rom2_wdata into ROM2.",
          "supports_claim": "ROM2 write controls are derived from the bus-facing interface."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 216,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "access_ctrl_reg",
          "evidence_type": "source",
          "description": "Access-control registers are directly assigned from ROM2-derived key_reg_out entries.",
          "supports_claim": "Modifying ROM2 secure_reg entries can modify the access-control registers."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 450,
          "line_end": 450,
          "module": "ariane_testharness",
          "object": "access_ctrl",
          "evidence_type": "source",
          "description": "The test harness expands access_ctrl_reg into per-peripheral access-control fields.",
          "supports_claim": "The ROM2-derived access-control registers become the SoC access-control matrix."
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "axi_node_intf_wrap",
          "object": "connectivity_map_o",
          "evidence_type": "source",
          "description": "The AXI node connectivity map is generated directly from access_ctrl_i indexed by current privilege level, with a special case for PLIC/CLINT-related access.",
          "supports_claim": "The access-control matrix controls bus connectivity/permissions."
        },
        {
          "file": "tb/ariane_soc_pkg.sv",
          "line_start": 57,
          "line_end": 57,
          "module": "ariane_soc package",
          "object": "ROM2Base",
          "evidence_type": "source",
          "description": "ROM2 is assigned a memory-mapped base address.",
          "supports_claim": "ROM2 is part of the SoC memory map and can be addressed as a peripheral region."
        }
      ],
      "reasoning_summary": "ROM2 is intended to hold security-sensitive fuse/key data and explicitly includes access-control entries. Those entries are copied to secure_reg and then used to drive access_ctrl_reg, which is expanded into the AXI node access-control matrix. However, secure_reg is writable whenever req_i and we_i are asserted, and these signals are connected to a bus-facing axi2mem path. No lock, privilege check, authentication check, write-once mechanism, or separation between fuse contents and mutable bus registers is visible. Therefore, any bus master with write access to the ROM2 region can potentially alter the permission policy enforced by the interconnect.",
      "security_impact": "An attacker that can reach the ROM2 write path may modify access_ctrl_reg values and thereby change the AXI connectivity permissions. This can grant unauthorized access to protected peripherals such as AES, ROM2, debug, PLIC/CLINT, or other memory-mapped regions, undermining the hardware permission model.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The visible code does not fully prove which masters or privilege levels can initially access ROM2 under the default access-control values, and some instantiated IP such as axi2mem/axi_node internals are not present in full. However, no protection is visible inside ROM2 or the shown integration path, and ROM2 directly drives the permission matrix.",
      "recommended_follow_up": [
        "Make ROM2 access-control/fuse contents immutable after reset or after a secure lock event.",
        "Remove or strictly gate the ROM2 write path; require a hardware root-of-trust-only update mechanism if field updates are needed.",
        "Ensure the ROM2 memory region itself is inaccessible to untrusted masters and lower privilege levels in the initial immutable access policy.",
        "Add explicit hardware authorization checks for ROM2 writes, independent of the mutable access-control values stored in ROM2.",
        "Consider separating access-control fuses from bus-readable/writable key storage and formally verifying that untrusted agents cannot modify the access matrix."
      ]
    },
    {
      "finding_id": "PERM-002",
      "status": "confirmed_finding",
      "summary": "Secret key material is readable via ROM2 and AES peripheral register interfaces.",
      "vulnerability_category": "Sensitive key exposure / improper access control",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "signal_or_register": "rdata_o / secure_reg"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 215,
          "module": "ariane_peripherals",
          "signal_or_register": "jtag_key"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "signal_or_register": "key_in"
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 57,
          "line_end": 57,
          "module": "aes_wrapper",
          "signal_or_register": "key_big"
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 129,
          "line_end": 139,
          "module": "aes_wrapper",
          "signal_or_register": "external_bus_io.rdata"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "object": "rdata_o",
          "evidence_type": "source",
          "description": "ROM2 read data is assigned directly from secure_reg indexed by the captured read address.",
          "supports_claim": "ROM2 key/access-control storage is readable through the ROM2 read interface."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 215,
          "module": "ariane_peripherals",
          "object": "jtag_key",
          "evidence_type": "source",
          "description": "JTAG key is assigned from ROM2-derived key_reg_out.",
          "supports_claim": "ROM2 contains a key used for JTAG/debug-related access."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "object": "key_in",
          "evidence_type": "source",
          "description": "AES wrapper receives key_in from ROM2-derived key_reg_out[0].",
          "supports_claim": "AES key material is sourced from ROM2 secure storage."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 57,
          "line_end": 57,
          "module": "aes_wrapper",
          "object": "key_big",
          "evidence_type": "source",
          "description": "AES wrapper assigns key_big directly from key_in.",
          "supports_claim": "The key exposed by AES registers is the actual key input from ROM2."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 129,
          "line_end": 139,
          "module": "aes_wrapper",
          "object": "external_bus_io.rdata",
          "evidence_type": "source",
          "description": "AES wrapper read mux returns all six 32-bit slices of key_big on external_bus_io.rdata at readable register offsets.",
          "supports_claim": "The AES key is readable through normal peripheral register reads."
        }
      ],
      "reasoning_summary": "Key material from ROM2 is exposed on bus-readable paths. ROM2 directly returns secure_reg contents on reads, and the AES wrapper maps all 192 bits of key_big to readable registers. Because key_big is assigned from key_in and key_in is wired from ROM2-derived key_reg_out[0], the AES key can be read through the AES peripheral. ROM2 also feeds jtag_key, indicating that ROM2 stores debug/JTAG-related secrets. If these keys are used to authenticate privileged access, exposing them can enable permission bypass.",
      "security_impact": "An attacker that can read ROM2 or the AES peripheral can extract AES key material and possibly JTAG/debug-related secrets. This may compromise encrypted data, enable debug authentication bypass, or weaken other key-based permission mechanisms.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The full default access matrix and the complete dmi_jtag implementation are not visible, so the exact set of agents that can read ROM2/AES and the exact use of jtag_key cannot be fully proven. The key exposure itself is explicit in the visible RTL.",
      "recommended_follow_up": [
        "Do not expose secret keys on bus-readable register maps; return zero or an error for key register reads.",
        "Restrict ROM2 read access to only trusted hardware paths or remove direct software-visible reads of secret entries.",
        "Separate public identifiers from secret keys; only expose non-sensitive key IDs to software.",
        "Review JTAG/debug authentication logic to ensure the JTAG key cannot be read by software or untrusted masters.",
        "Add access-control checks inside AES and ROM2 peripherals, not only at the external interconnect."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The analysis is limited to files under the provided input scope. Some instantiated modules and external IP internals are not fully visible, including complete axi2mem/axi_node behavior and dmi_jtag authentication semantics. The findings are based on visible source evidence showing unprotected writable and readable paths in security-sensitive modules and their integration into the permission system."
}