{
  "analysis_summary": "The scoped RTL contains permission-related security vulnerabilities around sensitive key/fuse storage and AES register exposure. The design includes an AXI-node access-control mechanism driven by privilege level and an access-control table, but sensitive peripherals behind that mechanism do not enforce local authorization. The AES wrapper directly exposes its full 192-bit key through readable register addresses. The ROM2 block, described as holding fuse/key values, permits reads and writes based only on bus request and write-enable signals; its secure registers feed AES key material, JTAG key material, and the interconnect access-control policy.",
  "findings": [
    {
      "finding_id": "PERM-001",
      "status": "confirmed_finding",
      "summary": "AES wrapper exposes the full 192-bit AES key through bus-readable registers.",
      "vulnerability_category": "Sensitive key disclosure due to missing register read permission enforcement",
      "affected_locations": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 57,
          "line_end": 139,
          "module": "aes_wrapper",
          "signal_or_register": "key_big / external_bus_io.rdata"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "signal_or_register": "key_reg_out[0] / key_in"
        }
      ],
      "evidence": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 57,
          "line_end": 57,
          "module": "aes_wrapper",
          "object": "key_big",
          "evidence_type": "source_assignment",
          "description": "AES key input is assigned directly to internal key_big.",
          "supports_claim": "Shows the readable key_big value is the actual AES key input."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 129,
          "line_end": 139,
          "module": "aes_wrapper",
          "object": "external_bus_io.rdata",
          "evidence_type": "source_read_mux",
          "description": "AES read mux returns all six 32-bit words of key_big at register indices 16 through 21.",
          "supports_claim": "Shows full 192-bit AES key material is exposed through bus-readable registers."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "object": "key_in",
          "evidence_type": "integration_wiring",
          "description": "AES wrapper is connected to ROM2-derived key register output.",
          "supports_claim": "Shows the exposed AES key comes from key_reg_out[0], the ROM2-derived key register."
        }
      ],
      "reasoning_summary": "The AES wrapper accepts a 192-bit key input, assigns it to key_big, and directly places each 32-bit slice of key_big on external_bus_io.rdata for readable address indices 16 through 21. No local privilege, secure-state, lock, or read-permission check is visible in the wrapper. The wrapper also sets ready high and error low, so it does not reject unauthorized reads locally. Since the integration wires key_reg_out[0] into key_in, any bus master that can reach the AES register window can read the ROM2-provisioned AES key.",
      "security_impact": "A requester with access to the AES APB register window can read the full AES key, defeating confidentiality of hardware key material and compromising encrypted data or authentication mechanisms that rely on that key.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The AXI interconnect may restrict which masters can reach AES, but the AES peripheral itself has no visible local permission check. The finding applies to any principal granted AES access or able to influence the access-control table.",
      "recommended_follow_up": [
        "Remove key readback registers or return zero/error for key address indices.",
        "Add local authorization or lifecycle/lock checks if privileged key export is truly required.",
        "Add security tests or assertions proving AES key material never appears on external_bus_io.rdata for unauthorized or normal runtime accesses."
      ]
    },
    {
      "finding_id": "PERM-002",
      "status": "confirmed_finding",
      "summary": "ROM2 fuse/key registers are bus-readable and bus-writable without local permission enforcement, and they feed keys plus interconnect access-control policy.",
      "vulnerability_category": "Missing authorization for security-critical fuse/key and policy registers",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 17,
          "line_end": 47,
          "module": "rom2",
          "signal_or_register": "secure_reg / rdata_o"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 194,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "rom2_fuse / key_reg_out / access_ctrl_reg / jtag_key"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "signal_or_register": "key_reg_out[0]"
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 450,
          "line_end": 490,
          "module": "ariane_testharness",
          "signal_or_register": "access_ctrl / ROM2 address map"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 1,
          "line_end": 34,
          "module": "rom2",
          "object": "secure_reg",
          "evidence_type": "source_comment_and_initialization",
          "description": "ROM2 is documented as containing all keys and initializes secure_reg from constant fuse-like memory on reset.",
          "supports_claim": "Shows ROM2 stores security-sensitive key/fuse material."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 36,
          "line_end": 43,
          "module": "rom2",
          "object": "secure_reg",
          "evidence_type": "source_control_flow",
          "description": "ROM2 read/write logic checks req_i and we_i only; writes update secure_reg indexed by address, and reads update raddr_q indexed by address.",
          "supports_claim": "Shows no local privilege, write-lock, or permission signal gates read or write access."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "object": "rdata_o",
          "evidence_type": "source_assignment",
          "description": "ROM2 returns secure_reg contents on rdata_o when raddr_q is in range.",
          "supports_claim": "Shows bus read path can expose secure_reg contents."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 194,
          "line_end": 200,
          "module": "ariane_peripherals",
          "object": "i_axi2rom2",
          "evidence_type": "integration_wiring",
          "description": "AXI-to-memory bridge connects the rom2_fuse AXI port to rom2 request, write-enable, address, write-data, and read-data signals.",
          "supports_claim": "Shows ROM2 is reachable as an AXI-connected peripheral."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 212,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "key_reg_out",
          "evidence_type": "integration_wiring",
          "description": "ROM2 secure_reg output feeds jtag_key and access_ctrl_reg.",
          "supports_claim": "Shows ROM2 contents affect JTAG key material and access-control policy state."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "object": "key_reg_out[0]",
          "evidence_type": "integration_wiring",
          "description": "ROM2 secure_reg output feeds AES key input.",
          "supports_claim": "Shows ROM2 contents affect AES key material."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 450,
          "line_end": 472,
          "module": "ariane_testharness",
          "object": "access_ctrl",
          "evidence_type": "integration_wiring",
          "description": "Harness derives interconnect access_ctrl entries from access_ctrl_reg and passes them into the AXI node.",
          "supports_claim": "Shows ROM2-derived access_ctrl_reg controls interconnect permissions."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 476,
          "line_end": 490,
          "module": "ariane_testharness",
          "object": "ROM2Base / ROM2Length",
          "evidence_type": "address_map",
          "description": "ROM2 base and end addresses are included in the AXI-node memory map.",
          "supports_claim": "Shows ROM2 is mapped into the SoC address space."
        }
      ],
      "reasoning_summary": "The ROM2 module is described as holding keys/fuse values, copies constants into secure_reg on reset, and then allows secure_reg reads and writes whenever req_i is asserted, using we_i to select write versus read behavior. No local permission, privilege, lock, lifecycle, or requester identity check is visible. Integration evidence shows this is security-critical because secure_reg drives AES key material, JTAG key material, and access-control policy bits used by the AXI node. Therefore, any requester that can reach ROM2 can potentially disclose or modify key and permission state.",
      "security_impact": "A requester with ROM2 access can potentially read secret key/fuse material and modify AES keys, JTAG key material, and the access-control policy. Because ROM2-derived values feed the interconnect permission table, this can become a privilege-escalation path as well as a confidentiality and integrity compromise.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The scoped source shows interconnect-level access control, so unauthorized ROM2 access may be blocked for some masters in some privilege states. The initial effective policy for every requester is not fully proven from the visible source. Also, rdata_o is 64 bits while secure_reg entries are 192 bits, so exact readback width/truncation depends on SystemVerilog sizing, but the unprotected read path remains present.",
      "recommended_follow_up": [
        "Make ROM2 key/fuse storage read-protected and write-protected after reset/provisioning.",
        "Separate immutable fuse values from bus-programmable policy registers, or require authenticated privileged writes for policy updates.",
        "Prevent access-control policy storage from being writable by requesters governed by that same policy.",
        "Add assertions proving unauthorized ROM2 writes cannot change AES, JTAG, or access-control state."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The analysis is limited to visible source files under the provided input scope and did not use simulation, formal analysis, synthesis, or external documentation. The source shows AXI-node privilege/access-control logic, but not a complete proof of the initial effective permissions for every master and privilege level. Findings therefore focus on explicit local endpoint behavior and integration evidence showing sensitive data and policy state exposure if the endpoint is reachable."
}