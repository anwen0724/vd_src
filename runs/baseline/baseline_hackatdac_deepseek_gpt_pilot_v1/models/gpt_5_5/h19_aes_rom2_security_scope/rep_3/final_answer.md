{
  "analysis_summary": "The inspected RTL contains permission-related security vulnerabilities in the ROM2/fuse key store, the AES peripheral register interface, and the access-control policy path. ROM2 is described as containing all keys and access-control words, but after reset it exposes its secure register array through a memory-mapped AXI-to-memory path and accepts writes based only on req_i/we_i. Its outputs directly feed the JTAG key, AES key, and interconnect access-control registers. Separately, the AES wrapper maps the full 192-bit AES key into readable register addresses. These are permission/security-boundary issues because secrets and policy state are readable or mutable without local authorization, privilege, master-ID, lock, or lifecycle checks visible in the source.",
  "findings": [
    {
      "finding_id": "FINDING-001",
      "status": "confirmed_finding",
      "summary": "ROM2/fuse secure registers are memory-mapped and writable/readable without visible authorization checks.",
      "vulnerability_category": "Missing authorization / insecure memory-mapped access to key and policy registers",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 5,
          "line_end": 13,
          "module": "rom2",
          "signal_or_register": "req_i, we_i, addr_i, wdata_i, rdata_o, secure_reg"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 18,
          "line_end": 24,
          "module": "rom2",
          "signal_or_register": "mem"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 34,
          "line_end": 40,
          "module": "rom2",
          "signal_or_register": "secure_reg"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "signal_or_register": "rdata_o"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 191,
          "line_end": 212,
          "module": "ariane_peripherals",
          "signal_or_register": "i_axi2rom2, i_rom2, key_reg_out"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "jtag_key, access_ctrl_reg"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "signal_or_register": "key_in/key_reg_out[0]"
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 476,
          "line_end": 490,
          "module": "ariane_testharness",
          "signal_or_register": "ROM2Base/ROM2Length mapping"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 1,
          "line_end": 3,
          "module": "rom2",
          "object": "ROM2 comment",
          "evidence_type": "source_comment",
          "description": "ROM2 is explicitly documented as containing all keys.",
          "supports_claim": "Shows the security-sensitive purpose of the block."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 18,
          "line_end": 24,
          "module": "rom2",
          "object": "mem",
          "evidence_type": "source_code",
          "description": "ROM2 constant array stores AES key, JTAG key, and access-control words.",
          "supports_claim": "The memory contains security-critical secrets and permission policy data."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 34,
          "line_end": 34,
          "module": "rom2",
          "object": "secure_reg <= mem",
          "evidence_type": "source_code",
          "description": "On reset, ROM2 copies constant contents into secure_reg.",
          "supports_claim": "secure_reg becomes the active storage for keys and access-control values."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 36,
          "line_end": 40,
          "module": "rom2",
          "object": "if(req_i) ... secure_reg[...] <= wdata_i",
          "evidence_type": "source_code",
          "description": "After reset, any request with write enable updates secure_reg indexed by address.",
          "supports_claim": "No authorization, privilege, or lock check is visible before modifying secure_reg."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "object": "assign rdata_o = (raddr_q < RomSize) ? secure_reg[raddr_q] : '0",
          "evidence_type": "source_code",
          "description": "Read path returns secure_reg contents on rdata_o.",
          "supports_claim": "Memory-mapped reads can expose secure_reg entries."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 191,
          "line_end": 212,
          "module": "ariane_peripherals",
          "object": "i_axi2rom2 and i_rom2",
          "evidence_type": "source_code",
          "description": "ROM2 is connected behind an AXI-to-memory adapter and secure_reg is exported as key_reg_out.",
          "supports_claim": "AXI traffic drives req/we/address/data for ROM2, and ROM2 secure_reg drives system key_reg_out."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "jtag_key/access_ctrl_reg assignments",
          "evidence_type": "source_code",
          "description": "ROM2-derived key_reg_out drives JTAG key and access-control registers.",
          "supports_claim": "ROM2 contents affect authentication/debug and permission policy."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "object": ".key_in(key_reg_out[0])",
          "evidence_type": "source_code",
          "description": "AES key input is connected to key_reg_out[0].",
          "supports_claim": "ROM2 contents provide AES key material."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 476,
          "line_end": 490,
          "module": "ariane_testharness",
          "object": "ROM2Base mapping",
          "evidence_type": "source_code",
          "description": "ROM2 is included in the SoC address map using ROM2Base and ROM2Length.",
          "supports_claim": "ROM2 is memory-mapped in the system address space."
        }
      ],
      "reasoning_summary": "ROM2 is intended to act like a secure fuse/key store, but the implementation copies constants into secure_reg and then allows secure_reg to be read and written through req_i/we_i without local authorization. Because an AXI-to-memory adapter connects the SoC bus to ROM2, and because secure_reg outputs feed JTAG, AES, and access-control state, memory-mapped access to ROM2 can disclose or alter security-critical state.",
      "security_impact": "An attacker able to issue transactions to the ROM2 address range may read AES/JTAG keys and access-control policy words, overwrite AES/JTAG keys, corrupt or weaken interconnect access policy, gain unauthorized peripheral/memory access, or cause denial of service. Since the permission policy itself is sourced from mutable ROM2 registers, this can become a privilege-escalation path.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "Exploitability by a specific unprivileged software context depends on the initial interconnect access-control values and current privilege/master routing. However, the ROM2 block itself has no local permission enforcement in the visible source.",
      "recommended_follow_up": [
        "Make ROM2/fuse contents immutable after reset, or add a one-time lock that prevents writes before untrusted software can execute.",
        "Add explicit authorization checks for ROM2 reads/writes based on privilege level, master identity, lifecycle/debug state, and secure boot state.",
        "Separate secret-key storage from memory-mapped software-visible data; do not expose key material through rdata_o.",
        "Return an error or zero data for unauthorized accesses and verify this behavior with formal/security assertions.",
        "Ensure access-control policy storage cannot be modified by any master whose permissions are governed by that policy."
      ]
    },
    {
      "finding_id": "FINDING-002",
      "status": "confirmed_finding",
      "summary": "AES peripheral exposes the full AES key through readable memory-mapped registers.",
      "vulnerability_category": "Secret exposure through readable registers / missing read permission check",
      "affected_locations": [
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
          "signal_or_register": "external_bus_io.rdata, key_big"
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 52,
          "line_end": 52,
          "module": "aes_wrapper",
          "signal_or_register": "external_bus_io.error"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "signal_or_register": "key_in/key_reg_out[0]"
        }
      ],
      "evidence": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 57,
          "line_end": 57,
          "module": "aes_wrapper",
          "object": "assign key_big = key_in",
          "evidence_type": "source_code",
          "description": "AES wrapper assigns key_big directly from key_in.",
          "supports_claim": "The value exposed by the read mux is the AES key supplied to the AES core."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 129,
          "line_end": 139,
          "module": "aes_wrapper",
          "object": "external_bus_io.rdata = key_big[...]",
          "evidence_type": "source_code",
          "description": "AES wrapper read mux returns each 32-bit slice of the 192-bit AES key at addresses 16 through 21.",
          "supports_claim": "A bus reader can reconstruct the full AES key through register reads."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 52,
          "line_end": 52,
          "module": "aes_wrapper",
          "object": "assign external_bus_io.error = 1'b0",
          "evidence_type": "source_code",
          "description": "AES wrapper hardwires bus error output to zero.",
          "supports_claim": "The AES wrapper does not signal access violations for key-register reads."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "object": ".key_in(key_reg_out[0])",
          "evidence_type": "source_code",
          "description": "AES key input is driven by ROM2-derived key_reg_out[0].",
          "supports_claim": "The readable key_big value corresponds to ROM2-provisioned AES key material."
        }
      ],
      "reasoning_summary": "The AES key is assigned from key_in and passed to the AES core, but the register read mux also returns all six 32-bit slices of that same key. No local privilege or authorization check is present in the AES wrapper. Therefore, any master allowed to read the AES peripheral register window can recover the AES key.",
      "security_impact": "Any software or bus master with read access to the AES peripheral can recover the full 192-bit AES key, defeating confidentiality of encrypted data and undermining the ROM/fuse key-protection model.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "Whether unprivileged software can reach the AES register window depends on interconnect access policy. The local AES wrapper has no visible key-read protection.",
      "recommended_follow_up": [
        "Remove key readback registers from the AES memory map or hardwire them to zero/non-secret status values.",
        "Add explicit read authorization if key inspection is required for a secure provisioning mode, and permanently disable it before normal operation.",
        "Return an access error for reads of secret-key addresses in production mode.",
        "Add security assertions that key material never appears on external_bus_io.rdata in normal operation."
      ]
    },
    {
      "finding_id": "FINDING-003",
      "status": "potential_warning",
      "summary": "Interconnect permission policy is derived from ROM2 data that is mutable through the ROM2 bus interface.",
      "vulnerability_category": "Mutable access-control policy / permission bypass risk",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 18,
          "line_end": 24,
          "module": "rom2",
          "signal_or_register": "mem access-control entries"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 34,
          "line_end": 40,
          "module": "rom2",
          "signal_or_register": "secure_reg"
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
          "file": "tb/ariane_testharness.sv",
          "line_start": 472,
          "line_end": 472,
          "module": "ariane_testharness",
          "signal_or_register": "access_ctrl_i"
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "axi_node_intf_wrap",
          "signal_or_register": "connectivity_map_o"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 20,
          "line_end": 21,
          "module": "rom2",
          "object": "access-control entries in mem",
          "evidence_type": "source_code",
          "description": "ROM2 mem includes access-control words for masters.",
          "supports_claim": "Permission policy data is stored in ROM2 alongside keys."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 34,
          "line_end": 40,
          "module": "rom2",
          "object": "secure_reg",
          "evidence_type": "source_code",
          "description": "ROM2 secure_reg is loaded from mem and can later be written via bus request.",
          "supports_claim": "The policy-bearing storage is mutable after reset."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 216,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "access_ctrl_reg[0/1]",
          "evidence_type": "source_code",
          "description": "Access-control registers are assigned from ROM2-derived key_reg_out entries.",
          "supports_claim": "Interconnect policy is sourced from ROM2 secure_reg outputs."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 450,
          "line_end": 450,
          "module": "ariane_testharness",
          "object": "assign access_ctrl[i][j] = access_ctrl_reg[i][4*j +: 4]",
          "evidence_type": "source_code",
          "description": "The testharness slices access_ctrl_reg into the access_ctrl matrix.",
          "supports_claim": "ROM2-derived bits become per-peripheral/per-privilege access-control bits."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 472,
          "line_end": 472,
          "module": "ariane_testharness",
          "object": ".access_ctrl_i(access_ctrl)",
          "evidence_type": "source_code",
          "description": "The access-control matrix is passed to the AXI node.",
          "supports_claim": "The AXI interconnect uses this policy input."
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "axi_node_intf_wrap",
          "object": "connectivity_map_o assignment",
          "evidence_type": "source_code",
          "description": "AXI connectivity is computed from access_ctrl_i indexed by priv_lvl_i.",
          "supports_claim": "Permission decisions depend directly on ROM2-derived access-control data."
        }
      ],
      "reasoning_summary": "The AXI node permission map is derived from access_ctrl_reg, which is sourced from ROM2 secure_reg. Since ROM2 secure_reg is writable through the memory-mapped ROM2 interface, the permission policy can potentially be changed by a bus master. This is a permission-design weakness: the enforcement policy is stored in a mutable register bank that lacks visible local authorization.",
      "security_impact": "If a master can write ROM2 policy entries, it may grant itself or another master access to restricted peripherals or memory regions, bypassing intended privilege separation. It may also revoke legitimate access and cause denial of service.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The dependency chain is visible, but the exact reachable privilege escalation depends on initial access_ctrl settings, current priv_lvl_i behavior, and whether a given attacker-controlled master can initially access ROM2.",
      "recommended_follow_up": [
        "Store access-control policy in immutable or locked registers after secure boot/provisioning.",
        "Protect policy updates with a hardware root of trust, lifecycle state, and master/privilege checks.",
        "Ensure the bus master whose permissions are controlled by a policy cannot write that policy.",
        "Add assertions that access-control policy cannot change after lock or after reset deassertion in production mode.",
        "Consider fail-closed defaults if policy storage is invalid or tampered with."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The analysis is based only on visible source files and read/search tool results. Some large file reads were truncated by the tool, and no simulation, formal checking, synthesis, or external documentation was used. Initial interconnect policy may limit which masters can reach ROM2/AES, but local ROM2 and AES modules lack visible permission checks for the identified sensitive operations."
}