{
  "analysis_summary": "Analyzed a RISC-V Ariane/OpenPiton SoC subsystem with cryptographic accelerators (AES0-2, SHA256, HMAC), access control (ACCT), and register locking (REGLK) modules. The design implements a layered permission scheme using privilege-level-indexed access control bits, register lock bits per peripheral, and debug mode key clearing. Several permission-related vulnerabilities were identified: (1) inconsistent debug_mode key clearing where certain key slots are not zeroed during debug, (2) we_flag inputs that can override access control and register lock protections, (3) a copy-paste index bug in reglk_wrapper that causes wrong register locking behavior, and (4) an insufficient output mapping in acct_wrapper where only 3 of potentially many access control entries are actually routed to the output, making most access control bits non-functional.",
  "findings": [
    {
      "finding_id": "F-001",
      "status": "confirmed_finding",
      "summary": "Inconsistent debug_mode key clearing across crypto wrappers — certain key slots remain readable in debug mode while others are zeroed",
      "vulnerability_category": "Debug Interface Bypass / Insufficient Protection of Sensitive Data",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/aes0/aes0_wrapper.sv",
          "line_start": 57,
          "line_end": 59,
          "module": "aes0_wrapper",
          "signal_or_register": "key_big2, key_big0, key_big1"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/aes2/aes2_wrapper.sv",
          "line_start": 52,
          "line_end": 55,
          "module": "aes2_wrapper",
          "signal_or_register": "cii_K0, cii_K1, cii_K2"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/aes1/aes1_wrapper.sv",
          "line_start": 139,
          "line_end": 146,
          "module": "aes1_wrapper",
          "signal_or_register": "core_key0, core_key1, core_key2"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac_wrapper.sv",
          "line_start": 52,
          "line_end": 54,
          "module": "hmac_wrapper",
          "signal_or_register": "key, ikey_hash, okey_hash"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/aes0/aes0_wrapper.sv",
          "line_start": 56,
          "line_end": 59,
          "module": "aes0_wrapper",
          "object": "key_big0, key_big1, key_big2",
          "evidence_type": "source_code",
          "description": "key_big0 = debug_mode_i ? 192'b0 : {key0[...]}; key_big1 = debug_mode_i ? 192'b0 : {key1[...]}; But key_big2 = {key2[...]} — NO debug_mode_i zeroing for key2 slot",
          "supports_claim": "Key slot 2 (key_big2) is NOT zeroed when debug_mode_i is active, while key0 and key1 slots ARE zeroed. This allows a debugger to read key2 material."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/aes2/aes2_wrapper.sv",
          "line_start": 52,
          "line_end": 55,
          "module": "aes2_wrapper",
          "object": "cii_K0, cii_K1, cii_K2",
          "evidence_type": "source_code",
          "description": "cii_K0 = debug_mode_i ? 128'b0 : ...; cii_K1 = debug_mode_i ? 128'b0 : ...; cii_K2 = {key2[...]} — NO debug_mode_i check",
          "supports_claim": "Same pattern: key slot 2 (cii_K2) is not protected in debug mode."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/aes1/aes1_wrapper.sv",
          "line_start": 139,
          "line_end": 146,
          "module": "aes1_wrapper",
          "object": "core_key0, core_key1, core_key2",
          "evidence_type": "source_code",
          "description": "core_key0 = debug_mode_i ? 'b0 : ...; core_key2 = debug_mode_i ? 'b0 : ...; core_key1 = {key_reg1[...]} — NO debug_mode_i for key1",
          "supports_claim": "Here key1 is the unprotected slot, showing an inconsistent approach across wrappers."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac_wrapper.sv",
          "line_start": 52,
          "line_end": 54,
          "module": "hmac_wrapper",
          "object": "key, ikey_hash, okey_hash",
          "evidence_type": "source_code",
          "description": "key = debug_mode_i ? 256'b0 : ...; okey_hash = debug_mode_i ? 256'b0 : ...; ikey_hash = {ikey_hash_bytes[...]} — NO debug_mode_i",
          "supports_claim": "HMAC ikey_hash is not zeroed during debug."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 55,
          "line_end": 55,
          "module": "riscv_peripherals",
          "object": "debug_mode_i",
          "evidence_type": "source_code",
          "description": "debug_mode_i input is passed to all crypto wrappers; the source of debug_mode_i is external to this module",
          "supports_claim": "debug_mode_i is used throughout; the inconsistent protection leaves some keys exposed."
        }
      ],
      "reasoning_summary": "Across four crypto wrappers (aes0, aes1, aes2, hmac), the debug_mode_i signal is intended to zero out cryptographic keys to prevent debugger extraction. However, in each wrapper, at least one key slot (out of 3 in each AES, or 2 key-related buffers in HMAC) lacks the debug_mode_i gating. This inconsistency is likely due to copy-paste errors during development. An attacker with debug access could read these unprotected key slots and extract secret key material.",
      "security_impact": "HIGH — An external debugger or an attacker who gains debug-mode access could extract partial cryptographic key material from unprotected key slots. Since all three key slots are typically needed for full operation, partial key leakage still significantly compromises the cryptosystem. This bypasses the intended debug protection mechanism.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "We cannot confirm from this source view alone how debug_mode_i is generated or gated (e.g., whether it requires authentication). However, the RTL clearly shows inconsistent application of the debug protection among key slots within the same module, which is a design flaw regardless of how debug_mode is obtained.",
      "recommended_follow_up": [
        "Update all crypto wrappers to consistently apply debug_mode_i zeroing to ALL key slots (e.g., key_big2 in aes0, cii_K2 in aes2, core_key1 in aes1, ikey_hash in hmac).",
        "Consider a centralized or automated mechanism (e.g., a parameterized wrapper) to ensure all sensitive registers are uniformly cleared in debug mode.",
        "Verify the debug authentication chain to understand who can assert debug_mode_i."
      ]
    },
    {
      "finding_id": "F-002",
      "status": "potential_warning",
      "summary": "we_flag signals can forcibly override access control and register lock protections, potentially bypassing the permission system",
      "vulnerability_category": "Access Control Bypass",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 49,
          "line_end": 49,
          "module": "acct_wrapper",
          "signal_or_register": "we_flag, acc_ctrl_o"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1194,
          "line_end": 1194,
          "module": "riscv_peripherals",
          "signal_or_register": "we_flag_1, reglk_ctrl"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 49,
          "line_end": 49,
          "module": "acct_wrapper",
          "object": "acc_ctrl_o",
          "evidence_type": "source_code",
          "description": "assign acc_ctrl_o = {acct_mem[3*0+2], acct_mem[3*0+1], acct_mem[3*0+0]|{8{we_flag}}}; — we_flag OR'd into the access control output, forcing it to 1",
          "supports_claim": "The we_flag signal forces at least the first peripheral's access control bits to '1' (full access), bypassing the configured acct_mem values."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1194,
          "line_end": 1194,
          "module": "riscv_peripherals",
          "object": "reglk_ctrl_i",
          "evidence_type": "source_code",
          "description": ".reglk_ctrl_i ( reglk_ctrl[1*8+7:1*8] | we_flag_1 ) — we_flag_1 OR'd into register lock control, potentially unlocking registers",
          "supports_claim": "we_flag_1 can force register lock bits to 1, allowing writes to otherwise locked registers."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 56,
          "line_end": 60,
          "module": "riscv_peripherals",
          "object": "we_flag_0..4",
          "evidence_type": "source_code",
          "description": "we_flag_0 through we_flag_4 are external inputs to riscv_peripherals module; their source and security control is not visible in this source view",
          "supports_claim": "The origin and gating of we_flag signals is unknown; if they can be controlled by untrusted software or hardware, they represent a permission bypass."
        }
      ],
      "reasoning_summary": "The we_flag signals (we_flag_0 through we_flag_4) are used to force-override access control outputs and register lock inputs at the hardware level. In acct_wrapper, we_flag directly ORs into the access control output, forcing at least the first peripheral's access bits to '1' (granting access). In riscv_peripherals, we_flag_1 is OR'd with the reglk_ctrl bits for one peripheral, potentially allowing register writes even when locked. The provenance and security controls around these we_flag signals are not visible in the provided source view — they could be tied to test modes, debug features, or other mechanisms. If exploitable, this completely bypasses the access control layer.",
      "security_impact": "MEDIUM-HIGH — If we_flag signals can be asserted by less-privileged execution modes (or via fault injection), the entire access control and register locking scheme can be defeated, enabling unauthorized access to cryptographic keys and control registers.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The source and control logic for we_flag_0..4 signals is outside the analyzed scope. We cannot determine whether these are test-only signals tied to a secure test controller, or whether they could be driven by software-accessible registers or external interfaces.",
      "recommended_follow_up": [
        "Trace the origin and control path of we_flag_0..4 signals to determine who can assert them.",
        "Ensure we_flag signals are gated by a secure, authenticated mechanism (e.g., life-cycle state, fuse, or authenticated debug).",
        "Consider removing OR-based overrides in production silicon or replacing with a secure unlock protocol."
      ]
    },
    {
      "finding_id": "F-003",
      "status": "confirmed_finding",
      "summary": "Copy-paste index bug in reglk_wrapper write path — writing to reglk_mem[2] reads back reglk_mem[3] in the locked case, corrupting data and potentially bypassing lock",
      "vulnerability_category": "Implementation Bug / Register Lock Bypass",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 85,
          "line_end": 85,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_mem[2]"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 51,
          "line_end": 93,
          "module": "reglk_wrapper",
          "object": "reglk_mem write case",
          "evidence_type": "source_code",
          "description": "Write case: address 1 -> reglk_mem[1] <= reglk_ctrl[1] ? reglk_mem[1] : wdata; address 2 -> reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[3] : wdata; // Uses reglk_mem[3] instead of reglk_mem[2]",
          "supports_claim": "In the locked case for address 2, the RTL reads back reglk_mem[3] and assigns it to reglk_mem[2] instead of preserving reglk_mem[2]'s current value. This corrupts reglk_mem[2] with reglk_mem[3]'s content whenever a write is attempted while locked."
        }
      ],
      "reasoning_summary": "In the reglk_wrapper module, the write-side always block includes a case statement for addresses 0 through 5. At address 2, the write assignment is:\n  reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[3] : wdata;\nThe intent is clearly to preserve reglk_mem[2] when locked (i.e., reglk_ctrl[1] ? reglk_mem[2] : wdata). Instead, it uses reglk_mem[3] on the right-hand side, which is a copy-paste error from the address 3 case.\nThis means:\n- When reglk_ctrl[1] is asserted (write locked) and a write to address 2 occurs, reglk_mem[2] gets overwritten with the contents of reglk_mem[3].\n- This corrupts the register lock configuration for the peripheral controlled by reglk_mem[2], potentially unlocking registers or causing unintended lock states.\n- The lock mechanism for peripheral slot 2 is effectively bypassed.",
      "security_impact": "MEDIUM — This bug can cause unintended modification of register lock bits for peripheral slot 2. An attacker who can write to the REGLK address space could leverage this to corrupt lock settings, either unlocking protected registers or locking critical control registers, leading to denial of service or privilege escalation.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The bug is clearly visible in the RTL. The only uncertainty is the exact peripheral mapping to reglk_mem[2] and how critical that peripheral is. From the riscv_peripherals wiring, each reglk_mem slot controls an 8-bit lock field for one peripheral; slot 2 controls one of the crypto or system peripherals.",
      "recommended_follow_up": [
        "Fix line 85 in reglk_wrapper.sv: change 'reglk_mem[3]' to 'reglk_mem[2]'.",
        "Review all other reglk_mem assignments (addresses 0-5) for similar copy-paste errors (address 2 line 85 uses reglk_mem[3], address 0 line 83 uses reglk_ctrl[3] not reglk_ctrl[0] — check if this is intentional).",
        "Add formal verification assertions to ensure write-locked registers retain their previous value on attempted writes."
      ]
    },
    {
      "finding_id": "F-004",
      "status": "potential_warning",
      "summary": "acct_wrapper outputs only 3 of its access control entries; the remaining entries may be non-functional, reducing effective access control coverage",
      "vulnerability_category": "Insufficient Access Control Coverage",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 33,
          "line_end": 49,
          "module": "acct_wrapper",
          "signal_or_register": "acct_mem, acc_ctrl_o"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 216,
          "line_end": 222,
          "module": "riscv_peripherals",
          "signal_or_register": "acc_ctrl_c, acc_ctrl"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 33,
          "line_end": 33,
          "module": "acct_wrapper",
          "object": "AcCt_MEM_SIZE",
          "evidence_type": "source_code",
          "description": "localparam AcCt_MEM_SIZE = NB_SLAVE*3; // With NB_SLAVE=1, this is 3 entries",
          "supports_claim": "The memory has only 3 entries (acct_mem[0:2]), but the case statement handles addresses 0-9 (10 entries)."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 49,
          "line_end": 49,
          "module": "acct_wrapper",
          "object": "acc_ctrl_o",
          "evidence_type": "source_code",
          "description": "assign acc_ctrl_o = {acct_mem[3*0+2], acct_mem[3*0+1], acct_mem[3*0+0]|{8{we_flag}}}; — only acct_mem[0], [1], [2] are routed to the output",
          "supports_claim": "Even though the case statement can read/write acct_mem indices 3-9, these entries are never connected to acc_ctrl_o, meaning any access control configuration written to addresses 3-9 has no effect."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 216,
          "line_end": 222,
          "module": "riscv_peripherals",
          "object": "acc_ctrl_c",
          "evidence_type": "source_code",
          "description": "logic [3:0][NB_PERIPHERALS-1:0] acc_ctrl_c; assign acc_ctrl_c[i][j] = acc_ctrl[j*4+i] | (j==5 && acc_ctrl[4*4+i]);",
          "supports_claim": "The top-level expects acc_ctrl to provide 4*NB_PERIPHERALS bits (4 privilege levels x N peripherals), but acct_wrapper only outputs 3*32=96 bits (covering only 3 peripherals). The mismatch may cause most peripherals to have no effective access control."
        }
      ],
      "reasoning_summary": "The acct_wrapper module is parameterized with NB_SLAVE=1, giving AcCt_MEM_SIZE=3 (three 32-bit access control registers). However, the module also has NB_PERIPHERALS=9 as a parameter, and its case statement handles 10 address slots (0-9). The output acc_ctrl_o only concatenates acct_mem[0], [1], and [2]. In riscv_peripherals.sv, acc_ctrl is used to build a 4xNB_PERIPHERALS array (acc_ctrl_c), but the unconnected entries would be floating or zero, meaning most peripherals would have no effective access control gating. The bootrom access check at line 517 does use acc_ctrl_c[priv_lvl_i][0], confirming the access control bits are used. The mismatch between acct_wrapper's output width and the expected NB_PERIPHERALS*4 width suggests the design may be incomplete or rely on default/zero values for the remaining bits, which could inadvertently grant or deny access.",
      "security_impact": "MEDIUM — If access control bits for peripherals beyond the first 3 are not properly driven, those peripherals may have undefined or default (possibly permissive) access control, allowing unauthorized access to sensitive crypto and system peripherals.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The incomplete output could be intentional if the intention is to only protect 3 peripherals, or the actual instantiation may use different parameters (NB_SLAVE > 1). Without seeing the actual parameter override in the instantiation hierarchy, we cannot confirm the exact extent of the coverage gap. The case statement handling more entries than the array size is also suspicious — this may be a Verilog elaboration warning or simulation mismatch.",
      "recommended_follow_up": [
        "Verify the actual NB_SLAVE and NB_PERIPHERALS parameter values used in synthesis/elaboration.",
        "Ensure acc_ctrl_o width matches the expected number of peripherals and privilege levels.",
        "Add elaboration-time assertions to check array bounds for acct_mem accesses.",
        "Audit whether all peripheral access control bits in acc_ctrl_c are properly driven and not left at default values."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The analysis is limited to the files under the provided input scope (piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv and the wrapper files under src/). We cannot see: (1) the source and control logic for we_flag_0..4, debug_mode_i, priv_lvl_i, and jtag_unlock signals; (2) the actual parameter overrides used for NB_SLAVE, NB_PERIPHERALS; (3) the downstream peripheral instantiation and address decoding to confirm which peripheral maps to which access control bit; (4) the axi_lite_interface module implementation; (5) the full integration-level PMP and privilege enforcement logic. These gaps introduce some uncertainty about the exploitability of the reported issues in the full system context."
}