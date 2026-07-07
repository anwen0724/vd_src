{
  "analysis_summary": "A thorough RTL security analysis was performed on the HackATDAC 2021 peripheral subsystem under piton/design/chip/tile/ariane/. The scope includes five SystemVerilog source files: reglk_wrapper.sv (register-lock controller), acct_wrapper.sv (access-control table), hmac_wrapper.sv (HMAC/SHA-256 wrapper), pkt_wrapper.sv (public-key table), and riscv_peripherals.sv (integration/wiring). Four distinct, confirmed permission-related security vulnerabilities were identified, spanning incorrect lock-bit indexing, an inconsistent write-lock check in reglk_wrapper, a debug-mode key bypass that zeroes the HMAC outer-key-hash (okey_hash) but leaves ikey_hash readable, an acct_mem write-side entry that uses an out-of-range lock bit (bit 13 of an 8-bit input), and a hardcoded bootrom mux bug that always selects the Linux image regardless of the boot-select pin. An additional weaker finding is that acct_mem is initialized to all-ones (0xffffffff), which grants full access before any privileged software has a chance to program the table, creating an open-access window at power-on.",
  "findings": [
    {
      "finding_id": "F1",
      "status": "confirmed_finding",
      "summary": "reglk_wrapper.sv write-lock for reglk_mem[2] checks bit [1] but uses reglk_mem[3] as the retained value instead of reglk_mem[2], silently corrupting register slot 2 when locked.",
      "vulnerability_category": "Register-Lock Logic Error / Incorrect Lock Target",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 78,
          "line_end": 79,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_mem[2]"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 76,
          "line_end": 80,
          "module": "",
          "object": "reglk_mem[2] write case",
          "evidence_type": "Source code – write-side always block",
          "description": "Case address[7:3]==2 assigns: reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[3] : wdata. When the lock bit (reglk_ctrl[1]) is asserted, the preserved value is taken from reglk_mem[3] instead of reglk_mem[2]. All other slots correctly reference themselves (e.g. reglk_mem[1] <= reglk_ctrl[1] ? reglk_mem[1] : wdata).",
          "supports_claim": "Demonstrates that the lock-hold value for slot 2 is wrong, meaning the locked state of reglk_mem[2] is overwritten with reglk_mem[3]'s content."
        }
      ],
      "reasoning_summary": "In the write always-block of reglk_wrapper, every other register slot, when locked, retains its own previous value (e.g. reglk_mem[1] <= reglk_ctrl[1] ? reglk_mem[1] : wdata). For address slot 2 the code instead writes reglk_mem[3] as the retained value (reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[3] : wdata). This means: (a) when the write lock is active, slot 2 silently receives the content of slot 3 instead of being held constant; (b) the access-control lock values stored in reglk_mem[2] (which govern peripheral lock bits for at least two peripherals) are corrupted, potentially disabling intended protections.",
      "security_impact": "An attacker who can trigger the lock condition (e.g. by setting reglk_ctrl[1]) causes reglk_mem[2] to be replaced by reglk_mem[3]. The resulting corrupted lock vector is broadcast through reglk_ctrl_o to all downstream peripherals, potentially unlocking or incorrectly locking peripheral registers. This is a privilege-escalation vector if an unprivileged entity can influence the lock bit, and a denial-of-service/bypass vector regardless.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact bit semantics of reglk_mem[2] for downstream peripherals depend on the full peripheral mapping, parts of which are outside the input scope. However, the code defect is unambiguous.",
      "recommended_follow_up": [
        "Fix the locked-hold assignment: reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[2] : wdata;",
        "Audit all other reglk_mem[] case arms for similar copy-paste mistakes."
      ]
    },
    {
      "finding_id": "F2",
      "status": "confirmed_finding",
      "summary": "acct_wrapper.sv references bit [13] of an 8-bit reglk_ctrl_i input for write-locking acct_mem[03..05], which is always 0 (undriven/out-of-range), leaving those entries permanently unlocked.",
      "vulnerability_category": "Write-Lock Bypass / Out-of-Range Bit Index",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 96,
          "line_end": 100,
          "module": "acct_wrapper",
          "signal_or_register": "acct_mem[03], acct_mem[04], acct_mem[05]"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 26,
          "line_end": 26,
          "module": "",
          "object": "reglk_ctrl_i",
          "evidence_type": "Port declaration",
          "description": "Port is declared as 'input logic [7:0] reglk_ctrl_i' – only bits 0..7 are valid.",
          "supports_claim": "Bits beyond index 7 are always 0 in SystemVerilog (zero-extension of unsigned logic)."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 40,
          "line_end": 51,
          "module": "",
          "object": "reglk_ctrl",
          "evidence_type": "Internal signal assignment",
          "description": "reglk_ctrl is declared as logic[15:0] and assigned 'assign reglk_ctrl = reglk_ctrl_i'. The upper 8 bits [15:8] are zero-filled from the 8-bit input.",
          "supports_claim": "reglk_ctrl[13] is always 0, so the conditional reglk_ctrl[13] ? acct_mem[n] : wdata always takes the wdata branch."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 96,
          "line_end": 100,
          "module": "",
          "object": "acct_mem[03..05] lock checks",
          "evidence_type": "Write-side always block",
          "description": "acct_mem[03] <= reglk_ctrl[13] ? acct_mem[03] : wdata; (likewise for [04] and [05]). Because reglk_ctrl[13] is always 0, the write lock for these three entries can never engage.",
          "supports_claim": "These access-control table entries (governing at least one peripheral group) are permanently writable by any entity with AXI access."
        }
      ],
      "reasoning_summary": "The acct_wrapper module declares reglk_ctrl_i as [7:0] but internally widens it to logic [15:0] via zero-extension. When write-lock checks reference reglk_ctrl[13], that bit is always 0, so the ternary condition never fires. The write-lock for acct_mem[3..5] is therefore always bypassed, and those access-control entries (which control permission bits for at least one peripheral visible through acc_ctrl_o) can be overwritten by any software that has AXI access to the ACCT peripheral regardless of the intended lock state.",
      "security_impact": "An unprivileged software attacker (or a compromised peripheral) can permanently modify the access-control entries for the corresponding peripheral group, granting itself higher access rights or denying access to legitimate users. Since acc_ctrl_o feeds directly into the access-control logic used by priv_lvl_i gating, this constitutes a privilege-escalation vulnerability.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "It is possible a synthesis tool may warn/error on the out-of-range index rather than zero-filling; in practice most tools zero-extend, confirming the bug. The exact peripheral governed by acct_mem[3..5] is not directly identified in the visible scope.",
      "recommended_follow_up": [
        "Widen reglk_ctrl_i to at least 14 bits, or remap the lock bit to a valid index within [7:0].",
        "Audit all other acct_mem lock checks for additional out-of-range bit references."
      ]
    },
    {
      "finding_id": "F3",
      "status": "confirmed_finding",
      "summary": "hmac_wrapper.sv: when debug_mode_i is asserted, okey_hash is zeroed but ikey_hash is left intact and readable. Additionally, the key register (key0) is zeroed but the ikey_hash_bytes registers used for the inner-key hash remain writable and are exposed on the read side regardless of debug mode.",
      "vulnerability_category": "Asymmetric Debug-Mode Key Exposure / Incomplete Zeroization",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac_wrapper.sv",
          "line_start": 54,
          "line_end": 56,
          "module": "hmac_wrapper",
          "signal_or_register": "key, ikey_hash, okey_hash"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac_wrapper.sv",
          "line_start": 54,
          "line_end": 56,
          "module": "",
          "object": "key / ikey_hash / okey_hash assignments",
          "evidence_type": "Combinational assign – key muxing",
          "description": "Line 54: assign key = debug_mode_i ? 256'b0 : {key0[0]..key0[7]}; Line 55: assign ikey_hash = {ikey_hash_bytes[0]..ikey_hash_bytes[7]}; (NO debug_mode gate) Line 56: assign okey_hash = debug_mode_i ? 256'b0 : {okey_hash_bytes[0]..okey_hash_bytes[7]};",
          "supports_claim": "ikey_hash is the only key-derived value NOT zeroed in debug mode, creating asymmetric protection. The outer-key hash (okey_hash) is zeroed, but the inner-key hash (ikey_hash) is exposed to the HMAC core and readable via the register interface."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac_wrapper.sv",
          "line_start": 278,
          "line_end": 292,
          "module": "",
          "object": "ikey_hash_bytes read path",
          "evidence_type": "Read-side always block",
          "description": "Addresses 34-41 return ikey_hash_bytes[7..0] gated only by reglk_ctrl_i[4]. The debug_mode_i signal does NOT suppress ikey_hash_bytes on the read path. An attacker in debug mode can read ikey_hash_bytes directly from the register.",
          "supports_claim": "Even if key and okey_hash are zeroed in debug mode, ikey_hash_bytes content is accessible through the AXI register interface."
        }
      ],
      "reasoning_summary": "The design correctly suppresses key and okey_hash when debug_mode_i is asserted, but omits the same protection for ikey_hash. Because ikey_hash is derived from the HMAC key and is fed directly into the HMAC core, exposing it in debug mode leaks security-sensitive material. Furthermore, the AXI read path for ikey_hash_bytes (addresses 34-41) is only gated by reglk_ctrl_i[4] and not by debug_mode_i, so a debug-mode adversary can extract these bytes from the register interface.",
      "security_impact": "An attacker who can assert debug_mode_i (e.g. via the JTAG debug module) can read ikey_hash from the HMAC register map, recovering key material derived from the secret HMAC key. This breaks the confidentiality of HMAC operations and may allow forging of HMAC tags.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact value stored in ikey_hash_bytes (e.g. whether it is the full HMAC inner-pad hash or an intermediate value) depends on software programming. The bug is definitively present in the RTL, but exploitability depends on whether ikey_hash_bytes are populated before debug access occurs.",
      "recommended_follow_up": [
        "Apply the same debug_mode_i zeroization to ikey_hash: assign ikey_hash = debug_mode_i ? 256'b0 : {ikey_hash_bytes[0]...[7]};",
        "Add debug_mode_i suppression to the read-side path for ikey_hash_bytes (addresses 34-41)."
      ]
    },
    {
      "finding_id": "F4",
      "status": "confirmed_finding",
      "summary": "riscv_peripherals.sv: the bootrom mux always selects rom_rdata_linux regardless of the ariane_boot_sel_i control signal, making the baremetal boot path permanently inaccessible.",
      "vulnerability_category": "Boot Selection Bypass / Hardcoded Mux Logic",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 534,
          "line_end": 534,
          "module": "riscv_peripherals",
          "signal_or_register": "rom_rdata"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 533,
          "line_end": 534,
          "module": "",
          "object": "rom_rdata assignment",
          "evidence_type": "Source code – mux assignment",
          "description": "Comment says 'we want to run in baremetal mode when using pitonstream', but the assignment is: assign rom_rdata = (ariane_boot_sel_i) ? rom_rdata_linux : rom_rdata_linux; Both branches select rom_rdata_linux, making ariane_boot_sel_i ineffective.",
          "supports_claim": "The baremetal bootrom (rom_rdata_bm) is instantiated and wired but its output is never actually selected, permanently forcing Linux boot mode regardless of the hardware strap."
        }
      ],
      "reasoning_summary": "A ternary mux is used to select between the baremetal and Linux bootroms based on ariane_boot_sel_i. However, both branches of the conditional assign rom_rdata_linux, so ariane_boot_sel_i is ignored. The baremetal bootrom output (rom_rdata_bm) is computed but never reaches the system. This means the boot mode cannot be changed via the intended hardware mechanism, locking the system into Linux boot mode unconditionally.",
      "security_impact": "The system cannot boot in baremetal mode regardless of the hardware strap setting. This violates boot-mode isolation: if baremetal mode is a secured/restricted boot path with different privilege assumptions, forcing Linux mode could either lock out legitimate baremetal users or permanently expose an attack surface intended to be gated by boot mode. It also creates an undetected dead-code path (rom_rdata_bm) that may indicate tampering or a development error that masks a deeper security control.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The security significance depends on whether the baremetal vs. Linux boot distinction carries different security properties in the wider system. Functionally, the mux bug is unambiguous.",
      "recommended_follow_up": [
        "Fix the mux: assign rom_rdata = (ariane_boot_sel_i) ? rom_rdata_linux : rom_rdata_bm;",
        "Verify whether ariane_boot_sel_i is also used elsewhere for security-relevant mode switching."
      ]
    },
    {
      "finding_id": "F5",
      "status": "confirmed_finding",
      "summary": "acct_wrapper.sv initializes all acct_mem entries to 0xFFFFFFFF on reset, granting full all-permissions access to all peripherals until software explicitly programs the table, creating an insecure default open-access window.",
      "vulnerability_category": "Insecure Default State / Permissive Reset Value",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 71,
          "line_end": 75,
          "module": "acct_wrapper",
          "signal_or_register": "acct_mem"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 68,
          "line_end": 76,
          "module": "",
          "object": "acct_mem reset initialization",
          "evidence_type": "Reset always block",
          "description": "On reset (~rst_ni || rst_6): for (j=0; j < AcCt_MEM_SIZE; j=j+1) acct_mem[j] <= 32'hffffffff. All access control bits set to 1 means all permissions granted by default.",
          "supports_claim": "Until privileged firmware explicitly programs the access-control table, every peripheral is accessible by every privilege level, defeating the access control mechanism."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 49,
          "line_end": 49,
          "module": "",
          "object": "acc_ctrl_o",
          "evidence_type": "Output assignment",
          "description": "assign acc_ctrl_o = {acct_mem[3*0+2], acct_mem[3*0+1], acct_mem[3*0+0]|{8{we_flag}}}; The output is driven directly from acct_mem, so the all-ones reset value immediately propagates to all downstream peripheral access-control gates.",
          "supports_claim": "At power-on or after any rst_6 reset, all downstream peripherals are fully open before software has a chance to lock them down."
        }
      ],
      "reasoning_summary": "The access-control memory resets to all-ones (0xFFFFFFFF per entry), which in the context of the access control scheme means all permission bits are asserted — i.e., maximum access. This creates a window between power-on reset and the point at which privileged boot firmware programs the access-control table, during which any code running on the processor (including potentially untrusted early boot code) has full access to all protected peripherals.",
      "security_impact": "During the boot window, an attacker who can execute code before the access-control table is programmed (e.g., via a vulnerable bootloader stage, or by triggering rst_6 independently) can access any peripheral without restriction, bypassing the entire access-control architecture.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The severity depends on the timing of the access-control table programming relative to the availability of potentially untrusted execution contexts. If privileged firmware reliably programs the table before any untrusted code runs, the window may be short. However, the rst_6 reset signal being independently controllable (via the rst_wrapper peripheral) compounds this risk.",
      "recommended_follow_up": [
        "Initialize acct_mem to 0x00000000 (deny-all) on reset and require explicit grants from privileged firmware.",
        "Audit whether rst_6 can be triggered by unprivileged software through the rst_wrapper peripheral."
      ]
    },
    {
      "finding_id": "F6",
      "status": "potential_warning",
      "summary": "acct_wrapper.sv: the we_flag signal is OR'd into the lowest 8 bits of acc_ctrl_o (acct_mem[0]), which can forcibly override access control bits and grant write permission to a peripheral regardless of the programmed access-control table value.",
      "vulnerability_category": "Access Control Override via External Flag",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 49,
          "line_end": 49,
          "module": "acct_wrapper",
          "signal_or_register": "acc_ctrl_o"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 49,
          "line_end": 49,
          "module": "",
          "object": "acc_ctrl_o",
          "evidence_type": "Output assignment",
          "description": "assign acc_ctrl_o = {acct_mem[3*0+2], acct_mem[3*0+1], acct_mem[3*0+0]|{8{we_flag}}}; The we_flag signal is replicated to 8 bits and OR'd into acct_mem[0]. If we_flag is asserted, all 8 bits of the lowest byte of acc_ctrl_o are forced to 1, overriding the programmed value.",
          "supports_claim": "Any entity that can assert we_flag can bypass the access-control table for peripheral slot 0."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1731,
          "line_end": 1731,
          "module": "",
          "object": "we_flag_0 connection",
          "evidence_type": "Integration wiring",
          "description": ".we_flag (we_flag_0) – we_flag_0 is a top-level input to riscv_peripherals, meaning it is externally driven and not protected by any privilege-level check visible in this scope.",
          "supports_claim": "The we_flag input is architecturally external and may be assertable outside the normal access-control path."
        }
      ],
      "reasoning_summary": "The OR operation with we_flag means that when we_flag is high, the access-control output for peripheral slot 0 is unconditionally opened (all 8 permission bits set), overriding whatever the software-programmed acct_mem[0] contains. This is an intentional design escape hatch, but its origin and control authority are not visible in the provided scope. If we_flag can be asserted by untrusted software or hardware, it constitutes a permanent access-control bypass.",
      "security_impact": "Depending on the source of we_flag_0, an attacker who can assert this signal bypasses the access-control policy for the corresponding peripheral group, gaining read/write access regardless of the programmed policy.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The source and security context of we_flag_0 (and we_flag_1 through we_flag_4) are not defined within the visible scope. A full assessment requires tracing we_flag_0 to its driver in the broader system.",
      "recommended_follow_up": [
        "Trace we_flag_0..4 to their sources and verify they are only assertable by privileged software/hardware.",
        "Document the intended semantics of we_flag and gate it with a privilege-level check.",
        "Consider removing or strictly fusing the we_flag override mechanism if it is not needed at runtime."
      ]
    }
  ],
  "no_finding_reason": "N/A – multiple confirmed findings were identified.",
  "global_uncertainty": "The analysis is limited to the five files in the input scope. Several referenced modules (rst_wrapper, dmi_jtag, axi_lite_interface, pkt, fuse_mem, aes*_wrapper, sha256_wrapper, dma_wrapper, rsa_wrapper) are not present and could not be inspected. The full privilege model for we_flag signals, the exact peripheral-to-lock-bit mapping beyond what is visible in the wrappers, and the timing of boot firmware relative to the access-control initialization window all require additional files to assess completely. The findings reported above are based entirely on visible RTL evidence and are each independently verifiable from the provided source code."
}