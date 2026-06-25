{
  "analysis_summary": "Reviewed the visible RTL under the provided scope, focusing on access-control (acct), register-lock (reglk), reset-control (rst_ctrl), the shared AXI-lite interface, and visible integration evidence in riscv_peripherals.sv. The code implements permission gating through acc_ctrl_c[priv_lvl_i][peripheral] and register locks through reglk_ctrl_i bits, but visible source evidence shows multiple permission-related weaknesses: reset-control can reset the register-lock block and access-control block via a software-accessible AXI register path, reglk_wrapper explicitly clears all lock state on rst_9 or jtag_unlock, and the access-control register defaults are fully permissive after reset. In combination, a caller that has access to reset-control can reset REGLK/ACCT and thereby reopen or reprogram security policy. There are also implementation bugs/mismatches in the lock-control storage path that can corrupt or incorrectly size lock state, including an apparent wrong-source assignment for reglk_mem[2] and a 16-bit internal reglk_ctrl fed from an 8-bit input despite many lock-bit references beyond bit 7 in acct_wrapper.",
  "findings": [
    {
      "finding_id": "F-001",
      "status": "confirmed_finding",
      "summary": "Software-accessible reset-control can reset ACCT/REGLK, clearing locks and restoring permissive access-control defaults.",
      "vulnerability_category": "Permission bypass via reset of security-control state / improper reset default for access-control and lock registers",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/rst_ctrl/rst_wrapper.sv",
          "line_start": 46,
          "line_end": 101,
          "module": "rst_wrapper",
          "signal_or_register": "rst_mem, rst_6, rst_9, rst_12"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/rst_ctrl/rst_wrapper.sv",
          "line_start": 142,
          "line_end": 169,
          "module": "rst_wrapper",
          "signal_or_register": "start, rst_id, en, acct_ctrl_i, reglk_ctrl_i"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 76,
          "line_end": 83,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_mem, rst_9, jtag_unlock"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 76,
          "line_end": 83,
          "module": "acct_wrapper",
          "signal_or_register": "acct_mem, rst_6"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/rst_ctrl/rst_wrapper.sv",
          "line_start": 46,
          "line_end": 62,
          "module": "rst_wrapper",
          "object": "rst_6, rst_9",
          "evidence_type": "source",
          "description": "Reset-control exposes reset outputs for ACCT and REGLK and maps them directly from rst_mem bits. Comments identify rst_6 as ACCT and rst_9 as REGLK.",
          "supports_claim": "Software-controllable reset-control can target the access-control and register-lock peripherals."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/rst_ctrl/rst_wrapper.sv",
          "line_start": 68,
          "line_end": 101,
          "module": "rst_wrapper",
          "object": "rst_mem, rst_id, start",
          "evidence_type": "source",
          "description": "When start is asserted, rst_wrapper sets rst_mem[rst_id] according to a case statement. Cases 6 and 9 assert resets for ACCT and REGLK respectively; case 12 resets RST_CTRL itself.",
          "supports_claim": "A write-controlled rst_id/start path can assert reset to security-control peripherals."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/rst_ctrl/rst_wrapper.sv",
          "line_start": 142,
          "line_end": 169,
          "module": "rst_wrapper",
          "object": "start, rst_id",
          "evidence_type": "source",
          "description": "AXI write side in rst_wrapper allows software to write start and rst_id when en && we, gated only by acct_ctrl_i and reglk_ctrl_i[1].",
          "supports_claim": "Reset selection and trigger are programmable over the peripheral interface when access-control permits."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 76,
          "line_end": 83,
          "module": "reglk_wrapper",
          "object": "reglk_mem, rst_9, jtag_unlock",
          "evidence_type": "source",
          "description": "reglk_wrapper clears all register-lock memory entries when reset is active, jtag_unlock is asserted, or rst_9 is asserted: if(~(rst_ni && ~jtag_unlock && ~rst_9)) reglk_mem[j] <= 'h0.",
          "supports_claim": "Resetting REGLK clears lock state instead of preserving a secure locked state."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 76,
          "line_end": 83,
          "module": "acct_wrapper",
          "object": "acct_mem, rst_6",
          "evidence_type": "source",
          "description": "acct_wrapper initializes all access-control memory entries to 32'hffffffff on reset or rst_6.",
          "supports_claim": "Resetting ACCT restores a fully permissive access-control policy."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1729,
          "line_end": 1906,
          "module": "riscv_peripherals",
          "object": "acct_ctrl_i connections",
          "evidence_type": "source_search",
          "description": "Top-level integration routes reset-control access through acc_ctrl_c[priv_lvl_i][8], and routes REGLK and ACCT access through acc_ctrl_c[priv_lvl_i][9] and acc_ctrl_c[priv_lvl_i][6] respectively.",
          "supports_claim": "Permission gating exists but reset-control is itself a permission-controlled peripheral that can affect security-control peripherals once accessed."
        }
      ],
      "reasoning_summary": "The reset-control block provides a memory-mapped way to select a reset target via rst_id and trigger it via start. The same block can assert rst_6 for ACCT and rst_9 for REGLK. In the ACCT block, rst_6 resets access-control registers to all ones, which is permissive because acc_ctrl_o is built from acct_mem and top-level access checks use acc_ctrl_c[priv_lvl_i][peripheral]. In the REGLK block, rst_9 clears reglk_mem to zero, and write logic treats lock bits set to 1 as preventing writes; clearing locks therefore unlocks protected configuration. Thus, any actor that can access RST_CTRL can reset and effectively reopen or reconfigure the access-control and register-lock policy, including after locks were set. The code does not show a hard exclusion preventing RST_CTRL from targeting ACCT/REGLK, nor a secure reset default that preserves or asserts locks.",
      "security_impact": "A lower-privileged or compromised software context with access to RST_CTRL could reset REGLK to clear lock bits and/or reset ACCT to restore all-ones permissive access permissions. This can bypass register locks, re-enable access to protected peripherals, alter cryptographic accelerator configuration, reset security-related IP, or escalate privileges across the SoC peripheral permission model.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The visible evidence does not include the full system policy or firmware configuration determining which privilege levels are allowed to access RST_CTRL in deployed systems. If RST_CTRL access is permanently restricted to a trusted root context and locked before untrusted execution, exploitability is reduced. However, the RTL itself exposes reset IDs for ACCT and REGLK and insecure reset behavior is directly visible.",
      "recommended_follow_up": [
        "Prevent software-triggered reset of security policy blocks such as ACCT and REGLK after secure initialization, or require a stronger immutable privilege/debug/authentication condition for those reset IDs.",
        "Change security-control reset defaults to fail-closed where feasible: locks asserted and access denied until trusted initialization completes.",
        "Add explicit hardware policy that reset-control cannot clear register locks or access-control state once locked.",
        "Verify top-level privilege policy for acc_ctrl_c[priv_lvl_i][8] ensures only trusted machine/secure firmware can access RST_CTRL; if not, treat as critical privilege escalation.",
        "Add assertions/formal checks that once a lock bit is set, no software-accessible reset path can clear the associated protection without an authorized lifecycle/debug unlock."
      ]
    },
    {
      "finding_id": "F-002",
      "status": "potential_warning",
      "summary": "Register-lock implementation has width/mapping inconsistencies and a wrong-state-preservation assignment that can undermine lock enforcement.",
      "vulnerability_category": "Improper lock enforcement / access-control configuration integrity weakness",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 87,
          "line_end": 97,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_mem[2], reglk_ctrl"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 31,
          "line_end": 37,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_ctrl_i, reglk_ctrl"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 87,
          "line_end": 101,
          "module": "acct_wrapper",
          "signal_or_register": "reglk_ctrl[13:0]"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 107,
          "line_end": 125,
          "module": "acct_wrapper",
          "signal_or_register": "reglk_ctrl[6:0]"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 31,
          "line_end": 50,
          "module": "reglk_wrapper",
          "object": "reglk_ctrl_i, reglk_ctrl",
          "evidence_type": "source",
          "description": "reglk_wrapper declares an 8-bit input reglk_ctrl_i but assigns it to a 16-bit internal reglk_ctrl.",
          "supports_claim": "Lock-control width handling is inconsistent, creating risk that expected lock bits are absent or zero-extended."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 89,
          "line_end": 94,
          "module": "reglk_wrapper",
          "object": "reglk_mem[2]",
          "evidence_type": "source",
          "description": "In reglk_wrapper write case for address index 2, the locked path assigns reglk_mem[2] <= reglk_mem[3] rather than preserving reglk_mem[2].",
          "supports_claim": "A write to a locked register can corrupt reglk_mem[2] from reglk_mem[3] instead of preserving it."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 18,
          "line_end": 101,
          "module": "acct_wrapper",
          "object": "reglk_ctrl_i, reglk_ctrl[13]",
          "evidence_type": "source",
          "description": "acct_wrapper declares input reglk_ctrl_i as 8 bits but uses an internal 16-bit reglk_ctrl and references bits up to reglk_ctrl[13] in access-control write protection.",
          "supports_claim": "Some access-control write locks depend on high bits that may not be represented by the 8-bit input."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 87,
          "line_end": 125,
          "module": "acct_wrapper",
          "object": "reglk_ctrl",
          "evidence_type": "source",
          "description": "Read protection in acct_wrapper references several low lock bits, while write protection references reglk_ctrl[13], [7], [5], and [1], showing a complex bit mapping that is not clearly consistent with the 8-bit input declaration.",
          "supports_claim": "Lock enforcement may not correspond to intended lock policy due to bit-index/width mismatches."
        }
      ],
      "reasoning_summary": "Lock enforcement depends on reglk_ctrl_i bits, but both reglk_wrapper and acct_wrapper declare reglk_ctrl_i as only 8 bits while internal logic and write protection reference up to bit 13. In SystemVerilog, assigning an 8-bit vector to a wider vector generally zero-extends the missing high bits, which means conditions such as reglk_ctrl[13] may never lock if the port truly supplies only 8 bits. Separately, reglk_wrapper has an apparent typo in the address-2 write case: when locked, it assigns reglk_mem[2] from reglk_mem[3] rather than preserving reglk_mem[2]. This can corrupt lock settings and may accidentally enable or disable permissions for unrelated peripherals.",
      "security_impact": "Incorrect lock-bit sizing or corrupted lock state may leave intended access-control registers writable after they should be locked, or may alter another peripheral's lock policy. This can weaken the permission model and enable unauthorized reconfiguration of protected peripheral access.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The top-level slices passed into reglk_ctrl_i are 8-bit slices of a larger reglk_ctrl vector, so some high-bit references in wrappers may be intended to refer to zero or may be coding mistakes. Without the full specification of lock-bit layout, the exact intended mapping is uncertain. The reglk_mem[2] assignment from reglk_mem[3] is nevertheless visibly suspicious and likely erroneous.",
      "recommended_follow_up": [
        "Align reglk_ctrl_i port widths with the number of lock bits actually consumed, or explicitly document and enforce the intended 8-bit mapping.",
        "Fix reglk_mem[2] locked write behavior to preserve reglk_mem[2], not copy reglk_mem[3].",
        "Add lint/formal checks for out-of-range or zero-extended lock-bit usage and for locked writes preserving state.",
        "Create tests that attempt writes to every protected ACCT/REGLK register with each lock bit asserted."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The analysis was limited to visible files and search/read outputs under the input scope. The full top-level file was truncated during direct read, and external definitions for bridge modules, peripheral modules, firmware programming sequence, lifecycle/debug policy, and the intended access-control register specification were not available. Exploitability depends on how acc_ctrl is provisioned before untrusted software runs and whether RST_CTRL remains accessible to untrusted privilege levels."
}