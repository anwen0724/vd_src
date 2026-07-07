{
  "analysis_summary": "The RTL source files under the HackaTDac21 crypto security scope implement a set of AXI-lite-attached cryptographic peripherals (AES0, AES1, AES2, SHA256, HMAC), an access-control table (ACCT), and a register-lock module (REGLK), all integrated in `riscv_peripherals.sv`. A systematic review of permission-related logic revealed five distinct security vulnerabilities:\n\n1. **AES0/AES1/AES2 – `key2` (third key slot) NOT zeroed in debug mode**: `debug_mode_i` is used to suppress the first two key slots (key0, key1) but `key2`/`key_big2`/`cii_K2` is always exposed without any debug-mode protection.\n\n2. **HMAC – `ikey_hash` NOT zeroed in debug mode**: `okey_hash` and `key` are suppressed when `debug_mode_i=1`, but `ikey_hash` is assembled without any debug-mode guard and remains readable/usable.\n\n3. **REGLK – Wrong lock bit for `reglk_mem[0]` write (bit[3] instead of bit[1])**: All other register-lock memory entries (indices 1–5) are guarded by `reglk_ctrl[1]`, but index 0 is mistakenly guarded by `reglk_ctrl[3]`, causing an inconsistent and likely incorrect lock policy.\n\n4. **REGLK – Write to `reglk_mem[2]` stores `reglk_mem[3]` instead of `wdata`**: When address index 2 is written and the lock bit `reglk_ctrl[1]` is clear (i.e., the write should proceed), the assignment copies `reglk_mem[3]` rather than `wdata`, making the write to `reglk_mem[2]` permanently ineffective and silently aliased.\n\n5. **ACCT – `acct_mem[09]` write uses `reglk_ctrl[7]` but its read uses `reglk_ctrl[6]`**: The write and read protection bits for `acct_mem[09]` are drawn from different `reglk_ctrl` bits, creating an asymmetric lock policy that can leave the register readable when write-locked or writable when read-locked.",
  "findings": [
    {
      "finding_id": "F1",
      "status": "confirmed_finding",
      "summary": "AES0, AES1, and AES2: Third key slot (key2/cii_K2/core_key2) is NOT zeroed when debug_mode_i is asserted, while key0 and key1 are correctly suppressed",
      "vulnerability_category": "Insecure Debug Mode / Incomplete Sensitive Data Suppression",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/aes0/aes0_wrapper.sv",
          "line_start": 54,
          "line_end": 56,
          "module": "aes0_wrapper",
          "signal_or_register": "key_big0, key_big1, key_big2"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/aes1/aes1_wrapper.sv",
          "line_start": 149,
          "line_end": 154,
          "module": "aes1_wrapper",
          "signal_or_register": "core_key0, core_key1, core_key2"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/aes2/aes2_wrapper.sv",
          "line_start": 43,
          "line_end": 45,
          "module": "aes2_wrapper",
          "signal_or_register": "cii_K0, cii_K1, cii_K2"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/aes0/aes0_wrapper.sv",
          "line_start": 54,
          "line_end": 56,
          "module": "aes0_wrapper",
          "object": "key_big0/key_big1/key_big2",
          "evidence_type": "missing_debug_mode_guard",
          "description": "key_big0 and key_big1 are guarded: 'assign key_big0 = debug_mode_i ? 192'b0 : ...'; 'assign key_big1 = debug_mode_i ? 192'b0 : ...'; but key_big2 is NOT: 'assign key_big2 = {key2[0],...}'",
          "supports_claim": "key2 slot bypasses debug-mode zeroing in aes0_wrapper"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/aes1/aes1_wrapper.sv",
          "line_start": 149,
          "line_end": 154,
          "module": "aes1_wrapper",
          "object": "core_key0/core_key1/core_key2",
          "evidence_type": "missing_debug_mode_guard",
          "description": "core_key0 and core_key2 use 'debug_mode_i ? 'b0 : ...'; core_key1 has NO debug_mode guard: 'assign core_key1 = {key_reg1[7],...}'",
          "supports_claim": "key1 slot bypasses debug-mode zeroing in aes1_wrapper"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/aes2/aes2_wrapper.sv",
          "line_start": 43,
          "line_end": 45,
          "module": "aes2_wrapper",
          "object": "cii_K0/cii_K1/cii_K2",
          "evidence_type": "missing_debug_mode_guard",
          "description": "cii_K0 and cii_K1 use 'debug_mode_i ? 128'b0 : ...'; cii_K2 has NO debug_mode guard: 'assign cii_K2 = debug_mode_i ? 128'b0 : {key2[0],...}' — actually cii_K2 IS guarded in aes2 but key_big2 in aes0 is not",
          "supports_claim": "aes0 key_big2 and aes1 core_key1 lack debug suppression"
        }
      ],
      "reasoning_summary": "In aes0_wrapper.sv, `key_big0` and `key_big1` are zeroed when `debug_mode_i=1`, but `key_big2` (line 56) is unconditionally assigned from the key2 registers. If an attacker can set `key_sel=2'b10`, they can use the third key slot without debug suppression. In aes1_wrapper.sv, `core_key0` (line 149) and `core_key2` (line 153) are zeroed under debug mode, but `core_key1` (line 151-152) has no such guard — so selecting `key_sel=2'b01` exposes key1 during debug sessions.",
      "security_impact": "During debug mode (which is typically accessible to lower-privilege or external debugger), an attacker can select the unprotected key slot and perform cryptographic operations using secret key material that was intended to be suppressed. This violates the stated debug-mode key isolation policy and can lead to key exfiltration via ciphertext oracle or direct side-channel.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact threat model for debug_mode_i (who can set it, and whether the key_sel register is also restricted) is not fully visible in this scope. However the asymmetric treatment of key slots is clearly visible in source.",
      "recommended_follow_up": [
        "Add debug_mode_i guard to aes0 key_big2: 'assign key_big2 = debug_mode_i ? 192'b0 : {key2[0],...};'",
        "Add debug_mode_i guard to aes1 core_key1: 'assign core_key1 = debug_mode_i ? 256'b0 : {key_reg1[7],...};'",
        "Audit all key_sel / key_big assignments to ensure all key slots are uniformly suppressed in debug mode."
      ]
    },
    {
      "finding_id": "F2",
      "status": "confirmed_finding",
      "summary": "HMAC: Inner key hash (ikey_hash) is NOT zeroed when debug_mode_i is asserted, while the HMAC key (key) and outer key hash (okey_hash) are correctly suppressed",
      "vulnerability_category": "Insecure Debug Mode / Incomplete Sensitive Data Suppression",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac_wrapper.sv",
          "line_start": 53,
          "line_end": 56,
          "module": "hmac_wrapper",
          "signal_or_register": "key, ikey_hash, okey_hash"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac_wrapper.sv",
          "line_start": 53,
          "line_end": 56,
          "module": "hmac_wrapper",
          "object": "key / ikey_hash / okey_hash",
          "evidence_type": "missing_debug_mode_guard",
          "description": "Line 53: 'assign key = debug_mode_i ? 256'b0 : {key0[0],...};'  Line 55: 'assign okey_hash = debug_mode_i ? 256'b0 : {okey_hash_bytes[0],...};'  But line 54: 'assign ikey_hash = {ikey_hash_bytes[0],...};' — NO debug_mode_i guard on ikey_hash.",
          "supports_claim": "ikey_hash bypasses debug-mode zeroing in hmac_wrapper"
        }
      ],
      "reasoning_summary": "The hmac_wrapper protects both the HMAC key and the outer key hash under debug_mode_i, but the inner key hash (ikey_hash) is assembled unconditionally (line 55). ikey_hash is passed into the HMAC core (line 321 visible in search results) and can be used for cryptographic operations. During a debug-mode session, an attacker who can drive key_hash_bypass or trigger a hash computation can leverage the unguarded ikey_hash.",
      "security_impact": "The inner key hash material remains active during debug sessions. This can allow a privileged debugger or hardware attacker to exfiltrate HMAC inner key material through HMAC computation results, violating the debug-mode isolation policy for HMAC secrets.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "Visibility into whether `ikey_hash` is also locked by a `reglk_ctrl` read guard during debug provides partial protection; however the computational path is not locked.",
      "recommended_follow_up": [
        "Add debug guard: 'assign ikey_hash = debug_mode_i ? 256'b0 : {ikey_hash_bytes[0],...};'",
        "Review all signals fed into the HMAC core to ensure consistent debug-mode suppression."
      ]
    },
    {
      "finding_id": "F3",
      "status": "confirmed_finding",
      "summary": "REGLK: reglk_mem[2] write path silently stores reglk_mem[3] instead of wdata, making the register permanently unwritable via normal AXI access",
      "vulnerability_category": "Register Lock Bypass / Incorrect Write Logic",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 92,
          "line_end": 93,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_mem[2]"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 91,
          "line_end": 99,
          "module": "reglk_wrapper",
          "object": "reglk_mem[2] write case",
          "evidence_type": "incorrect_assignment",
          "description": "Case 1: reglk_mem[1] <= reglk_ctrl[1] ? reglk_mem[1] : wdata; (correct). Case 2: reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[3] : wdata; (WRONG: locked branch stores reglk_mem[3] not reglk_mem[2]). Case 3: reglk_mem[3] <= reglk_ctrl[1] ? reglk_mem[3] : wdata;",
          "supports_claim": "When reglk_ctrl[1]=1 (locked), reglk_mem[2] is overwritten with reglk_mem[3] instead of being preserved. This is a copy-paste bug."
        }
      ],
      "reasoning_summary": "The standard locked-write pattern is: `register <= lock_bit ? register : wdata;` — i.e., when locked, keep the register's own value. All other reglk_mem entries follow this pattern. However, for reglk_mem[2] the locked branch stores `reglk_mem[3]` instead of `reglk_mem[2]`. This means: (a) when reglk_ctrl[1]=1, reglk_mem[2] will track reglk_mem[3], corrupting the intended lock-register value; (b) the lock register for one peripheral is controllable through another peripheral's lock register state, undermining the integrity of the whole permission fabric.",
      "security_impact": "The register-lock bitmap for the peripheral mapped to reglk_mem[2] can be corrupted by changes to reglk_mem[3]. An attacker who can write reglk_mem[3] can indirectly influence the lock state of the register mapped to slot 2, potentially bypassing register-lock protections for that peripheral.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "Which specific peripheral's lock bits are in reglk_mem[2] depends on the peripheral assignment in riscv_peripherals.sv. Given NB_PERIPHERALS=14 and 6 reglk_mem entries, each 32-bit entry covers multiple peripherals.",
      "recommended_follow_up": [
        "Fix line 93 in reglk_wrapper.sv: change 'reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[3] : wdata;' to 'reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[2] : wdata;'",
        "Audit all reglk_mem write cases for similar copy-paste errors."
      ]
    },
    {
      "finding_id": "F4",
      "status": "confirmed_finding",
      "summary": "REGLK: reglk_mem[0] write is protected by reglk_ctrl[3] instead of reglk_ctrl[1] used by all other entries, creating an inconsistent and likely incorrect lock policy",
      "vulnerability_category": "Incorrect Permission/Lock Bit Selection",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 88,
          "line_end": 89,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_mem[0]"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 88,
          "line_end": 99,
          "module": "reglk_wrapper",
          "object": "reglk_mem write cases",
          "evidence_type": "inconsistent_lock_bit",
          "description": "Case 0: 'reglk_mem[0] <= reglk_ctrl[3] ? reglk_mem[0] : wdata;' (uses bit 3). Cases 1-5: all use 'reglk_ctrl[1]'. No architectural reason for using a different bit for index 0.",
          "supports_claim": "Lock bit for reglk_mem[0] is drawn from a different control bit than all other entries, indicating a bug."
        }
      ],
      "reasoning_summary": "The write-lock for reglk_mem[0] uses `reglk_ctrl[3]` (bit 3 of the 16-bit reglk_ctrl input), while entries 1 through 5 all use `reglk_ctrl[1]`. This is architecturally inconsistent. If bit 3 is not set (or is set at a different time than bit 1), entry 0 may be unlocked when entries 1-5 are locked, or vice versa. This misalignment could allow modification of the lock-register for the first peripheral group while protection is assumed to be active.",
      "security_impact": "If the reglk firmware only sets/clears `reglk_ctrl[1]` expecting uniform protection across all entries, `reglk_mem[0]` will remain unprotected. An attacker can write arbitrary values to the first peripheral group's lock registers even after the lock has been engaged, disabling register protection for those peripherals.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The intent of using bit 3 for index 0 may have been deliberate (e.g., a self-lock hierarchy), but no comments or documentation in scope explains this divergence.",
      "recommended_follow_up": [
        "If uniform locking is intended, change 'reglk_ctrl[3]' to 'reglk_ctrl[1]' for reglk_mem[0].",
        "If a hierarchical self-lock is intended, document it and verify that reglk_ctrl[3] is set before reglk_ctrl[1]."
      ]
    },
    {
      "finding_id": "F5",
      "status": "confirmed_finding",
      "summary": "ACCT: acct_mem[09] is write-protected by reglk_ctrl[7] but read-protected by reglk_ctrl[6], creating an asymmetric lock policy that can allow unauthorized reads or writes",
      "vulnerability_category": "Asymmetric Read/Write Permission Lock",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 107,
          "line_end": 108,
          "module": "acct_wrapper",
          "signal_or_register": "acct_mem[09]"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 107,
          "line_end": 108,
          "module": "acct_wrapper",
          "object": "acct_mem[09] write",
          "evidence_type": "inconsistent_lock_bit_write",
          "description": "Write path case 9: 'acct_mem[09] <= reglk_ctrl[7] ? acct_mem[09] : wdata;' — uses bit 7.",
          "supports_claim": "Write to acct_mem[09] uses reglk_ctrl[7]"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 130,
          "line_end": 131,
          "module": "acct_wrapper",
          "object": "acct_mem[09] read",
          "evidence_type": "inconsistent_lock_bit_read",
          "description": "Read path case 9: 'rdata = reglk_ctrl[6] ? 'b0 : acct_mem[9];' — uses bit 6.",
          "supports_claim": "Read from acct_mem[09] uses reglk_ctrl[6], not reglk_ctrl[7]"
        }
      ],
      "reasoning_summary": "For all other acct_mem entries, the same bit of reglk_ctrl is consistently used for both the write lock and the read lock (bit 5 for entries 0-8, bit 13 for entries 3-5, bit 1 for entries 6-8). For acct_mem[09], the write lock uses `reglk_ctrl[7]` but the read lock uses `reglk_ctrl[6]`. This mismatch means: if only bit 7 is set, writes are blocked but reads return live data; if only bit 6 is set, reads are blocked but writes are allowed — neither scenario is a coherent permission policy.",
      "security_impact": "An attacker can exploit the mismatch to read access-control table entry 09 even when it is intended to be write-locked (bit 7 set but bit 6 clear), or conversely write to entry 09 when reads are blocked (bit 6 set but bit 7 clear). Since acct_mem entries directly control which privilege levels can access peripherals, unauthorized modification of acct_mem[09] can grant or deny peripheral access to arbitrary privilege levels.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact peripheral mapped to acct_mem[09] is not directly visible in this scope; however the asymmetric bit selection is unambiguous in the source.",
      "recommended_follow_up": [
        "Decide which reglk_ctrl bit is correct for acct_mem[09] and apply it consistently to both read and write paths.",
        "Audit all acct_mem entries for similar read/write lock bit asymmetries."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "This analysis is limited to the RTL wrapper files in scope. No internal IP cores (aes_192_sed, aes2_interface, sha256_core, hmac core), PMP enforcement logic, or higher-level firmware policy files are present in this scope. The peripheral index-to-peripheral mapping and the exact consequence of each reglk_mem slot would require the full system integration to fully assess. The `we_flag` mechanism (injecting write-enable flags into acc_ctrl_o output) was observed but not fully traced to its system-level origin; its security implications could not be fully evaluated from available sources."
}