{
  "analysis_summary": "Analyzed 8 SystemVerilog files under the hackatdac21 crypto security scope (riscv_peripherals.sv, acct_wrapper.sv, reglk_wrapper.sv, aes0_wrapper.sv, aes1_wrapper.sv, aes2_wrapper.sv, hmac_wrapper.sv, sha256_wrapper.sv). The design implements a multi-layer hardware permission scheme: PMP, per-peripheral per-privilege-level Access Control (ACCT), per-register Register Lock (REGLK), and debug-mode key-zeroing. Three concrete permission-related vulnerabilities were identified: (1) a data-corruption bug in reglk_wrapper.sv where locked register index 2 is overwritten with reglk_mem[3] instead of being preserved; (2) AES0 wrapper key_big2 is not zeroed in debug_mode_i, leaking key material; (3) AES1 wrapper core_key1 is not zeroed in debug_mode_i, leaking key material; (4) HMAC wrapper ikey_hash is not zeroed in debug_mode_i, leaking inner-key hash. Additionally, SHA-256 lacks any debug_mode_i protection (lower severity since SHA-256 is not keyed).",
  "findings": [
    {
      "finding_id": "F01",
      "status": "confirmed_finding",
      "summary": "reglk_wrapper.sv: Register lock data corruption at address index 2 — when reglk_ctrl[1] is high, a write to reglk_mem[2] incorrectly loads reglk_mem[3] instead of preserving reglk_mem[2].",
      "vulnerability_category": "Permission Bypass / Register Lock Corruption",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 84,
          "line_end": 84,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_mem[2]"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 80,
          "line_end": 88,
          "module": "reglk_wrapper",
          "object": "reglk_mem write case statement",
          "evidence_type": "RTL source code",
          "description": "In the write-side always block, case item 2 reads: 'reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[3] : wdata;' The locked-state expression uses reglk_mem[3] instead of reglk_mem[2]. All other case items (0,1,3,4,5) correctly self-reference: e.g., 'reglk_mem[0] <= reglk_ctrl[3] ? reglk_mem[0] : wdata;' This copy-paste error corrupts reglk_mem[2] with the value of reglk_mem[3] whenever a write is attempted while register lock bit [1] is set.",
          "supports_claim": "This demonstrates that the register lock for index 2 is broken: instead of preventing writes, it copies unrelated data from index 3, bypassing the intended permission enforcement."
        }
      ],
      "reasoning_summary": "The register lock (reglk) mechanism is designed to protect security-critical peripheral registers from further modification after initial configuration. Each reglk_mem location controls lock bits for specific peripherals. When locked (reglk_ctrl[Y]=1), writes must be ignored (value preserved). For index 2, the right-hand side of the ternary uses reglk_mem[3] instead of reglk_mem[2], so a write to address 2 while locked copies index 3's value into index 2. This corrupts the lock state and can unlock unintended peripheral registers or lock the wrong ones.",
      "security_impact": "An attacker with write access to the REGLK memory map at address index 2 while the lock bit is active can overwrite reglk_mem[2] with the current value of reglk_mem[3]. This undermines the hardware-enforced register lock policy and may allow unauthorized modification of previously locked peripheral registers controlled by index 2.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact peripheral-register mapping for reglk_mem[2] vs reglk_mem[3] is defined by the riscv_peripherals.sv instantiation (reglk_ctrl slice assignments). We have not traced the full 8-bit-per-peripheral mapping in detail, but the RTL bug is unambiguous regardless of assignment.",
      "recommended_follow_up": [
        "Fix the typo: change 'reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[3] : wdata;' to 'reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[2] : wdata;'",
        "Review all case statements in the design for similar copy-paste errors."
      ]
    },
    {
      "finding_id": "F02",
      "status": "confirmed_finding",
      "summary": "aes0_wrapper.sv: key_big2 (third AES-192 key set) is NOT zeroed when debug_mode_i is asserted, exposing key material in debug mode.",
      "vulnerability_category": "Permission Bypass (Debug Mode Key Leakage)",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/aes0/aes0_wrapper.sv",
          "line_start": 56,
          "line_end": 56,
          "module": "aes0_wrapper",
          "signal_or_register": "key_big2"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/aes0/aes0_wrapper.sv",
          "line_start": 54,
          "line_end": 56,
          "module": "aes0_wrapper",
          "object": "key_big0, key_big1, key_big2 assignments",
          "evidence_type": "RTL source code",
          "description": "Line 54: 'assign key_big0 = debug_mode_i ? 192'b0 : {key0[0], key0[1], key0[2], key0[3], key0[4], key0[5]};' Line 55: 'assign key_big1 = debug_mode_i ? 192'b0 : {key1[0], key1[1], key1[2], key1[3], key1[4], key1[5]};' Line 56: 'assign key_big2 = {key2[0], key2[1], key2[2], key2[3], key2[4], key2[5]};' No debug_mode_i gating on key_big2.",
          "supports_claim": "key_big2 passes through the full key material regardless of debug_mode_i, while key_big0 and key_big1 are correctly zeroed."
        }
      ],
      "reasoning_summary": "The design intent is to zero all cryptographic keys when the CPU enters debug mode, preventing key exfiltration via debug interfaces. AES0 instantiates three 192-bit key sets (key0, key1, key2). key_big0 and key_big1 are correctly gated with debug_mode_i, but key_big2 is not. An attacker with debug access can read key2 in plaintext.",
      "security_impact": "The third AES key set (key2) is exposed to any debug-mode access path, enabling extraction of secret key material. If key2 is actively used (selected via key_sel[1]), the cryptographic operations can be compromised.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "Whether key2 is intended to always be non-secret is not documented in the provided files. The inconsistency with key0/key1 strongly suggests an oversight.",
      "recommended_follow_up": [
        "Change key_big2 assignment to: 'assign key_big2 = debug_mode_i ? 192'b0 : {key2[0], key2[1], key2[2], key2[3], key2[4], key2[5]};'",
        "Audit all debug_mode_i key-zeroing assignments across all crypto wrappers for consistency."
      ]
    },
    {
      "finding_id": "F03",
      "status": "confirmed_finding",
      "summary": "aes1_wrapper.sv: core_key1 (second AES key set) is NOT zeroed when debug_mode_i is asserted, while core_key0 and core_key2 are correctly zeroed.",
      "vulnerability_category": "Permission Bypass (Debug Mode Key Leakage)",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/aes1/aes1_wrapper.sv",
          "line_start": 116,
          "line_end": 118,
          "module": "aes1_wrapper",
          "signal_or_register": "core_key1"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/aes1/aes1_wrapper.sv",
          "line_start": 114,
          "line_end": 118,
          "module": "aes1_wrapper",
          "object": "core_key0, core_key1, core_key2 assignments",
          "evidence_type": "RTL source code",
          "description": "core_key0 = debug_mode_i ? 'b0 : {...}; core_key1 = {...}  // no debug_mode_i gating; core_key2 = debug_mode_i ? 'b0 : {...}. core_key1 is not protected.",
          "supports_claim": "The middle key set in AES1 is intentionally or accidentally excluded from debug-mode zeroing."
        }
      ],
      "reasoning_summary": "Same pattern as F02 but in the AES1 wrapper. Of the three key sets (key_reg0, key_reg1, key_reg2), only the first and third are zeroed in debug mode. The second key set is directly exposed.",
      "security_impact": "Key material in the second AES key slot of AES1 is accessible via debug interfaces, enabling key exfiltration and compromise of any cryptographic contexts using that key.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "Same uncertainty as F02 — no design documentation confirms intentionality, but the pattern strongly indicates an oversight.",
      "recommended_follow_up": [
        "Change core_key1 assignment to: 'assign core_key1 = debug_mode_i ? 'b0 : {key_reg1[7], key_reg1[6], key_reg1[5], key_reg1[4], key_reg1[3], key_reg1[2], key_reg1[1], key_reg1[0]};'",
        "Consistent audit across all crypto wrappers."
      ]
    },
    {
      "finding_id": "F04",
      "status": "confirmed_finding",
      "summary": "hmac_wrapper.sv: ikey_hash (inner key HMAC hash) is NOT zeroed in debug mode, while key and okey_hash are correctly zeroed.",
      "vulnerability_category": "Permission Bypass (Debug Mode Key Leakage)",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac_wrapper.sv",
          "line_start": 46,
          "line_end": 46,
          "module": "hmac_wrapper",
          "signal_or_register": "ikey_hash"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac_wrapper.sv",
          "line_start": 44,
          "line_end": 46,
          "module": "hmac_wrapper",
          "object": "key, ikey_hash, okey_hash assignments",
          "evidence_type": "RTL source code",
          "description": "assign key = debug_mode_i ? 256'b0 : {key0[0],...}; assign ikey_hash = {ikey_hash_bytes[0],...};  // no debug_mode_i; assign okey_hash = debug_mode_i ? 256'b0 : {okey_hash_bytes[0],...};",
          "supports_claim": "ikey_hash is the only one of the three HMAC key-derived values not gated by debug_mode_i."
        }
      ],
      "reasoning_summary": "HMAC uses two derived keys: inner-key hash (ikey_hash) and outer-key hash (okey_hash), both derived from the root key. If ikey_hash is exposed in debug mode, an attacker can reconstruct the HMAC state and potentially the root key, while only key and okey_hash are properly protected.",
      "security_impact": "Exposure of the HMAC inner-key hash in debug mode undermines the HMAC authentication chain. An attacker with debug access can read intermediate key-derived material and break message authentication.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "Whether ikey_hash_bytes are user-writable vs internally computed is not fully confirmed from the provided RTL subset, but the variable naming and structure indicate they contain key-derived sensitive data.",
      "recommended_follow_up": [
        "Change ikey_hash assignment to: 'assign ikey_hash = debug_mode_i ? 256'b0 : {ikey_hash_bytes[0], ...};'",
        "Full audit of all HMAC internal state exposure under debug_mode_i."
      ]
    },
    {
      "finding_id": "F05",
      "status": "potential_warning",
      "summary": "sha256_wrapper.sv does not accept debug_mode_i input — no debug-mode key-zeroing protection (low severity since SHA-256 is not keyed).",
      "vulnerability_category": "Missing Debug Protection (Information Leakage)",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/sha256/sha256_wrapper.sv",
          "line_start": 1,
          "line_end": 180,
          "module": "sha256_wrapper",
          "signal_or_register": "N/A (missing port)"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/sha256/sha256_wrapper.sv",
          "line_start": 22,
          "line_end": 30,
          "module": "sha256_wrapper",
          "object": "module port list",
          "evidence_type": "RTL source code",
          "description": "The sha256_wrapper module port list includes clk_i, rst_ni, reglk_ctrl_i, acct_ctrl_i, axi_req_i, axi_resp_o, rst_3 — but NOT debug_mode_i. Compare with all other crypto wrappers (aes0, aes1, aes2, hmac) which all accept debug_mode_i.",
          "supports_claim": "SHA-256 lacks the debug-mode protection mechanism present in all other crypto accelerators."
        }
      ],
      "reasoning_summary": "While SHA-256 itself does not use secret keys, it may process sensitive data (plaintext to be hashed, intermediate hash state) that could be valuable to an attacker. All other crypto peripherals implement debug-mode protection; the omission from SHA-256 may be intentional (non-keyed hash) or an oversight.",
      "security_impact": "Low-medium. SHA-256 intermediate state and data could be exposed in debug mode, but the primary concern (secret key leakage) does not apply directly. If SHA-256 is used in a keyed mode or processes sensitive data, this becomes more significant.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "SHA-256 is non-keyed by nature, so the absence of debug protection may be by design. However, HMAC-SHA-256 uses the separate hmac_wrapper; the standalone SHA-256 might still process sensitive data. Design intent is unclear.",
      "recommended_follow_up": [
        "Confirm design intent: if SHA-256 is only used for non-sensitive hashing, this is acceptable. If sensitive data passes through, add debug_mode_i zeroing."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "This analysis is based on a sanitized subsystem source view. The full connectivity of priv_lvl_i, debug_mode_i, we_flag_*, jtag_unlock, rst_* signals, and the AXI-lite bus fabric is not completely visible. The exact mapping of reglk_mem[2] to specific peripheral register lock groups is assumed from the reglk_ctrl slice assignments in riscv_peripherals.sv (lines 925, 1021, 1107, 1194, 1280, 1365, 1450, 1535, 1626, 1728, 1818, 1905) but not exhaustively traced. The acct_ctrl_c self-referential access control bootstrap relies on trusted firmware to configure registers before dropping privilege; this architectural assumption could not be validated from RTL alone."
}