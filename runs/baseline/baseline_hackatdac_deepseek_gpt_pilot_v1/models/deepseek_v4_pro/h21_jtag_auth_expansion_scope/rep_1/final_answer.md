{
  "analysis_summary": "Analyzed RTL source files under hackatdac21/h21_jtag_auth_expansion_scope/piton/design/chip/tile/ariane/. The design contains a JTAG debug authentication system using HMAC-SHA256 for password verification against hardcoded expected hashes stored in a fuse memory. Three permission-related security issues were identified: (1) all cryptographic secrets (AES keys, HMAC keys, SHA keys, access control bits) are hardcoded as plain-text RTL constants in fuse_mem.sv, making them trivially extractable from the source; (2) the HMAC key-hash derivation step is permanently bypassed via a hard-tied input (key_hash_bypass_i = 1'h1) in dmi_jtag.sv, weakening the authentication scheme; (3) the we_flag read-bypass logic allows DMI read operations without successful password authentication when we_flag is deasserted, creating a potential backdoor depending on how we_flag is controlled externally.",
  "findings": [
    {
      "finding_id": "F1",
      "status": "confirmed_finding",
      "summary": "Hardcoded cryptographic secrets (AES/HMAC/SHA keys, access-control bitmaps, expected JTAG HMAC hash) stored as plain-text constants in RTL source fuse_mem.sv, exposing all security material to anyone with source access.",
      "vulnerability_category": "Insecure Storage of Secrets / Information Leakage",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 17,
          "line_end": 99,
          "module": "fuse_mem",
          "signal_or_register": "mem (constant logic array MEM_SIZE-1:0 of 32-bit words)"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 17,
          "line_end": 99,
          "module": "fuse_mem",
          "object": "const logic [MEM_SIZE-1:0][31:0] mem",
          "evidence_type": "RTL source code (constant declaration with hardcoded key material)",
          "description": "The constant array 'mem' contains: JTAG expected HMAC hash (8 words), RNG polynomials, HMAC okey/ikey hashes (8 words each), HMAC key (8 words as ASCII strings), access control bitmaps for masters 2/1/0 (3 words each), SHA key, AES2/AES1/AES0 keys. All values are hardcoded 32-bit hex/ASCII literals with comments identifying their purpose.",
          "supports_claim": "Directly shows all security-critical secrets embedded in source code without any obfuscation or runtime key injection mechanism."
        }
      ],
      "reasoning_summary": "The fuse_mem module declares all cryptographic secrets as a compile-time constant 'const logic' array with explicit hex values and descriptive comments labeling each secret. There is no mechanism to load keys from an external secure storage, e-fuses, or key management unit at runtime. Anyone with read access to the RTL source repository can extract all keys, expected hashes, and access-control configurations, completely compromising the security of the JTAG authentication, AES encryption, HMAC operations, and access-control enforcement.",
      "security_impact": "Critical. Full disclosure of all cryptographic keys (AES0/1/2, HMAC, SHA), expected JTAG authentication hash, and peripheral access-control bitmaps. An attacker can forge JTAG authentication, decrypt/encrypt data, and bypass access controls.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The broader system integration is not visible. It is possible (though unlikely given the 'const' keyword and explicit values) that a higher-level build flow replaces these constants via generated files. The readme indicates this is a simulation/evaluation dataset; the secrets may be test-only values.",
      "recommended_follow_up": [
        "Replace hardcoded secrets with a secure key management interface (e.g., e-fuse controller, OTP, or external key injection at boot).",
        "Ensure keys are never stored as plain-text RTL constants in production netlists.",
        "Implement access controls on the RTL repository to prevent unauthorized read access if secrets remain in source."
      ]
    },
    {
      "finding_id": "F2",
      "status": "confirmed_finding",
      "summary": "HMAC key-hash derivation step is permanently bypassed in the JTAG authentication path (key_hash_bypass_i tied to 1'h1), weakening or potentially nullifying the password-verification security.",
      "vulnerability_category": "Authentication Bypass / Weak Cryptography",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/riscv-dbg/src/dmi_jtag.sv",
          "line_start": 327,
          "line_end": 327,
          "module": "dmi_jtag",
          "signal_or_register": "key_hash_bypass_i"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac.sv",
          "line_start": 1,
          "line_end": 100,
          "module": "hmac",
          "signal_or_register": "key_hash_bypass_i, sha_init, sha_h_block_update"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/riscv-dbg/src/dmi_jtag.sv",
          "line_start": 320,
          "line_end": 330,
          "module": "dmi_jtag",
          "object": "hmac instantiation",
          "evidence_type": "RTL source code (hard-tied parameter on module instantiation)",
          "description": "The HMAC module is instantiated with .key_hash_bypass_i(1'h1), permanently enabling the bypass of the key hashing step. The ikey_hash_i and okey_hash_i inputs from fuse_mem are passed but the sha_init signal is gated by ~key_hash_bypass_i, meaning the SHA core is never initialized with the key-derived hash state. Instead, sha_h_block_update = key_hash_bypass_i causes the hash to be loaded directly as the initial SHA state without proper HMAC key derivation.",
          "supports_claim": "Demonstrates that the HMAC authentication flow skips the standard key derivation (inner/outer padding + hashing of the key), potentially allowing an attacker to forge valid authentication tokens without knowing the actual HMAC key."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac.sv",
          "line_start": 55,
          "line_end": 68,
          "module": "hmac",
          "object": "sha_init, sha_h_block_update assignments",
          "evidence_type": "RTL source code (combinational logic)",
          "description": "In the HASHI_1 and HASHO_1 states: sha_init = ~key_hash_bypass_i (so 0 when bypassed) and sha_h_block_update = key_hash_bypass_i (so 1 when bypassed). This means the SHA core's initial hash state is directly loaded from ikey_hash_i/okey_hash_i without computing SHA(key XOR ipad) / SHA(key XOR opad), bypassing the standard HMAC key derivation.",
          "supports_claim": "Confirms that when key_hash_bypass_i=1, the HMAC module skips the first hash round over the padded key and uses the pre-computed hash directly, reducing HMAC to a simple SHA256 over the message followed by a SHA256 over the concatenated result, which is not standard HMAC-SHA256."
        }
      ],
      "reasoning_summary": "The HMAC module supports a 'key_hash_bypass' mode that skips the standard HMAC key derivation step (SHA256(key XOR ipad) and SHA256(key XOR opad)) and instead uses pre-computed hashes (ikey_hash_i, okey_hash_i) directly as the initial SHA state. In dmi_jtag.sv, this bypass is hard-wired to 1'h1. The expected hash (jtag_hash_i from fuse_mem) is compared against the result. This means the authentication does not follow standard HMAC-SHA256 and the security now depends entirely on the secrecy of the pre-computed hashes rather than the original HMAC key. If the hashes are known (which they are, from F1), the authentication provides no real security. Even if the hashes were secret, the bypass mode reduces the cryptographic strength since the key is never mixed into the inner/outer padding steps.",
      "security_impact": "High. Combined with F1 (exposed hashes), the JTAG authentication is completely broken. Even in isolation, bypassing standard HMAC key derivation weakens the authentication by removing one round of cryptographic mixing and making the scheme non-standard.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The design intent may be to use pre-computed hashes as a performance optimization (avoiding one SHA round per authentication attempt), assuming the hashes are stored securely. However, the permanent hard-tie to 1'h1 removes any flexibility to disable bypass in production.",
      "recommended_follow_up": [
        "Evaluate whether key_hash_bypass should be configurable (e.g., via a CSR or fuse bit) rather than hard-tied.",
        "If bypass is used, ensure the pre-computed hashes are truly secret and not exposed in source/bitstream.",
        "Consider implementing full HMAC key derivation for stronger security guarantees."
      ]
    },
    {
      "finding_id": "F3",
      "status": "potential_warning",
      "summary": "The 'we_flag' input allows DMI read operations to bypass the pass_check authentication requirement when we_flag is deasserted, potentially creating an unauthorized read channel.",
      "vulnerability_category": "Access Control Bypass / Debug Interface Protection",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/riscv-dbg/src/dmi_jtag.sv",
          "line_start": 125,
          "line_end": 125,
          "module": "dmi_jtag",
          "signal_or_register": "we_flag, pass_check"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 56,
          "line_end": 60,
          "module": "riscv_peripherals",
          "signal_or_register": "we_flag_0..4"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 279,
          "line_end": 279,
          "module": "riscv_peripherals",
          "signal_or_register": "we_flag_4 -> dmi_jtag.we_flag"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/riscv-dbg/src/dmi_jtag.sv",
          "line_start": 120,
          "line_end": 132,
          "module": "dmi_jtag",
          "object": "Idle state transition logic",
          "evidence_type": "RTL source code (combinational always_comb block)",
          "description": "The condition for transitioning to the Read state is: (dm::dtm_op_e'(dmi.op) == dm::DTM_READ) && (pass_check | ~we_flag == 1). This means if we_flag is 0 (~we_flag == 1), a DTM_READ operation is accepted regardless of the pass_check state. Writes (DTM_WRITE) require pass_check == 1 unconditionally. The pass_check/we_flag signals are also referenced for DTM_PASS handling.",
          "supports_claim": "Proves that DMI reads can be performed without successful password verification when we_flag is low, while writes always require pass_check. This asymmetry may be intentional (open read, locked write) or an unintentional backdoor depending on the security policy."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 279,
          "line_end": 279,
          "module": "riscv_peripherals",
          "object": ".we_flag(we_flag_4)",
          "evidence_type": "RTL source code (module instantiation)",
          "description": "The dmi_jtag module's we_flag is driven by we_flag_4, which is a top-level input to riscv_peripherals. The five we_flag signals (0-4) are unconnected internally except for this and similar bindings to other peripherals. Without visibility into how we_flag_4 is driven at the chip level, its security posture is unknown.",
          "supports_claim": "Shows that we_flag is externally controlled; if an attacker can influence we_flag_4 (e.g., through a software-controlled GPIO or register), they could enable unauthorized DMI reads."
        }
      ],
      "reasoning_summary": "The we_flag signal creates an asymmetric access policy: DMI reads are permitted without authentication when we_flag=0, while writes always require pass_check. This could be a legitimate design choice (allowing unauthenticated debug reads for development, while protecting system modification), or an unintended bypass. The risk depends on (a) how we_flag_4 is controlled in the full chip (tied to 0 in production vs. software-controllable), (b) whether read-only DMI access can leak sensitive data (register values, memory contents via abstract commands), and (c) whether the authentication scheme (F1/F2 flaws aside) is meant to protect both read and write access.",
      "security_impact": "Medium. If we_flag is controllable by untrusted software or is accidentally left deasserted in production, an attacker can read processor state, memory, and registers via JTAG DMI without passing the password check. Combined with F1 and F2, the entire JTAG authentication scheme becomes ineffective.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "We cannot determine how we_flag_4 is driven at the top-level chip/SoC integration boundary. It may be hard-wired to 1 in production (always requiring pass_check) or controlled by a secure boot mechanism. The we_flag naming suggests 'write-enable flag' semantics, but the implementation allows reads when ~we_flag, not just writes.",
      "recommended_follow_up": [
        "Trace the we_flag_4 signal to its top-level source to verify it is tied to a secure state.",
        "If unauthenticated debug reads are not intended, change the condition to require pass_check for both read and write DMI operations.",
        "Document the intended debug access policy (open-read/closed-write vs. fully authenticated)."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The analysis is limited to the RTL files under the provided scope. The full chip-level integration (how we_flag signals are driven, whether fuse_mem secrets are overridden by a build flow, and whether additional security layers exist in other tiles/modules) is not visible. The scope appears to be a subsystem snapshot focusing on the JTAG authentication path; findings are based exclusively on the RTL contents and may not reflect the production configuration."
}