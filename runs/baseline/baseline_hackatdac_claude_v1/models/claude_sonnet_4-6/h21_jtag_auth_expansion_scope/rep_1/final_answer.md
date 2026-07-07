{
  "analysis_summary": "Analysis of the RTL files in the HackAtDac21 JTAG authentication expansion scope revealed several significant permission-related security vulnerabilities. The scope covers a RISC-V (Ariane) peripheral subsystem with JTAG debug interface authentication, a fuse memory holding secrets, an HMAC module, and an access control subsystem. Four distinct vulnerability classes were identified: (1) a critically flawed JTAG read-access bypass due to an operator precedence bug, (2) a hardcoded HMAC key bypass enabling authentication circumvention, (3) hardcoded cryptographic secrets exposed in plaintext ROM, and (4) a boot ROM mux that always selects the Linux image regardless of the boot selector signal.",
  "findings": [
    {
      "finding_id": "VULN-001",
      "status": "confirmed_finding",
      "summary": "Operator precedence bug in JTAG read-access check allows unauthenticated DMI reads when we_flag=0",
      "vulnerability_category": "Authentication Bypass / Incorrect Access Control",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/riscv-dbg/src/dmi_jtag.sv",
          "line_start": 125,
          "line_end": 125,
          "module": "dmi_jtag",
          "signal_or_register": "pass_check, we_flag"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/riscv-dbg/src/dmi_jtag.sv",
          "line_start": 125,
          "line_end": 127,
          "module": "dmi_jtag",
          "object": "Idle state read condition",
          "evidence_type": "source_code",
          "description": "The read gate condition is: `(pass_check | ~we_flag == 1)`. Due to SystemVerilog operator precedence, `~` (bitwise NOT) binds tighter than `==`, so this parses as `(pass_check | (~we_flag == 1))`. When we_flag=0, `~we_flag` evaluates to 1, meaning `(~we_flag == 1)` is always TRUE regardless of pass_check. This unconditionally grants DMI read access whenever we_flag=0.",
          "supports_claim": "Authentication bypass — DMI reads are permitted without a valid HMAC password check when we_flag input is deasserted (0)."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 279,
          "line_end": 279,
          "module": "riscv_peripherals",
          "object": ".we_flag (we_flag_4) port connection",
          "evidence_type": "source_code",
          "description": "The we_flag port of dmi_jtag is driven by the top-level input we_flag_4. If we_flag_4 is held low (0), the bug is continuously triggered, permitting all DMI reads without authentication.",
          "supports_claim": "The vulnerability is architecturally reachable via a single input signal."
        }
      ],
      "reasoning_summary": "The intended design requires `pass_check` to be set (authenticated) OR `~we_flag` to be 1 to allow a DMI read. However, the expression `~we_flag == 1` is evaluated as `(~we_flag) == 1` rather than `~(we_flag == 1)`. When we_flag=0, `~we_flag` is 1-bit 1, and `1 == 1` is always TRUE. Therefore the condition collapses to `pass_check | 1'b1` which is always TRUE, bypassing the HMAC authentication entirely for read operations. A correct implementation should be `(pass_check | (~we_flag))` or `(pass_check | (we_flag == 0))`.",
      "security_impact": "An attacker with physical JTAG access can read all DMI registers (including arbitrary memory and CSRs visible through the debug module) without providing the correct password/HMAC response. This defeats the confidentiality of the entire authenticated JTAG subsystem for read operations.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The functional value of we_flag_4 at the chip top level is not in scope; however, the logic bug is unambiguously present in the RTL regardless of the specific we_flag_4 value.",
      "recommended_follow_up": [
        "Fix the condition to: `(pass_check | (we_flag == 1'b0))` or equivalently `(pass_check || !we_flag)` using correct SystemVerilog operator precedence.",
        "Add a formal assertion: `assert property (dmi_req_valid |-> pass_check || !we_flag)` for read paths."
      ]
    },
    {
      "finding_id": "VULN-002",
      "status": "confirmed_finding",
      "summary": "HMAC key bypass hardcoded to 1, allowing the HMAC authentication to be skipped entirely",
      "vulnerability_category": "Authentication Bypass / Hardcoded Security Bypass",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/riscv-dbg/src/dmi_jtag.sv",
          "line_start": 327,
          "line_end": 327,
          "module": "dmi_jtag",
          "signal_or_register": "key_hash_bypass_i"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/riscv-dbg/src/dmi_jtag.sv",
          "line_start": 320,
          "line_end": 332,
          "module": "dmi_jtag",
          "object": "hmac instantiation with key_hash_bypass_i=1'h1",
          "evidence_type": "source_code",
          "description": "The HMAC module is instantiated with `.key_hash_bypass_i(1'h1)`, a hardcoded constant 1. This means the HMAC will always use the pre-computed key hashes (ikey_hash_i, okey_hash_i) stored in fuse memory rather than computing them fresh from the raw key.",
          "supports_claim": "The key_hash_bypass_i=1 causes the HMAC to skip its key expansion phase (sha_init is driven as ~key_hash_bypass_i = 0), using the fuse-provided intermediate hash state. If the fuse memory values are known or predictable, the HMAC authentication can be replicated without the actual secret key."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac.sv",
          "line_start": 60,
          "line_end": 68,
          "module": "hmac",
          "object": "HASHI_1 state with key_hash_bypass_i",
          "evidence_type": "source_code",
          "description": "In HASHI_1 state: `sha_init = ~key_hash_bypass_i` and `sha_h_block_update = key_hash_bypass_i`. With bypass=1, sha_init=0 (normal SHA256 init skipped) and sha_h_block_update=1 (direct hash block injection used). This means the ikey/okey intermediate digests from fuse memory are directly injected as the SHA256 internal state, bypassing normal HMAC key expansion.",
          "supports_claim": "Hardcoding bypass to 1 means anyone who can read the fuse memory contents (ikey_hash, okey_hash) can replicate the HMAC computation without knowing the original secret key."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 25,
          "line_end": 32,
          "module": "fuse_mem",
          "object": "ikey_hash_o and okey_hash_o assignments",
          "evidence_type": "source_code",
          "description": "The ikey_hash and okey_hash values are hardcoded in plaintext within the fuse_mem const array and directly driven as combinational outputs, making them statically visible in the RTL.",
          "supports_claim": "The bypass pre-computed values are statically known from the RTL, allowing authentication forgery."
        }
      ],
      "reasoning_summary": "The HMAC module supports a `key_hash_bypass_i` mode where, instead of deriving the HMAC key schedule from the raw key, it injects pre-computed ipad/opad hashes directly. This bypass is permanently enabled (hardcoded 1). The fuse_mem module stores these pre-computed hash values in a hardcoded const array visible in the RTL. Any party reading the RTL or the fuse memory can extract `ikey_hash` and `okey_hash` and then directly compute a valid HMAC response without ever possessing the original HMAC key, effectively defeating the authentication scheme.",
      "security_impact": "The key bypass combined with exposed intermediate hash values means the JTAG password authentication can be forged. An attacker can extract ikey_hash/okey_hash from fuse memory (or from the RTL) and compute a valid HMAC response, obtaining full DMI write access (and bypassing the write gate which requires pass_check==1).",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact SHA256 padding and message format used in the PassChk flow may introduce additional complexity, but the bypass flag=1 is unconditional and statically set in the RTL.",
      "recommended_follow_up": [
        "Remove the hardcoded `key_hash_bypass_i(1'h1)` and drive it from a secure, non-bypassable configuration signal.",
        "Ensure fuse memory intermediate hash values (ikey_hash, okey_hash) are not directly readable from the AXI-mapped address space.",
        "Reconsider the HMAC key bypass feature entirely — it weakens the security model."
      ]
    },
    {
      "finding_id": "VULN-003",
      "status": "confirmed_finding",
      "summary": "Cryptographic secrets (HMAC key, AES keys, SHA keys, JTAG hash) stored as plaintext hardcoded constants in fuse_mem RTL",
      "vulnerability_category": "Sensitive Data Exposure / Hardcoded Secrets",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 15,
          "line_end": 95,
          "module": "fuse_mem",
          "signal_or_register": "mem"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 15,
          "line_end": 95,
          "module": "fuse_mem",
          "object": "const logic [MEM_SIZE-1:0][31:0] mem",
          "evidence_type": "source_code",
          "description": "The entire fuse memory is declared as a `const logic` array with all secret values hardcoded in the RTL source: the JTAG expected HMAC hash (8 x 32-bit words), HMAC okey_hash (8 words), HMAC ikey_hash (8 words), HMAC key (`$$|-`, `|/-\\`, etc.), AES0/AES1/AES2 keys (multiple sets), SHA256 key, RNG polynomial, and access control default values.",
          "supports_claim": "All cryptographic secrets are visible in plaintext RTL, violating the confidentiality property of a 'fuse memory' which is normally implemented as a one-time programmable memory with secrets injected post-fabrication."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/riscv-dbg/src/dmi_jtag.sv",
          "line_start": 324,
          "line_end": 324,
          "module": "dmi_jtag",
          "object": ".key_i hardcoded value",
          "evidence_type": "source_code",
          "description": "The HMAC module is also instantiated with a hardcoded key: `.key_i(256'h24e6fa2254c2ff632a41b3b42e5c9b54f247b9a445a1ce488cfa23b384632154)` directly in the dmi_jtag source.",
          "supports_claim": "The HMAC key used for JTAG authentication is exposed in plaintext in the RTL source code."
        }
      ],
      "reasoning_summary": "The fuse_mem module, which is architecturally intended to hold device-unique secrets provisioned during manufacturing, instead contains all secrets as hardcoded compile-time constants. This means all keys are identical across all chip instances and are publicly visible in the RTL. Any adversary who obtains the RTL (or synthesizes the design) immediately possesses all cryptographic keys for all chips using this design.",
      "security_impact": "Complete compromise of all cryptographic operations protected by these keys: AES encryption/decryption, SHA256 operations, HMAC authentication, and JTAG debug access control. All chip instances sharing this RTL have identical, publicly known keys.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "No missing evidence — the constants are directly readable from the source file.",
      "recommended_follow_up": [
        "Replace hardcoded constants with OTP (one-time programmable) or eFuse memory cells that are programmed post-fabrication with device-unique values.",
        "Remove all key material from synthesizable RTL source files.",
        "Consider using a secure boot/key provisioning flow where secrets are injected outside of the design boundary."
      ]
    },
    {
      "finding_id": "VULN-004",
      "status": "confirmed_finding",
      "summary": "Boot ROM mux is broken — always selects linux boot image regardless of ariane_boot_sel_i selector",
      "vulnerability_category": "Logic Error / Incorrect Boot Selection Control",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 534,
          "line_end": 534,
          "module": "riscv_peripherals",
          "signal_or_register": "rom_rdata, ariane_boot_sel_i"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 534,
          "line_end": 534,
          "module": "riscv_peripherals",
          "object": "assign rom_rdata = (ariane_boot_sel_i) ? rom_rdata_linux : rom_rdata_linux;",
          "evidence_type": "source_code",
          "description": "Both branches of the conditional select `rom_rdata_linux`. The intent (from the comment on line 533: 'we want to run in baremetal mode when using pitonstream') was to select `rom_rdata_bm` for baremetal mode. The correct expression should likely be `(ariane_boot_sel_i) ? rom_rdata_linux : rom_rdata_bm`. As written, `ariane_boot_sel_i` is ignored entirely and the baremetal boot ROM is never used.",
          "supports_claim": "The boot selection input has no effect; the chip always boots the Linux image regardless of selector state, defeating secure boot path selection."
        }
      ],
      "reasoning_summary": "The assignment `assign rom_rdata = (ariane_boot_sel_i) ? rom_rdata_linux : rom_rdata_linux` is a copy-paste error where both the true and false branches of the ternary select `rom_rdata_linux`. The baremetal ROM output `rom_rdata_bm` is instantiated and driven correctly but its output is never connected to `rom_rdata`. This means the boot selector input is a dead signal with no effect on boot behavior.",
      "security_impact": "The baremetal secure boot path cannot be selected, potentially preventing the system from running in a secure minimal environment. If the Linux boot path has different security properties than the intended baremetal path, this could enable unintended software execution contexts.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The security impact depends on what security-sensitive distinctions exist between the linux and baremetal boot ROMs, which are not in scope. The logic bug itself is unambiguous.",
      "recommended_follow_up": [
        "Fix the mux to: `assign rom_rdata = (ariane_boot_sel_i) ? rom_rdata_linux : rom_rdata_bm;`",
        "Verify the intended boot ROM selection semantics with the system specification."
      ]
    }
  ],
  "no_finding_reason": "N/A — multiple confirmed findings were identified.",
  "global_uncertainty": "The scope does not include the top-level chip integration files, so it is not possible to determine the static value of we_flag_4 at the system level. The access control wrapper modules (acct_wrapper, reglk_wrapper, etc.) are not in scope, so the downstream enforcement of acc_ctrl and reglk_ctrl signals cannot be fully verified. The sha256 submodule used within hmac.sv is not present in the scope, so the exact SHA256 behavior with h_block_update=1 cannot be confirmed from first principles — however, the hmac.sv control logic makes the bypass behavior clear. The priv_lvl_i-indexed access control logic (acc_ctrl_c) appears correctly structured for privilege-based access gating, but the correctness of the fuse-programmed access control values cannot be independently validated without the acct_wrapper source."
}