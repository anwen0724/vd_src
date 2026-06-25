{
  "analysis_summary": "Analyzed the RTL files under INPUT_SCOPE (src/rom2/rom2.sv, src/axi_node/src/axi_node_intf_wrap.sv, tb/ariane_soc_pkg.sv, tb/ariane_testharness.sv). The design implements an access control fabric where master-to-peripheral permissions are stored in ROM2 as 'secure' 192-bit keys. Two critical permission-related vulnerabilities were identified: (1) the 'secure_reg' inside ROM2 that holds access control keys is writable via the bus interface with no access restriction, allowing any bus master to overwrite the access control configuration; (2) ROM2 provides no bus-level write protection, meaning the access control keys can be modified at runtime, completely defeating the access control fabric and allowing privilege escalation to access all peripherals including AES and JTAG.",
  "findings": [
    {
      "finding_id": "F1",
      "status": "confirmed_finding",
      "summary": "ROM2 'secure_reg' holding access control keys is writable via the AXI bus interface, allowing unauthorized modification of access control permissions.",
      "vulnerability_category": "Insufficient Access Control on Security-Critical Registers",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 1,
          "line_end": 48,
          "module": "rom2",
          "signal_or_register": "secure_reg"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 29,
          "line_end": 32,
          "module": "rom2",
          "signal_or_register": "secure_reg (write path)"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 23,
          "line_end": 25,
          "module": "rom2",
          "object": "secure_reg",
          "evidence_type": "code",
          "description": "secure_reg is declared as an output, writable internally via always_ff block on write request",
          "supports_claim": "Demonstrates that secure_reg is writable"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 29,
          "line_end": 32,
          "module": "rom2",
          "object": "write logic",
          "evidence_type": "code",
          "description": "When we_i is high and req_i is asserted, wdata_i is written directly to secure_reg at the address-derived index with no access restriction or privilege check",
          "supports_claim": "Shows the write path has no protection mechanism"
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 550,
          "line_end": 555,
          "module": "ariane_testharness",
          "object": "ROM2 bus connection",
          "evidence_type": "code",
          "description": "ROM2 is connected as a regular AXI bus slave at master[ariane_soc::ROM2]; the access_ctrl_reg output feeds the access control system",
          "supports_claim": "Shows ROM2 is bus-accessible and its outputs control access permissions"
        },
        {
          "file": "tb/ariane_soc_pkg.sv",
          "line_start": 38,
          "line_end": 40,
          "module": "ariane_soc",
          "object": "ROM2 address map",
          "evidence_type": "code",
          "description": "ROM2Base = 64'h0021_0000, ROM2Length = 64'h10000 — ROM2 is mapped in the memory space",
          "supports_claim": "Confirms ROM2 is accessible in the address map"
        }
      ],
      "reasoning_summary": "The ROM2 module stores 192-bit keys that serve as the access control matrix for the entire SoC. The comment in the source states 'We can read and write initial 64 bits' and the RTL implements an unconditional write path: when we_i is asserted, wdata_i is written to secure_reg[addr-derived-index]. There is no privilege check, no write-once mechanism, no lock bit, and no bus-level write protection. Since ROM2 is mapped as a standard AXI slave at address 0x0021_0000 (ariane_soc::ROM2), any master that can issue a write transaction to this address range can overwrite the access control keys, including its own permission bits, thereby granting itself access to any peripheral. This directly undermines the entire access control fabric.",
      "security_impact": "Critical: An attacker who can perform a bus write to the ROM2 address range can modify the access control keys and escalate privileges to access any peripheral (AES, JTAG, UART, SPI, Ethernet, etc.). The access control fabric can be completely bypassed, leading to unauthorized access to cryptographic keys (AES), debug interfaces (JTAG), and all other peripherals.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The test harness file was truncated; the full connection of access_ctrl_reg from ROM2's secure_reg to the AXI node was partially visible (line 555 .access_ctrl_reg( access_ctrl_reg )). The complete mapping between ROM2's 192-bit entries and the 48-bit access_ctrl_reg fields is not fully verified from the available evidence but the vulnerability of writable secure_reg is confirmed independently.",
      "recommended_follow_up": [
        "Implement a write-once or write-lock mechanism (e.g., a fuse-like lock bit) in ROM2 to prevent runtime modification of security-critical keys after initialization.",
        "Consider making the security key registers read-only from the bus after initial load from a secure ROM/fuse source.",
        "Add bus-level write protection (e.g., block write transactions to ROM2 address range in the AXI node or interconnect).",
        "Verify that the access control keys loaded from ROM2 cannot be read back by untrusted masters (prevent read side-channel of security configuration).",
        "Review the hardcoded constant key values in ROM2 — they appear to be default/public values which may themselves represent a security weakness if not overridden per chip."
      ]
    },
    {
      "finding_id": "F2",
      "status": "confirmed_finding",
      "summary": "Hardcoded default security keys in ROM2 source code expose access control and cryptographic key material in the RTL repository.",
      "vulnerability_category": "Hardcoded Security Keys / Credentials in Source Code",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 13,
          "line_end": 22,
          "module": "rom2",
          "signal_or_register": "mem (const)"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 13,
          "line_end": 22,
          "module": "rom2",
          "object": "mem constant",
          "evidence_type": "code",
          "description": "Four 192-bit key values are hardcoded as constants: access control master 1 key, access control master 0 key, JTAG key, and AES key — all visible in plain text in the source code",
          "supports_claim": "Shows all security keys are hardcoded as readable constants"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 1,
          "line_end": 3,
          "module": "rom2",
          "object": "module header comment",
          "evidence_type": "code",
          "description": "Comment reads 'ROM2: Which have all the keys' — explicitly acknowledges this module holds all security keys",
          "supports_claim": "Confirms ROM2 is the central key storage"
        }
      ],
      "reasoning_summary": "The ROM2 module is described as storing 'all the keys' and contains a const logic array with four hardcoded 192-bit values used as default/reset values for: access control master keys, JTAG key, and AES key. These values are visible in the RTL source file and may be intended as production defaults or placeholders. Hardcoding security keys in source code violates secure development practices because anyone with access to the RTL repository can see these keys, and if they are used in production silicon without per-chip fusing, all instances would share the same keys. Combined with F1 (writable secure_reg), this means an attacker who knows the default keys can also verify their attack by reading the reset state.",
      "security_impact": "High: If these keys are used in production silicon without per-chip overrides, the JTAG, AES, and access control keys are known to anyone with access to the source code (or silicon reverse engineering). This would allow unauthorized debug access, decryption of AES-protected data, and bypass of the access control fabric.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "It is unclear whether the hardcoded values are intended only for simulation/verification and are overridden by per-chip fusing in production. The comment 'Replication of fuse' suggests an intended fuse-based override path, but no such mechanism is visible in the provided RTL. The production flow (fuse programming scripts, OTP controller) is outside the provided scope.",
      "recommended_follow_up": [
        "Ensure production silicon uses per-chip unique fuse values to override these defaults.",
        "Remove hardcoded key values from the RTL source; use parameterized or externally-loaded (e.g., via OTP/eFuse controller) key inputs.",
        "If the RTL is shared or open-source, ensure default keys are replaced with placeholders (e.g., all zeros) and documented as simulation-only.",
        "Verify that the reset values of secure_reg are overwritten before any untrusted code can execute."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The test harness file (tb/ariane_testharness.sv) is large and was only partially read. The complete connectivity between ROM2's secure_reg[3:0][191:0] output and the access_ctrl_reg[1:0][47:0] signal is inferred from signal names and partial connection evidence (line 555: .access_ctrl_reg( access_ctrl_reg )). The exact bit slicing and mapping between the 192-bit ROM entries and the 48-bit access control registers is not fully verified from the visible source. Additionally, the broader SoC integration (ariane core, debug module, PLIC, CLINT) and any higher-level bus protections (e.g., ARM TrustZone, PMP, or IOMMU configurations) are not in scope and could provide additional defense layers. The scope only includes access control fabric related files, so privilege escalation through other paths (e.g., debug module, JTAG key bypass) cannot be fully assessed."
}