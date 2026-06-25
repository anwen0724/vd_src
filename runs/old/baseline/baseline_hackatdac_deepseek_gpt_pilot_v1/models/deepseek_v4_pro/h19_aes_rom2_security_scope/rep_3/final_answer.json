{
  "analysis_summary": "The design contains a critical permission-related vulnerability in the rom2 module. The `secure_reg` register array, intended to act as immutable fuse-based storage for security-critical keys (JTAG key, AES key, access control registers), is exposed as fully writable via the AXI bus interface without any access-control enforcement. Additionally, the `aes_wrapper` module allows read-back of the AES key through its register map. Together these flaws allow any bus master on the SoC to overwrite or disclose cryptographic keys and access-control configurations, completely subverting the intended security model.",
  "findings": [
    {
      "finding_id": "F-001",
      "status": "confirmed_finding",
      "summary": "Security-critical keys in ROM2 secure_reg are writable by any AXI bus master without access-control enforcement.",
      "vulnerability_category": "Missing Write Protection (Insufficient Permission Enforcement)",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 30,
          "line_end": 43,
          "module": "rom2",
          "signal_or_register": "secure_reg"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 177,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "key_reg_out, jtag_key, access_ctrl_reg"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 463,
          "line_end": 467,
          "module": "ariane_peripherals",
          "signal_or_register": "key_in (AES key from key_reg_out[0])"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 37,
          "line_end": 41,
          "module": "rom2",
          "object": "secure_reg write logic",
          "evidence_type": "RTL source code",
          "description": "When req_i is asserted and we_i is high, the write-data wdata_i is stored into secure_reg at the address-derived index without any permission check. The logic is: `if(req_i) begin if (!we_i) begin ... end else begin secure_reg[addr_i[...]] <= wdata_i; end end`. There is no bus master identification or access-control gating.",
          "supports_claim": "Proves that any bus master with connectivity to ROM2 can overwrite the secure registers."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 16,
          "line_end": 25,
          "module": "rom2",
          "object": "mem constant (fuse emulation)",
          "evidence_type": "RTL source code",
          "description": "The localparam `mem` array contains hardcoded key values meant to emulate fuse storage: index 0 = AES key, index 1 = JTAG key, indices 2-3 = access control registers. The comment states 'Replication of fuse' and 'Store key values here'. These are loaded into secure_reg on reset but are immediately overridable through the writable interface.",
          "supports_claim": "Demonstrates that these registers hold security-critical values that should be immutable after initialization."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "key_reg_out usage",
          "evidence_type": "RTL source code",
          "description": "jtag_key is assigned from key_reg_out[1][31:0] (JTAG key); access_ctrl_reg is assigned from key_reg_out[2] and key_reg_out[3] (access control matrix for AXI crossbar). All derive from the writable secure_reg.",
          "supports_claim": "Confirms that overwriting secure_reg directly compromises JTAG authentication and the entire AXI access-control matrix."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 68,
          "line_end": 105,
          "module": "aes_wrapper",
          "object": "Read path for AES key",
          "evidence_type": "RTL source code",
          "description": "The APB read-side always_comb block maps addresses 16-21 to key_big[191:0], which is connected to the AES key from ROM2 (key_reg_out[0]). This allows any bus master to read back the full 192-bit AES key.",
          "supports_claim": "Proves the AES key is readable, not write-only."
        }
      ],
      "reasoning_summary": "The ROM2 module is intended to emulate fuse-based key storage, where keys are loaded once at reset and remain immutable. However, the implementation unconditionally allows writes (when we_i is asserted) to the secure_reg array. There is no hardware mechanism to lock the registers after initial load, nor is there any filtering based on the identity or privilege of the requesting bus master. The AXI interconnect (axi_node_intf_wrap.sv) uses access_ctrl_reg derived from secure_reg for its own permission checking, creating a circular dependency: the access control matrix itself is stored in unprotected writable registers. An attacker who can initiate AXI transactions to the ROM2 base address (0x0021_0000, with ROM2Length = 64'h10000) can overwrite the JTAG key, AES key, and access control registers, gaining full system compromise.",
      "security_impact": "CRITICAL. An attacker with bus-master capability can: (1) Overwrite the JTAG key to bypass debug authentication. (2) Overwrite the AES key to compromise data confidentiality. (3) Overwrite the access control matrix to grant themselves access to all peripherals. (4) Read the AES key through the aes_wrapper register interface.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The source for the axi2mem bridge module and the full AXI node integration is not provided, so we cannot confirm whether write transactions to ROM2 are already gated elsewhere. However, based on the available source, the ROM2 module itself has no write protection and the access control matrix is derived from ROM2 registers. If any hardware-level protection exists outside the provided scope, it would be in un-included wrapper modules.",
      "recommended_follow_up": [
        "Implement a write-once or lock-after-reset mechanism in rom2.sv: on the first write (or after initial load from fuse), set a lock bit that prevents further writes to secure_reg.",
        "Route a bus-master identity signal (e.g., AXI aw_id or a derived privilege level) to rom2 and gate writes based on master ID (e.g., only allow writes from a secure boot controller).",
        "Make the AES key read interface in aes_wrapper write-only: remove or gate the rdata assignment for key-related address offsets (16-21).",
        "Consider storing the access control matrix in a separate, hardware-protected register file rather than in the same writable array as the cryptographic keys."
      ]
    },
    {
      "finding_id": "F-002",
      "status": "confirmed_finding",
      "summary": "AES encryption key is readable by any APB bus master through the aes_wrapper read interface.",
      "vulnerability_category": "Insufficient Permission Enforcement / Key Readback",
      "affected_locations": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 90,
          "line_end": 101,
          "module": "aes_wrapper",
          "signal_or_register": "external_bus_io.rdata (key readback)"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 463,
          "line_end": 467,
          "module": "ariane_peripherals",
          "signal_or_register": "i_aes_wrapper.key_in"
        }
      ],
      "evidence": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 90,
          "line_end": 101,
          "module": "aes_wrapper",
          "object": "rdata case items 16-21",
          "evidence_type": "RTL source code",
          "description": "The APB read multiplexer maps address offsets 16-21 to key_big[191:0] (the full 192-bit AES key). The comment '// no write access to ct registers !!' indicates awareness of write-access restrictions for ciphertext but there is no read restriction for the key.",
          "supports_claim": "Confirms that the AES key can be read back via the APB register interface."
        }
      ],
      "reasoning_summary": "The aes_wrapper module provides a full read path for the AES encryption key via the APB register interface. The key is brought in from ROM2 (key_in, 192 bits) and mapped to read addresses 16-21 without any access gating. In a secure system, cryptographic key material should be write-only from software's perspective; reading it back undermines key confidentiality.",
      "security_impact": "HIGH. An attacker who can read the APB-mapped AES peripheral addresses (e.g., at base 0x1010_0000) can extract the 192-bit AES key, compromising all data encrypted with that key.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The APB-to-AXI bridge and the top-level address decoding are not fully provided; it is possible that reads to the AES peripheral are blocked at a higher level. However, the aes_wrapper itself unconditionally provides the key on the read bus.",
      "recommended_follow_up": [
        "Make the AES key read addresses (16-21) in aes_wrapper write-only by returning zero or a bus error on reads.",
        "Alternatively, implement a key-use counter or access-control gating that restricts key reads to a specific privilege level or boot stage."
      ]
    }
  ],
  "no_finding_reason": "N/A — findings were identified.",
  "global_uncertainty": "The analysis is based on the fully available modules (rom2.sv, aes_wrapper.sv, ariane_peripherals.sv, ariane_testharness.sv, ariane_soc_pkg.sv, axi_node_intf_wrap.sv, bootrom.sv). The axi2mem bridge module and the complete AXI crossbar node implementation are not fully available, so any external write-gating or bus-level protection cannot be assessed. The bootrom module appears auto-generated with no security-related logic."
}