{
  "analysis_summary": "Analysis of the SoC RTL (Ariane test harness with AES, ROM2 fuse, and AXI access control) identified multiple permission-related security vulnerabilities. The ROM2 module stores cryptographic keys (AES, JTAG) and access control registers but allows unrestricted write access over the AXI bus without any lock mechanism. The AES wrapper exposes the encryption key via its APB read interface. The access control enforcement mechanism is self-defeating because the access control registers themselves reside in the writable ROM2. Additionally, the JTAG key used for debug authentication is readable from ROM2. These issues allow an attacker with bus-master access to extract secrets, bypass access controls, and compromise system security.",
  "findings": [
    {
      "finding_id": "ROM2-001",
      "status": "confirmed_finding",
      "summary": "ROM2 secure key registers are writable over AXI bus without any write-lock or access control enforcement",
      "vulnerability_category": "Insufficient Permission Enforcement / Missing Write Lock",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 33,
          "line_end": 44,
          "module": "rom2",
          "signal_or_register": "secure_reg"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 185,
          "line_end": 212,
          "module": "ariane_peripherals",
          "signal_or_register": "key_reg_out"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 33,
          "line_end": 44,
          "module": "rom2",
          "object": "always_ff block",
          "evidence_type": "source_code",
          "description": "ROM2 allows writes to any secure_reg on any clock cycle when req_i && we_i are asserted. No lock bit, one-time-programmable (OTP) mechanism, privilege check, or access control exists within the module.",
          "supports_claim": "ROM2 secure registers accept arbitrary writes from any AXI bus master without any permission check."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "assign statements",
          "evidence_type": "source_code",
          "description": "jtag_key and access_ctrl_reg are directly derived from key_reg_out which is the writable secure_reg from ROM2; jtag_key = key_reg_out[1][31:0], access_ctrl_reg[0] = key_reg_out[2][47:0], access_ctrl_reg[1] = key_reg_out[3][47:0].",
          "supports_claim": "Compromise of ROM2 directly compromises JTAG authentication and access control."
        }
      ],
      "reasoning_summary": "The rom2 module is meant to emulate fuse-based key storage, but its implementation permits unrestricted writes via the AXI bus interface. There is no mechanism to prevent overwriting of keys after initial programming. The comment 'Replication of fuse' suggests an intent for immutable or OTP storage, but the RTL does not implement this. The write path is: axi2mem converts AXI transactions to req/we/addr/wdata, rom2 accepts any write where we_i=1. This means any software or device with bus-master access to ROM2's address space (0x0021_0000) can overwrite AES keys, JTAG keys, and access control registers.",
      "security_impact": "An attacker can overwrite the AES key to a known value and decrypt/encrypt data arbitrarily. They can overwrite the JTAG key to bypass debug authentication and gain full debug control of the SoC. They can overwrite access control registers to grant themselves access to any peripheral, effectively gaining full system compromise.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The original design intent may have been for ROM2 to be implemented as a true read-only memory or one-time-programmable fuse array at the physical level, but the RTL as written does not enforce this. No lock register or OTP controller is instantiated.",
      "recommended_follow_up": [
        "Add a write-lock mechanism (e.g., a lock bit per key register that is set once and prevents further writes).",
        "Implement ROM2 as actual read-only memory or require physical fuse values loaded only at reset.",
        "Add access control at the AXI node level to restrict which masters can write to ROM2, independent of ROM2's own registers."
      ]
    },
    {
      "finding_id": "AES-001",
      "status": "confirmed_finding",
      "summary": "AES encryption key is readable by any bus master through the APB register read interface",
      "vulnerability_category": "Exposure of Cryptographic Key via Readable Register",
      "affected_locations": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 85,
          "line_end": 105,
          "module": "aes_wrapper",
          "signal_or_register": "external_bus_io.rdata, key_big"
        }
      ],
      "evidence": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 85,
          "line_end": 105,
          "module": "aes_wrapper",
          "object": "always @(*) read case block",
          "evidence_type": "source_code",
          "description": "Addresses 16–21 of the APB read interface return the full 192-bit AES key in 32-bit words: addr 16 returns key_big[191:160], 17 returns [159:128], 18 returns [127:96], 19 returns [95:64], 20 returns [63:32], 21 returns [31:0].",
          "supports_claim": "The full AES encryption key is readable in plaintext through standard register reads."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 56,
          "line_end": 57,
          "module": "aes_wrapper",
          "object": "assign key_big = key_in;",
          "evidence_type": "source_code",
          "description": "key_big is connected directly to key_in, which comes from key_reg_out[0] (the AES key from ROM2). Reading addresses 16-21 exposes this key.",
          "supports_claim": "Reading the AES key through the APB interface reveals the actual encryption key."
        }
      ],
      "reasoning_summary": "The AES wrapper provides read access to the full key through addresses 16-21 of the APB register map. There is no access enable bit, clear-on-read mechanism, or privilege check to prevent key extraction. The comment '// no write access to ct registers !!' shows awareness of protecting ciphertext registers from writes, but no corresponding protection exists for reading the key. Any software or bus master that can reach the AES peripheral base address (0x1010_0000) can read back the full 192-bit AES key.",
      "security_impact": "The AES encryption key is exposed to any software running on the SoC, including untrusted user-mode code if AES is mapped in user-accessible address space. This completely defeats the purpose of encryption as the key is not secret. An attacker can read the key and decrypt all data encrypted with that key, or impersonate the device.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "Whether the AES peripheral's APB address space is actually restricted by the AXI access control register bits for AES (bits 16-19 in access_ctrl_reg) is not fully determinable from the available RTL, but the key readability within the peripheral is inherent.",
      "recommended_follow_up": [
        "Remove read access to key registers (addresses 16-21) or restrict reads to return zeros.",
        "Implement a write-only key register interface.",
        "Add a lock bit that, once set, prevents key reads."
      ]
    },
    {
      "finding_id": "ROM2-002",
      "status": "confirmed_finding",
      "summary": "JTAG debug authentication key is readable through ROM2 AXI read interface",
      "vulnerability_category": "Exposure of Authentication Credential via Readable Register",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "signal_or_register": "rdata_o"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 215,
          "module": "ariane_peripherals",
          "signal_or_register": "jtag_key"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "object": "assign rdata_o = (raddr_q < RomSize) ? secure_reg[raddr_q] : '0;",
          "evidence_type": "source_code",
          "description": "ROM2 read path returns the full 192-bit value from any of the 4 secure registers when the read address is within bounds. Index 1 holds the JTAG key.",
          "supports_claim": "Any bus master with read access to ROM2 can read the JTAG key."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 215,
          "module": "ariane_peripherals",
          "object": "assign jtag_key = key_reg_out[1][31:0];",
          "evidence_type": "source_code",
          "description": "jtag_key is taken from key_reg_out[1] bits 31:0, which is the JTAG key stored in ROM2 secure_reg[1].",
          "supports_claim": "Reading ROM2 index 1 reveals the JTAG debug unlock key."
        }
      ],
      "reasoning_summary": "The JTAG key (key_reg_out[1][31:0]) is used by the dmi_jtag module for debug authentication. ROM2's read path at line 47 allows any bus master to read secure_reg[raddr_q] for raddr_q < RomSize. Since RomSize = 4, and index 1 contains the JTAG key, any software that can read from ROM2's AXI address space (base 0x0021_0000) can extract the 32-bit JTAG key. This bypasses debug authentication entirely.",
      "security_impact": "An attacker who extracts the JTAG key can authenticate to the debug interface and gain full debug access to the processor, including register access, memory dump, code injection, and complete system takeover. This is a critical security breach.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The dmi_jtag module's exact authentication mechanism is not visible in the provided files, but the key is clearly forwarded to it via the jtag_key signal, and the key is readable from ROM2.",
      "recommended_follow_up": [
        "Make the JTAG key register read-only or write-only.",
        "Store the JTAG key in a separate, non-readable register (e.g., only accessible via physical fuses).",
        "Implement a mechanism to clear the JTAG key after it is loaded into the dmi_jtag module."
      ]
    },
    {
      "finding_id": "ACTRL-001",
      "status": "confirmed_finding",
      "summary": "Access control registers are self-defeating: stored in writable ROM2, allowing an attacker to grant themselves access to any peripheral",
      "vulnerability_category": "Circular / Self-Defeating Access Control",
      "affected_locations": [
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 216,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "access_ctrl_reg"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 33,
          "line_end": 44,
          "module": "rom2",
          "signal_or_register": "secure_reg"
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
          "file": "tb/ariane_peripherals.sv",
          "line_start": 216,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "assign access_ctrl_reg[0] = key_reg_out[2][47:0]; assign access_ctrl_reg[1] = key_reg_out[3][47:0];",
          "evidence_type": "source_code",
          "description": "The access control registers that govern bus-master-to-peripheral connectivity are derived directly from ROM2's writable secure registers 2 and 3.",
          "supports_claim": "Access control configuration is stored in writable memory."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 442,
          "line_end": 450,
          "module": "ariane_testharness",
          "object": "access_ctrl generation block",
          "evidence_type": "source_code",
          "description": "access_ctrl[i][j] = access_ctrl_reg[i][4*j +: 4]; the AXI node's connectivity map is built from the ROM2-derived access_ctrl_reg.",
          "supports_claim": "The AXI node's access enforcement depends entirely on ROM2 content."
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "axi_node_intf_wrap",
          "object": "assign connectivity_map_o[i][j] = access_ctrl_i[i][j][priv_lvl_i] || ((j==6) && access_ctrl_i[i][7][priv_lvl_i]);",
          "evidence_type": "source_code",
          "description": "The AXI connectivity map is a pure function of access_ctrl_i and priv_lvl_i. If access_ctrl_i comes from writable ROM2, the access control can be bypassed by overwriting ROM2.",
          "supports_claim": "Access control can be bypassed by rewriting ROM2 registers 2 and 3."
        }
      ],
      "reasoning_summary": "The SoC implements a permission-based access control scheme where each bus master's access to each peripheral is governed by 4-bit fields in access_ctrl_reg, one per privilege level. However, access_ctrl_reg itself is stored in ROM2's secure_reg[2] and [3], which are writable via AXI. If an attacker can write to ROM2 (and ROM2 permissions are themselves controlled by ROM2 content), they can grant themselves full access to all peripherals including AES, UART, SPI, Ethernet, GPIO, PLIC, CLINT, and debug. This circular dependency makes the access control system self-defeating.",
      "security_impact": "The entire SoC access control mechanism can be bypassed by a single write to ROM2. An attacker who initially has any access to ROM2 can escalate privileges to access all other peripherals. This undermines the security architecture of the entire SoC.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "It is possible that the AXI node's access_ctrl for ROM2 itself (peripheral index 9) is hardcoded or externally enforced, but from the available RTL there is no evidence of this. The access_ctrl for ROM2 appears to come from the same writable registers.",
      "recommended_follow_up": [
        "Store access control configuration in immutable memory (true ROM or efuse) or at minimum make ROM2's own access control non-writable.",
        "Implement a secure boot process that locks access control registers before untrusted software runs.",
        "Consider hardware-strapping access control values that cannot be changed after reset."
      ]
    },
    {
      "finding_id": "ROM2-003",
      "status": "confirmed_finding",
      "summary": "All cryptographic and security keys (AES key, JTAG key, access control configuration) are readable by any bus master through ROM2 AXI reads",
      "vulnerability_category": "Mass Exposure of Security Assets via Readable Bus Interface",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "signal_or_register": "rdata_o"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 18,
          "line_end": 24,
          "module": "rom2",
          "signal_or_register": "mem"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "object": "assign rdata_o = (raddr_q < RomSize) ? secure_reg[raddr_q] : '0;",
          "evidence_type": "source_code",
          "description": "The ROM2 read path returns any of the 4 secure registers (AES key, JTAG key, access control master 0, access control master 1) with no restriction.",
          "supports_claim": "All four 192-bit security registers are readable via AXI reads to ROM2."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 18,
          "line_end": 24,
          "module": "rom2",
          "object": "const logic [RomSize-1:0][191:0] mem = { ... }",
          "evidence_type": "source_code",
          "description": "The default (reset) values for all keys are hardcoded in RTL, meaning default keys are known to anyone with access to the source code.",
          "supports_claim": "Default security keys are not secret and can be used until overwritten, but even after overwriting they remain readable."
        }
      ],
      "reasoning_summary": "ROM2 serves as the central repository for all security-critical keys in this SoC: AES encryption key (index 0), JTAG debug authentication key (index 1), and access control configuration (indices 2, 3). The module's read interface exposes all of these to any bus-master with read access to ROM2. Combined with the lack of write-lock, this means both confidentiality and integrity of all security keys are compromised. The hardcoded default values in the RTL source code further weaken security, as the reset-state keys are known to anyone reviewing the design.",
      "security_impact": "Complete compromise of all cryptographic and authentication material on the SoC. An attacker can: (1) read the AES key to decrypt all data, (2) read the JTAG key to gain debug access, (3) read and modify access control to escalate privileges.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "None. The read path is straightforward and unambiguous.",
      "recommended_follow_up": [
        "Implement read restrictions: either return zeros for key registers or restrict ROM2 reads to only the access control registers.",
        "Store AES and JTAG keys in dedicated key storage elements that are not accessible via the system bus.",
        "Remove default hardcoded keys from production RTL."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The analysis is based solely on the provided RTL source files. External modules (dmi_jtag, axi2mem, aes_192_sed, axi_node_wrap) are not fully visible, so the exact behavior of the AXI access control enforcement at the interconnect level could not be fully verified. It is possible (though not evident from available RTL) that the AXI node hardcodes ROM2's own access control bits to prevent modification, but no such mechanism was found. Additionally, the actual physical implementation may use real e-fuse or ROM technology that is immutable, but the synthesizable RTL does not model this property."
}