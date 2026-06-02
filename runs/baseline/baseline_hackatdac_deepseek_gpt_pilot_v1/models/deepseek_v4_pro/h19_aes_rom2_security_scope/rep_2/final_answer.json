{
  "analysis_summary": "Analyzed RTL source files under the hackatdac19/h19_aes_rom2_security_scope for permission-related security vulnerabilities. Reviewed modules: rom2 (secure key storage), aes_wrapper (AES with APB interface), ariane_peripherals (SoC peripheral integration), ariane_testharness (top-level), bootrom, axi_node_intf_wrap (AXI routing with access control), and ariane_soc_pkg (address map). Found multiple critical permission-related vulnerabilities centered on the rom2 module which stores cryptographic keys and access control configuration in writable registers accessible via the AXI bus without any authentication or privilege enforcement.",
  "findings": [
    {
      "finding_id": "F-001",
      "status": "confirmed_finding",
      "summary": "ROM2 secure key registers are writable via AXI bus without any access control enforcement, allowing any bus master to overwrite cryptographic keys and access control configuration.",
      "vulnerability_category": "Permission / Access Control - Missing Write Protection on Secure Key Storage",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 1,
          "line_end": 50,
          "module": "rom2",
          "signal_or_register": "secure_reg"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 37,
          "line_end": 41,
          "module": "rom2",
          "signal_or_register": "secure_reg write path"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 178,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "rom2_fuse AXI slave port, key_reg_out, jtag_key, access_ctrl_reg"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 37,
          "line_end": 41,
          "module": "rom2",
          "object": "secure_reg write logic",
          "evidence_type": "source_code",
          "description": "The always_ff block assigns secure_reg <= wdata_i when req_i and we_i are asserted, with no privilege check, authentication, or write-once mechanism. The address decoding uses addr_i[$clog2(RomSize)-1+3:3] to select which 64-bit slice of the 192-bit register to write.",
          "supports_claim": "Demonstrates that any AXI master can write to any of the four 192-bit secure registers, modifying AES keys, JTAG keys, and access control configuration."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 5,
          "line_end": 5,
          "module": "rom2",
          "object": "comment",
          "evidence_type": "source_code",
          "description": "Comment states 'ROM2: Which have all the keys.' confirming these registers hold all system keys.",
          "supports_claim": "Confirms the security sensitivity of the writable registers."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 212,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "key distribution",
          "evidence_type": "source_code",
          "description": "key_reg_out from ROM2 is distributed as: key_reg_out[0] -> AES key (line 467), key_reg_out[1][31:0] -> jtag_key (line 215), key_reg_out[2][47:0] -> access_ctrl_reg[0] (line 216), key_reg_out[3][47:0] -> access_ctrl_reg[1] (line 217). All can be overwritten via AXI writes.",
          "supports_claim": "Shows the full impact scope of writable ROM2 registers on system security."
        }
      ],
      "reasoning_summary": "The ROM2 module is intended to emulate fuse registers that are typically immutable after manufacturing. However, the RTL implements them as standard read-write registers accessible via AXI bus from the `rom2_fuse` slave port. There is no mechanism to prevent writes after initialization, no authentication requirement, and no privilege-level checking. This means any bus master—including potentially compromised software or a debug interface—can overwrite all cryptographic keys and access control policies at runtime.",
      "security_impact": "CRITICAL: An attacker who can perform AXI writes to the ROM2 address space can overwrite the AES encryption key, JTAG debug authentication key, and access control permissions for all bus subordinates. This would allow complete compromise of confidentiality (AES key replacement enables data decryption/manipulation), integrity (access control bypass), and debug security (JTAG key overwrite enables unauthorized debug access).",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The AXI node's address routing and the upstream access control (if any) for the ROM2 slave port itself are not fully visible in the provided scope. However, since ROM2 is mapped as slave 9 in ariane_soc_pkg with base address 0x0021_0000, and the access_ctrl for ROM2 is itself stored within ROM2 (creating a circular dependency), any master with access to the ROM2 address region can modify its own access permissions.",
      "recommended_follow_up": [
        "Add write-once or write-disable-after-boot locking mechanism to ROM2 secure_reg registers.",
        "Implement a hardware state machine that only allows writes during a secure boot phase and permanently locks registers afterward.",
        "Consider using actual one-time programmable (OTP) fuse technology or a secure boot ROM that programs keys before releasing the system bus.",
        "Add authentication (e.g., password or cryptographic challenge-response) before allowing writes to secure registers."
      ]
    },
    {
      "finding_id": "F-002",
      "status": "confirmed_finding",
      "summary": "AES encryption key is readable via the APB register interface, allowing any bus master to extract the secret key.",
      "vulnerability_category": "Permission / Access Control - Sensitive Key Readable via Memory-Mapped I/O",
      "affected_locations": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 100,
          "line_end": 130,
          "module": "aes_wrapper",
          "signal_or_register": "key_big readback via external_bus_io.rdata"
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 57,
          "line_end": 57,
          "module": "aes_wrapper",
          "signal_or_register": "key_big assignment from key_in"
        }
      ],
      "evidence": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 109,
          "line_end": 125,
          "module": "aes_wrapper",
          "object": "read side case statement",
          "evidence_type": "source_code",
          "description": "The always @(*) block maps addresses 16-21 to return the six 32-bit slices of key_big (191:0). For example, addr 16 returns key_big[191:160], addr 17 returns key_big[159:128], etc. This allows complete 192-bit AES key extraction through the APB read interface.",
          "supports_claim": "Demonstrates direct exposure of the full AES key through the memory-mapped register interface."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 57,
          "line_end": 57,
          "module": "aes_wrapper",
          "object": "key_big assignment",
          "evidence_type": "source_code",
          "description": "assign key_big = key_in; — the internal key_big directly reflects the key_in input which comes from ROM2's key_reg_out[0].",
          "supports_claim": "Confirms that the readable key_big is the actual AES encryption key, not a masked or derived value."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "object": "AES key connection",
          "evidence_type": "source_code",
          "description": ".key_in (key_reg_out[0]) — the AES key comes from ROM2 slot 0.",
          "supports_claim": "Confirms the AES key is the same one stored in the writable/readable ROM2 register."
        }
      ],
      "reasoning_summary": "The AES wrapper exposes the encryption key through its APB register map at addresses 16-21 (offset 0x40-0x54 in the APB address space). The key is connected directly from the ROM2 secure register. Combined with F-001, this means not only can an attacker overwrite the key, but they can also stealthily extract the existing key before replacement, enabling decryption of previously encrypted data.",
      "security_impact": "HIGH: The AES encryption key can be extracted by any AXI master with access to the AES peripheral address space (base 0x1010_0000). This compromises all data confidentiality that relies on this AES instance. Since the key comes from writable ROM2 storage, an attacker could also replace the key with a known value to perform chosen-key attacks.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "None significant. The read path is clearly visible in the combinational always block.",
      "recommended_follow_up": [
        "Remove the key read-back path from the APB register map (addresses 16-21).",
        "If key verification is needed, implement a write-only comparison mechanism (e.g., write a key and receive a match/mismatch result, never the key itself).",
        "Consider zeroizing the key register after use or implementing hardware key isolation."
      ]
    },
    {
      "finding_id": "F-003",
      "status": "confirmed_finding",
      "summary": "ROM2 secure registers are readable via AXI bus, allowing complete extraction of all stored keys (AES, JTAG, access control).",
      "vulnerability_category": "Permission / Access Control - Sensitive Key Readable via Memory-Mapped I/O",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 30,
          "line_end": 47,
          "module": "rom2",
          "signal_or_register": "rdata_o read path, raddr_q, secure_reg"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 37,
          "line_end": 37,
          "module": "rom2",
          "object": "read path",
          "evidence_type": "source_code",
          "description": "raddr_q <= addr_i[$clog2(RomSize)-1+3:3]; — on read request, the address is latched to select which 64-bit slice of the 192-bit secure_reg to read.",
          "supports_claim": "Shows that read access is unconditionally granted on any AXI read request."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "object": "read data output",
          "evidence_type": "source_code",
          "description": "assign rdata_o = (raddr_q < RomSize) ? secure_reg[raddr_q] : '0; — returns the selected 64-bit slice of the full 192-bit secure register content, with only a bounds check.",
          "supports_claim": "Confirms that any slice of the 192-bit key registers can be read out over the AXI interface."
        }
      ],
      "reasoning_summary": "The ROM2 module provides an unrestricted read path for all four 192-bit secure registers. An attacker who can issue AXI reads to the ROM2 address range (base 0x0021_0000) can extract the complete AES key (192 bits), JTAG debug key (32 bits from 192-bit register), and both access control registers (48 bits each from 192-bit registers). The only access control is the $clog2(RomSize)-based address range check, which does not restrict read access.",
      "security_impact": "CRITICAL: Extraction of all system keys enables an attacker to: (1) decrypt all AES-encrypted data, (2) authenticate to the JTAG debug interface, and (3) learn the access control policy to craft targeted bypasses. Combined with F-001 (writability), an attacker can replace keys without detection.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The AXI node's connectivity map based on access_ctrl may restrict which bus masters can reach the ROM2 slave port. However, since the access control configuration is stored within ROM2 itself, at least one master (likely the debug module or a secure boot processor) must have access, and the circular dependency undermines the security model.",
      "recommended_follow_up": [
        "Restrict read access to secure_reg from the AXI bus entirely (read returns zero or causes a bus fault).",
        "Implement a secure read-once or destructive read mechanism if key distribution is needed during boot.",
        "Use dedicated, isolated key distribution wires (like the existing key_reg_out output) rather than exposing keys on the shared bus."
      ]
    },
    {
      "finding_id": "F-004",
      "status": "confirmed_finding",
      "summary": "Access control configuration for AXI bus permissions is stored in writable ROM2 registers, allowing privilege escalation through key modification.",
      "vulnerability_category": "Permission / Access Control - Circular Dependency / Self-Modifiable Access Control Policy",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 20,
          "line_end": 25,
          "module": "rom2",
          "signal_or_register": "mem initialization values for access control (indices 2 and 3)"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 216,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "access_ctrl_reg derived from key_reg_out[2] and [3]"
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 442,
          "line_end": 450,
          "module": "ariane_testharness",
          "signal_or_register": "access_ctrl derived from access_ctrl_reg"
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 399,
          "line_end": 399,
          "module": "axi_node_intf_wrap",
          "signal_or_register": "access_ctrl_i input to axi_node"
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "axi_node_intf_wrap",
          "signal_or_register": "connectivity_map_o derivation from access_ctrl_i"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 20,
          "line_end": 25,
          "module": "rom2",
          "object": "mem initialization",
          "evidence_type": "source_code",
          "description": "The four ROM2 slots contain: index 3 = access control master 1 (192'h00000000_..._0000f8f8_ff6fe00f), index 2 = access control master 0 (192'h00000000_..._0000fff8_ff6ff00f), index 1 = JTAG key, index 0 = AES key. The access control values define which master can access which slave at which privilege level.",
          "supports_claim": "Shows that access control configuration is stored alongside cryptographic keys in the same writable memory."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 216,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "access control extraction",
          "evidence_type": "source_code",
          "description": "assign access_ctrl_reg[0] = key_reg_out[2][47:0]; assign access_ctrl_reg[1] = key_reg_out[3][47:0]; — the 48-bit access control values are extracted from the lower bits of the 192-bit ROM2 registers and exported to the AXI node.",
          "supports_claim": "Confirms that writable ROM2 registers directly control AXI bus permissions."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 448,
          "line_end": 450,
          "module": "ariane_testharness",
          "object": "access_ctrl unpacking",
          "evidence_type": "source_code",
          "description": "for loop unpacks access_ctrl_reg into per-subordinate, per-manager, per-privilege-level bits: assign access_ctrl[i][j] = access_ctrl_reg[i][4*j +: 4]; This is fed to the AXI node's access_ctrl_i port.",
          "supports_claim": "Shows how the ROM2-stored configuration maps to AXI bus access control signals."
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "axi_node_intf_wrap",
          "object": "connectivity_map_o",
          "evidence_type": "source_code",
          "description": "assign connectivity_map_o[i][j] = access_ctrl_i[i][j][priv_lvl_i] || ((j==6) && access_ctrl_i[i][7][priv_lvl_i]); — the AXI connectivity (which master can access which slave) is directly gated by the access_ctrl_i signal derived from ROM2.",
          "supports_claim": "Confirms that the writable ROM2 registers control the hardware-enforced AXI bus permissions."
        }
      ],
      "reasoning_summary": "The AXI bus access control mechanism intended to enforce privilege separation between masters and slaves is undermined by storing the access control policy in writable ROM2 registers. This creates a circular dependency: the access control values that determine which master can access ROM2 are themselves stored in ROM2. An attacker with write access to ROM2 can grant themselves or their compromised master full access to all peripherals by writing permissive values (e.g., all 0xF) to the access control register slots. Even if ROM2 access were restricted to a subset of masters, those masters could be compromised through other vulnerabilities.",
      "security_impact": "HIGH: The access control mechanism can be bypassed by modifying the ROM2-stored permission bits. An attacker who gains write access to ROM2 can escalate privileges to access any peripheral on the AXI bus (DRAM, Ethernet, SPI, UART, GPIO, AES, Debug, etc.). This defeats the entire hardware-enforced privilege separation model.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact bit format of the access_ctrl encoding (4 bits per manager per slave per privilege level) and which privilege levels are active is partially inferred from the source code patterns. The riscv::NB_PRIV_LVL parameter is not defined in the provided scope but the pattern is clear.",
      "recommended_follow_up": [
        "Store access control configuration in true immutable storage (e-fuses, OTP, or boot-time-locked registers) rather than in writable ROM2.",
        "Separate access control storage from cryptographic key storage to reduce attack surface.",
        "Implement a hash or signature verification of access control configuration before applying it to the AXI node."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The provided scope does not include the complete AXI infrastructure (axi2mem, axi_node wrapper internals beyond intf_wrap), the processor core's privilege level generation, or the boot ROM code's runtime behavior. The analysis assumes the displayed RTL is representative of the full system. The bootrom.sv file contains what appears to be device tree or configuration data in hex form but the actual boot code is not visible. No formal verification or simulation was performed."
}