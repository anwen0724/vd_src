{
  "analysis_summary": "Inspected the RTL/source files under the input scope for permission-related security issues. The visible design contains security-sensitive key material and access-control policy in ROM2, exposes ROM2 through an AXI-facing memory interface, permits writes to the ROM2-backed secure registers without local authorization checks, and derives system access-control bits from those writable registers. The AES wrapper also exposes the full AES key through readable MMIO registers without local permission checks. These are permission/access-control vulnerabilities because sensitive state and policy can be read or modified by any transaction that reaches the peripheral, and the peripherals themselves do not validate privilege, requester identity, or read/write authorization.",
  "findings": [
    {
      "finding_id": "PERM-001",
      "status": "confirmed_finding",
      "summary": "ROM2 secure key/access-control storage is memory-mapped, readable, and writable without local authorization checks.",
      "vulnerability_category": "Missing authorization / improper access control on security-sensitive MMIO storage",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 5,
          "line_end": 47,
          "module": "rom2",
          "signal_or_register": "secure_reg, mem, req_i, we_i, addr_i, wdata_i, rdata_o"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 191,
          "line_end": 212,
          "module": "ariane_peripherals",
          "signal_or_register": "rom2_fuse, rom2_req, rom2_we, rom2_addr, rom2_wdata, rom2_rdata, key_reg_out"
        },
        {
          "file": "tb/ariane_soc_pkg.sv",
          "line_start": 31,
          "line_end": 55,
          "module": "ariane_soc package",
          "signal_or_register": "ROM2, ROM2Length, ROM2Base"
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 476,
          "line_end": 550,
          "module": "ariane_testharness",
          "signal_or_register": "master[ariane_soc::ROM2], ROM2Base/ROM2Length address mapping"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 1,
          "line_end": 3,
          "module": "rom2",
          "object": "ROM2 comment",
          "evidence_type": "source_comment",
          "description": "ROM2 is explicitly described as containing all keys.",
          "supports_claim": "ROM2 is intended to hold security-sensitive key material."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 14,
          "line_end": 20,
          "module": "rom2",
          "object": "mem",
          "evidence_type": "source_code",
          "description": "ROM2 initializes constant entries containing AES key, JTAG key, and access-control values.",
          "supports_claim": "Security-sensitive data and policy are stored in ROM2."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 33,
          "line_end": 35,
          "module": "rom2",
          "object": "secure_reg <= mem",
          "evidence_type": "source_code",
          "description": "On reset, ROM2 copies constant values into secure_reg.",
          "supports_claim": "The runtime security-sensitive state is held in secure_reg."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 36,
          "line_end": 41,
          "module": "rom2",
          "object": "secure_reg write path",
          "evidence_type": "source_code",
          "description": "During normal operation, any req_i with we_i writes wdata_i into secure_reg indexed by addr_i. No privilege, requester, lock, or authorization condition is checked in this module.",
          "supports_claim": "ROM2 secure registers are writable through the bus-facing interface without local permission enforcement."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "object": "rdata_o",
          "evidence_type": "source_code",
          "description": "Read data is returned directly from secure_reg based on raddr_q.",
          "supports_claim": "ROM2 secure register contents are readable through the bus-facing interface."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 191,
          "line_end": 200,
          "module": "ariane_peripherals",
          "object": "i_axi2rom2",
          "evidence_type": "integration",
          "description": "ROM2 is connected to an AXI-facing axi2mem adapter, which produces req/we/address/write-data and consumes read-data.",
          "supports_claim": "ROM2 is exposed as a bus-accessible peripheral."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 204,
          "line_end": 212,
          "module": "ariane_peripherals",
          "object": "i_rom2",
          "evidence_type": "integration",
          "description": "The ROM2 instance receives the AXI-derived req/we/address/write-data signals and returns read data; secure_reg is exported as key_reg_out.",
          "supports_claim": "External bus accesses can reach ROM2's read/write interface."
        },
        {
          "file": "tb/ariane_soc_pkg.sv",
          "line_start": 31,
          "line_end": 55,
          "module": "ariane_soc package",
          "object": "ROM2, ROM2Length, ROM2Base",
          "evidence_type": "source_code",
          "description": "ROM2 is assigned a base address and size in the SoC address map.",
          "supports_claim": "ROM2 is memory-mapped in the SoC."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 476,
          "line_end": 550,
          "module": "ariane_testharness",
          "object": "ROM2 address mapping and rom2_fuse connection",
          "evidence_type": "integration",
          "description": "The test harness includes ROM2Base and ROM2Base+ROM2Length-1 in the AXI node address map and connects master[ariane_soc::ROM2] to rom2_fuse.",
          "supports_claim": "ROM2 is reachable through the SoC interconnect address map."
        }
      ],
      "reasoning_summary": "ROM2 is intended to contain keys and security policy, but its RTL implements a generic memory-like interface. When req_i is asserted and we_i is high, secure_reg is updated directly from wdata_i at the address-selected index. When read, rdata_o returns secure_reg content. The module does not check privilege level, requester identity, transaction source, read/write permissions, lock state, or whether the target entry is secret/policy. Integration evidence shows ROM2 is memory-mapped through an AXI-facing adapter and connected into the SoC address map. Thus, any requester that can reach ROM2 can read or overwrite key/policy state at the peripheral boundary.",
      "security_impact": "An attacker with a bus path to ROM2 could read AES/JTAG keys, overwrite keys, corrupt secure state, or modify the policy values used elsewhere for access control. This can lead to privilege escalation, debug bypass, cryptographic key compromise, and persistent weakening of isolation until reset or re-provisioning.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The complete implementation and configuration of all upstream AXI access-control modules is not fully visible. If the interconnect absolutely prevents all untrusted accesses to ROM2, exploitability is reduced. However, ROM2 itself contains no local protection, and the visible integration exposes it as a bus peripheral.",
      "recommended_follow_up": [
        "Add local ROM2 authorization checks for read and write operations based on trusted privilege/requester metadata, not only upstream routing.",
        "Make fuse/key contents read-protected after provisioning; do not expose raw key material over MMIO.",
        "Make access-control policy registers immutable after reset or writable only through a trusted lifecycle/provisioning mechanism.",
        "Reject unauthorized accesses with an error response rather than returning data or silently accepting writes.",
        "Verify with formal/security assertions that untrusted masters cannot read or write ROM2 entries."
      ]
    },
    {
      "finding_id": "PERM-002",
      "status": "confirmed_finding",
      "summary": "System access-control permissions are derived from ROM2 entries that are writable through ROM2's bus interface.",
      "vulnerability_category": "Mutable access-control policy / authorization bypass risk",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 14,
          "line_end": 41,
          "module": "rom2",
          "signal_or_register": "secure_reg[2], secure_reg[3], mem access-control entries"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "access_ctrl_reg, key_reg_out"
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 439,
          "line_end": 473,
          "module": "ariane_testharness",
          "signal_or_register": "access_ctrl, access_ctrl_reg, priv_lvl"
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 415,
          "line_end": 430,
          "module": "axi_node_intf_wrap / addr_decoder",
          "signal_or_register": "access_ctrl_i, priv_lvl_i, connectivity_map_o"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 14,
          "line_end": 17,
          "module": "rom2",
          "object": "mem[access-control entries]",
          "evidence_type": "source_comment_and_code",
          "description": "ROM2 constant entries are commented as access-control values for master 1 and master 0.",
          "supports_claim": "ROM2 stores access-control policy values."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 36,
          "line_end": 41,
          "module": "rom2",
          "object": "secure_reg write path",
          "evidence_type": "source_code",
          "description": "ROM2 writes can update secure_reg through the MMIO-style write path.",
          "supports_claim": "The access-control entries stored in secure_reg are mutable via ROM2 writes."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 216,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "access_ctrl_reg",
          "evidence_type": "source_code",
          "description": "Access-control outputs are assigned from key_reg_out[2][47:0] and key_reg_out[3][47:0], which are ROM2 secure_reg outputs.",
          "supports_claim": "ROM2-derived state directly becomes system access-control configuration."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 442,
          "line_end": 450,
          "module": "ariane_testharness",
          "object": "access_ctrl",
          "evidence_type": "source_code",
          "description": "The test harness slices access_ctrl_reg into per-master/per-peripheral access_ctrl bits.",
          "supports_claim": "The ROM2-derived access-control register values drive the access-control matrix."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 454,
          "line_end": 473,
          "module": "ariane_testharness",
          "object": "axi_node_intf_wrap instantiation",
          "evidence_type": "integration",
          "description": "The AXI node receives access_ctrl as access_ctrl_i and also receives priv_lvl_i.",
          "supports_claim": "The ROM2-derived policy is provided to the AXI interconnect/access-control logic."
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 415,
          "line_end": 430,
          "module": "axi_node_intf_wrap / addr_decoder",
          "object": "connectivity_map_o",
          "evidence_type": "source_code",
          "description": "The AXI node computes connectivity_map_o from access_ctrl_i indexed by priv_lvl_i.",
          "supports_claim": "Access decisions depend directly on the ROM2-derived access-control bits."
        }
      ],
      "reasoning_summary": "The visible design stores system access-control policy values in ROM2 secure_reg entries and exports those values to access_ctrl_reg. The test harness converts access_ctrl_reg into the access_ctrl matrix, and the AXI node uses access_ctrl_i[...][priv_lvl_i] to generate connectivity permissions. Because ROM2 permits writes to secure_reg without local authorization, a requester with ROM2 write access can potentially modify the same policy that controls peripheral access, creating a privilege-escalation path and a circular dependency in the permission model.",
      "security_impact": "If an attacker can write ROM2, they may grant themselves or another master access to restricted peripherals such as ROM2, AES, debug, PLIC, or memory regions. This can bypass intended isolation, alter privilege boundaries, and undermine the SoC-wide access-control policy.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact enumeration and width of all privilege levels are defined outside the visible files, and the complete lower-level AXI node implementation is not fully shown. Nevertheless, the visible code clearly shows writable ROM2-derived state feeding connectivity_map_o permission decisions.",
      "recommended_follow_up": [
        "Do not store active access-control policy in a writable MMIO-accessible array unless writes are strictly authorized by immutable hardware policy.",
        "Separate immutable root policy from software-visible key storage.",
        "Add write-once/lock mechanisms for access-control entries and assert that they cannot change after secure boot/provisioning.",
        "Ensure the permission-checking fabric does not depend on policy that can be modified through the protected fabric by untrusted masters.",
        "Add assertions that user/untrusted privilege levels cannot alter access_ctrl_reg or ROM2 entries that feed it."
      ]
    },
    {
      "finding_id": "PERM-003",
      "status": "confirmed_finding",
      "summary": "AES wrapper exposes the full AES key through readable MMIO registers without local permission checks.",
      "vulnerability_category": "Sensitive key disclosure through insufficient MMIO access control",
      "affected_locations": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 28,
          "line_end": 157,
          "module": "aes_wrapper",
          "signal_or_register": "key_in, key_big, external_bus_io.rdata"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 463,
          "line_end": 468,
          "module": "ariane_peripherals",
          "signal_or_register": "key_reg_out[0], key_in"
        },
        {
          "file": "tb/ariane_soc_pkg.sv",
          "line_start": 42,
          "line_end": 57,
          "module": "ariane_soc package",
          "signal_or_register": "AES, AESLength, AESBase"
        }
      ],
      "evidence": [
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 28,
          "line_end": 31,
          "module": "aes_wrapper",
          "object": "key_in",
          "evidence_type": "source_code",
          "description": "AES wrapper receives a 192-bit key input.",
          "supports_claim": "The AES wrapper has direct access to AES key material."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 57,
          "line_end": 57,
          "module": "aes_wrapper",
          "object": "key_big",
          "evidence_type": "source_code",
          "description": "The internal key_big signal is assigned directly from key_in.",
          "supports_claim": "key_big contains the AES key supplied to the wrapper."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 152,
          "line_end": 157,
          "module": "aes_wrapper",
          "object": "aes_192_sed.key",
          "evidence_type": "source_code",
          "description": "The AES engine instance uses key_big as its key input.",
          "supports_claim": "key_big is cryptographic key material, not just status/configuration data."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 128,
          "line_end": 139,
          "module": "aes_wrapper",
          "object": "external_bus_io.rdata key reads",
          "evidence_type": "source_code",
          "description": "The read-side case statement returns all six 32-bit words of key_big at offsets 16 through 21.",
          "supports_claim": "The full 192-bit AES key is exposed through readable MMIO registers."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 51,
          "line_end": 52,
          "module": "aes_wrapper",
          "object": "external_bus_io.ready/error",
          "evidence_type": "source_code",
          "description": "The wrapper permanently reports ready and no error and does not contain a local authorization condition around key reads.",
          "supports_claim": "The AES wrapper does not reject unauthorized accesses locally."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 463,
          "line_end": 468,
          "module": "ariane_peripherals",
          "object": "i_aes_wrapper.key_in",
          "evidence_type": "integration",
          "description": "The AES key input is connected to key_reg_out[0], which comes from ROM2 secure_reg.",
          "supports_claim": "The readable key exposed by AES is the ROM2-derived AES key."
        },
        {
          "file": "tb/ariane_soc_pkg.sv",
          "line_start": 42,
          "line_end": 57,
          "module": "ariane_soc package",
          "object": "AESBase/AESLength",
          "evidence_type": "source_code",
          "description": "AES has a defined base address and length in the SoC address map.",
          "supports_claim": "AES is a memory-mapped peripheral, so key registers are externally addressable if the AES region is reachable."
        }
      ],
      "reasoning_summary": "The AES wrapper assigns key_big from key_in, uses key_big for encryption, and also maps key_big onto read data for offsets 16 through 21. There is no local privilege check, lock bit, read-disable, or error response for these key reads. Therefore any requester that can read the AES MMIO region can retrieve the full AES key instead of being limited to invoking AES operations.",
      "security_impact": "A requester with access to the AES MMIO space can extract the 192-bit AES key, enabling decryption or forgery outside the hardware engine, cloning of protected device secrets, and compromise of confidentiality/integrity mechanisms relying on that key.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The upstream AXI access-control policy may restrict which masters can reach the AES region. However, the AES peripheral itself exposes the raw key to any permitted AES reader, which is still an insecure permission model for cryptographic hardware.",
      "recommended_follow_up": [
        "Remove key_big from the readable register map; never expose raw AES keys through MMIO.",
        "If debug visibility is required, gate it behind immutable lifecycle/debug authorization and ensure it is disabled in production.",
        "Add local access-control checks in the AES wrapper for sensitive registers, including explicit error responses for unauthorized reads.",
        "Add security assertions that external_bus_io.rdata never equals key material for non-secure requests.",
        "Consider loading keys through a write-only path or from a hardware key manager/fuse interface that prevents software readback."
      ]
    },
    {
      "finding_id": "PERM-004",
      "status": "potential_warning",
      "summary": "JTAG key is sourced from writable ROM2 state, creating a potential debug authorization weakness.",
      "vulnerability_category": "Potential mutable debug authentication credential",
      "affected_locations": [
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 215,
          "module": "ariane_peripherals",
          "signal_or_register": "jtag_key, key_reg_out[1]"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 18,
          "line_end": 41,
          "module": "rom2",
          "signal_or_register": "secure_reg[1], mem JTAG entry"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 18,
          "line_end": 18,
          "module": "rom2",
          "object": "mem JTAG entry",
          "evidence_type": "source_comment_and_code",
          "description": "ROM2 contains a 192-bit entry commented as the JTAG key.",
          "supports_claim": "JTAG authentication or debug keying material is stored in ROM2."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 36,
          "line_end": 41,
          "module": "rom2",
          "object": "secure_reg write path",
          "evidence_type": "source_code",
          "description": "ROM2 secure_reg entries are writable during normal operation through req_i/we_i.",
          "supports_claim": "The JTAG key entry can be modified if the corresponding ROM2 address is written."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 215,
          "module": "ariane_peripherals",
          "object": "jtag_key",
          "evidence_type": "source_code",
          "description": "The jtag_key output is assigned from key_reg_out[1][31:0].",
          "supports_claim": "The JTAG key used by integration is sourced from ROM2 secure_reg."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 142,
          "line_end": 153,
          "module": "ariane_testharness",
          "object": "dmi_jtag.jtag_key",
          "evidence_type": "integration",
          "description": "The test harness connects jtag_key into the dmi_jtag instance.",
          "supports_claim": "The ROM2-derived JTAG key affects the debug/JTAG block interface."
        }
      ],
      "reasoning_summary": "The design sources jtag_key from ROM2 state, and ROM2 state is writable through the ROM2 bus interface. If dmi_jtag uses this key for debug authentication, then a ROM2 write could alter the debug authentication secret. The actual dmi_jtag implementation is not present in the inspected files, so the exact impact cannot be fully confirmed, but the visible wiring indicates a plausible debug-permission weakness tied to writable security state.",
      "security_impact": "Potential debug authentication bypass, denial of debug access, or alteration of debug authorization state if an attacker can write the ROM2 JTAG-key entry and if dmi_jtag relies on this key for access control.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The dmi_jtag module implementation is not included in the visible source scope, so the precise authentication semantics and exploitability of modifying jtag_key cannot be proven from the provided files alone.",
      "recommended_follow_up": [
        "Confirm how dmi_jtag uses jtag_key and whether changing it can bypass or disable debug authentication.",
        "Make the JTAG key immutable or writable only through an authenticated lifecycle/provisioning path.",
        "Prevent software or untrusted bus masters from reading or writing the ROM2 JTAG key entry.",
        "Add assertions that jtag_key cannot change after secure initialization in production mode."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The full implementations of some external modules such as axi2mem, axi2apb_64_32, apb_to_reg, dmi_jtag, the processor privilege source, and the complete AXI node internals are not fully visible under the inspected source scope. Upstream interconnect policy may reduce exploitability for some initiators. The findings are based on visible local peripheral behavior and integration wiring showing sensitive state exposed through bus-accessible interfaces without local authorization enforcement."
}