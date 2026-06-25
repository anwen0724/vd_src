{
  "analysis_summary": "Reviewed the RTL/source files under the provided scope for permission-related security issues. The visible source shows that ROM2 is used as a secure fuse/key store and as the source of access-control policy, but it exposes both read and write behavior through an AXI memory interface without local authorization checks. Because access-control registers are directly derived from ROM2 secure registers and then used by the AXI node permission/connectivity map, writes to ROM2 can alter SoC permissions. The AES wrapper also exposes its full ROM2-derived 192-bit key through readable registers.",
  "findings": [
    {
      "finding_id": "PERM-001",
      "status": "confirmed_finding",
      "summary": "ROM2 secure registers are writable through the AXI-facing memory path and directly drive the SoC access-control permission matrix.",
      "vulnerability_category": "Permission bypass / mutable access-control policy storage",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 3,
          "line_end": 13,
          "module": "rom2",
          "signal_or_register": "secure_reg"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 34,
          "line_end": 40,
          "module": "rom2",
          "signal_or_register": "secure_reg"
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "signal_or_register": "rdata_o"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 204,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "key_reg_out/access_ctrl_reg/jtag_key"
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 450,
          "line_end": 450,
          "module": "ariane_testharness",
          "signal_or_register": "access_ctrl"
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "connectivity_mapping",
          "signal_or_register": "connectivity_map_o"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 1,
          "line_end": 3,
          "module": "rom2",
          "object": "ROM2 purpose comment",
          "evidence_type": "source_comment",
          "description": "ROM2 is described as containing all keys.",
          "supports_claim": "Shows ROM2 is intended to hold security-sensitive key material."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 13,
          "line_end": 13,
          "module": "rom2",
          "object": "output logic [3:0][191:0] secure_reg",
          "evidence_type": "source_code",
          "description": "ROM2 exposes the secure register bank as an output port.",
          "supports_claim": "Shows secure registers are externally visible to integration logic."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 34,
          "line_end": 34,
          "module": "rom2",
          "object": "secure_reg <= mem",
          "evidence_type": "source_code",
          "description": "On reset, secure_reg is initialized from constant fuse-like memory.",
          "supports_claim": "Shows secure_reg stores the ROM2 key/access-control values."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 37,
          "line_end": 40,
          "module": "rom2",
          "object": "secure_reg[addr_i[$clog2(RomSize)-1+3:3]] <= wdata_i",
          "evidence_type": "source_code",
          "description": "After reset, a request with we_i asserted writes bus data directly into secure_reg indexed by address.",
          "supports_claim": "Shows the secure register bank is writable without a local privilege, master, lock, or authorization check."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 47,
          "line_end": 47,
          "module": "rom2",
          "object": "assign rdata_o = (raddr_q < RomSize) ? secure_reg[raddr_q] : '0",
          "evidence_type": "source_code",
          "description": "ROM2 reads return secure_reg contents.",
          "supports_claim": "Shows security-sensitive ROM2 contents are readable over the memory interface."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 191,
          "line_end": 212,
          "module": "ariane_peripherals",
          "object": "i_axi2rom2 and i_rom2 connections",
          "evidence_type": "source_code",
          "description": "ROM2 is connected to AXI via axi2mem, with req/we/address/wdata/rdata connected to the rom2_fuse AXI slave path.",
          "supports_claim": "Shows ROM2 is accessible through an AXI-facing memory path."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "jtag_key/access_ctrl_reg assignments from key_reg_out",
          "evidence_type": "source_code",
          "description": "ROM2 secure register outputs drive security-critical values: jtag_key and two access-control registers.",
          "supports_claim": "Shows ROM2 secure register contents directly determine JTAG key and access-control policy."
        },
        {
          "file": "tb/ariane_testharness.sv",
          "line_start": 450,
          "line_end": 450,
          "module": "ariane_testharness",
          "object": "assign access_ctrl[i][j] = access_ctrl_reg[i][4*j +: 4]",
          "evidence_type": "source_code",
          "description": "The test harness expands access_ctrl_reg bitfields into the access_ctrl permission matrix.",
          "supports_claim": "Shows ROM2-derived access-control register bits become the active permission matrix."
        },
        {
          "file": "src/axi_node/src/axi_node_intf_wrap.sv",
          "line_start": 430,
          "line_end": 430,
          "module": "connectivity_mapping",
          "object": "connectivity_map_o assignment",
          "evidence_type": "source_code",
          "description": "The AXI connectivity map is derived from access_ctrl_i indexed by current privilege level.",
          "supports_claim": "Shows the ROM2-derived permission matrix controls AXI connectivity/permission decisions."
        }
      ],
      "reasoning_summary": "ROM2 acts as the root storage for both key material and access-control policy. However, its internal secure_reg array can be written via req_i/we_i/wdata_i without any local authorization, privilege-level, master-ID, lock-state, or write-once restriction. Integration code wires secure_reg entries into access_ctrl_reg, and the AXI node uses those bits to build the connectivity map by privilege level. Therefore, any actor able to reach ROM2 writes can modify the live permission policy and potentially grant itself or another master access to protected peripherals.",
      "security_impact": "A malicious or compromised bus master that can issue writes to the ROM2 address range may alter access-control registers, bypass master/peripheral/privilege isolation, enable unauthorized peripheral access, modify the JTAG key, or corrupt AES key material. This undermines the SoC permission model because the root of the access-control policy is itself writable through a bus-facing interface.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The visible source does not include the full implementation of the underlying axi_node or axi2mem modules, nor runtime software configuration. The files reviewed do not prove which masters can initially access ROM2 under the default policy. However, the ROM2 module itself lacks local enforcement, and the source directly shows writable security-policy storage feeding the AXI permission map.",
      "recommended_follow_up": [
        "Make ROM2 fuse-derived security registers read-only after reset or enforce one-time-programming semantics if mutation is required.",
        "Add local authorization checks in ROM2 for any write path, independent of upstream interconnect policy.",
        "Separate access-control policy storage from software-accessible memory space or protect it with immutable hardware policy.",
        "Verify reset/default access_ctrl settings and prove no untrusted master can write ROM2 before policy is locked."
      ]
    },
    {
      "finding_id": "PERM-002",
      "status": "confirmed_finding",
      "summary": "The AES wrapper exposes the full ROM2-derived 192-bit AES key through normal readable registers.",
      "vulnerability_category": "Sensitive key disclosure through permissionless register read",
      "affected_locations": [
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "signal_or_register": "key_reg_out[0]"
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 57,
          "line_end": 57,
          "module": "aes_wrapper",
          "signal_or_register": "key_big"
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 129,
          "line_end": 139,
          "module": "aes_wrapper",
          "signal_or_register": "external_bus_io.rdata"
        }
      ],
      "evidence": [
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 467,
          "line_end": 467,
          "module": "ariane_peripherals",
          "object": ".key_in (key_reg_out[0])",
          "evidence_type": "source_code",
          "description": "AES wrapper receives its key input from ROM2 secure register entry 0.",
          "supports_claim": "Shows the AES key comes from ROM2 secure register storage."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 57,
          "line_end": 57,
          "module": "aes_wrapper",
          "object": "assign key_big = key_in",
          "evidence_type": "source_code",
          "description": "AES wrapper assigns the external key input directly into key_big.",
          "supports_claim": "Shows key_big is the ROM2-derived AES key."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 129,
          "line_end": 139,
          "module": "aes_wrapper",
          "object": "external_bus_io.rdata = key_big[...] cases 16 through 21",
          "evidence_type": "source_code",
          "description": "AES read-side register map returns all six 32-bit chunks of the 192-bit key.",
          "supports_claim": "Shows the full AES key is exposed through readable bus registers."
        },
        {
          "file": "src/aes/aes_wrapper.sv",
          "line_start": 49,
          "line_end": 50,
          "module": "aes_wrapper",
          "object": "external_bus_io.ready/error assignments",
          "evidence_type": "source_code",
          "description": "AES wrapper always reports ready and no error on its register interface.",
          "supports_claim": "Shows no local error response is generated for key-register accesses."
        }
      ],
      "reasoning_summary": "The AES key is security-sensitive material sourced from ROM2 secure registers. The AES wrapper maps key_big into readable register addresses 16 through 21, exposing the complete 192-bit key over the peripheral register bus. No local privilege check, lock bit, debug-only condition, or redaction is visible in the AES wrapper.",
      "security_impact": "Any bus agent permitted to read the AES peripheral can recover the full AES key. This compromises confidentiality of data protected by the AES engine and undermines assumptions that ROM2-derived key material remains secret inside hardware.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The visible source does not prove which masters or privilege levels can access AES by default. Upstream AXI permissions may reduce exploitability for some actors, but the AES block itself contains no local protection against key readback.",
      "recommended_follow_up": [
        "Remove key readback from the AES register map and return zero or an error for key register addresses.",
        "Keep key material internal to the AES block or load it through a write-only/key-ladder path.",
        "Add local access checks for sensitive AES status/debug registers if any must remain readable.",
        "Verify that software-visible AES documentation and tests do not depend on key readback."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "Analysis was limited to visible files under the provided scope and used only read/search inspection. The full implementations of some instantiated modules, runtime firmware behavior, and complete reset-time access policy behavior were not visible. Findings are based on direct source evidence in the scoped RTL."
}