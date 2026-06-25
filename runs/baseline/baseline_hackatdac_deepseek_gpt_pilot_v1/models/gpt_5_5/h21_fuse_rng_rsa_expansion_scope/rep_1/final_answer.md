{
  "analysis_summary": "Analyzed the RTL/source files visible under the provided input scope for permission-related security vulnerabilities. The strongest issue is in the PKT-to-fuse-memory path: fuse memory contains security-sensitive data and can be addressed through pkt_wrapper. Although pkt_wrapper has peripheral-level access gating and an explicit register-lock check on one fuse-data read register, its default read path can leave rdata equal to raw fuse_rdata_i without applying the same register-lock protection. This creates a likely lock-bypass/read-disclosure path for fuse entries. A secondary defense-in-depth concern is that fuse_mem itself has no intrinsic authorization checks and relies entirely on external wrapper correctness.",
  "findings": [
    {
      "finding_id": "FINDING-001",
      "status": "confirmed_finding",
      "summary": "PKT wrapper can expose raw fuse_rdata_i through its default read path without applying the intended reglk_ctrl_i[6] fuse-data lock.",
      "vulnerability_category": "Permission check bypass / sensitive fuse-data disclosure",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 68,
          "line_end": 111,
          "module": "pkt_wrapper",
          "signal_or_register": "en, fuse_req_o, fuse_addr_o, rdata, fuse_rdata_i, reglk_ctrl_i[6]"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 127,
          "line_end": 135,
          "module": "fuse_mem",
          "signal_or_register": "req_i, addr_i, addr_q, rdata_o, mem"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1618,
          "line_end": 1708,
          "module": "riscv_peripherals",
          "signal_or_register": "fuse_req, fuse_addr, fuse_rdata, reglk_ctrl, acc_ctrl_c"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 68,
          "line_end": 68,
          "module": "pkt_wrapper",
          "object": "en",
          "evidence_type": "source",
          "description": "The PKT wrapper gates accesses with peripheral-level access control.",
          "supports_claim": "Access to the PKT register logic is controlled by acct_ctrl_i, showing that permission control is intended at this boundary."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 80,
          "line_end": 85,
          "module": "pkt_wrapper",
          "object": "fuse_req_o, fuse_addr_o",
          "evidence_type": "source",
          "description": "The PKT wrapper allows software-visible writes to control fuse request and fuse address.",
          "supports_claim": "An accessor permitted to reach PKT can select fuse addresses and issue fuse requests."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 92,
          "line_end": 97,
          "module": "pkt_wrapper",
          "object": "rdata, fuse_rdata_i",
          "evidence_type": "source",
          "description": "The PKT read logic initializes rdata to raw fuse_rdata_i before the address case decode.",
          "supports_claim": "Raw fuse data is made the default read value whenever en is asserted, before lock checks are applied for specific addresses."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 106,
          "line_end": 107,
          "module": "pkt_wrapper",
          "object": "reglk_ctrl_i[6], fuse_rdata_i",
          "evidence_type": "source",
          "description": "The explicit fuse-data register at address index 4 applies reglk_ctrl_i[6].",
          "supports_claim": "The design appears to intend register-lock protection for fuse data reads."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 108,
          "line_end": 110,
          "module": "pkt_wrapper",
          "object": "default, fuse_addr_o, rdata",
          "evidence_type": "source",
          "description": "The default case does not apply reglk_ctrl_i[6] and only clears rdata when fuse_addr_o <= 110.",
          "supports_claim": "For default-case reads with fuse_addr_o > 110, rdata remains the raw fuse_rdata_i assigned earlier, bypassing the explicit lock check."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 1,
          "line_end": 123,
          "module": "fuse_mem",
          "object": "mem",
          "evidence_type": "source",
          "description": "The fuse memory is documented as containing secure data and stores keys, hashes, access-control values, and crypto material.",
          "supports_claim": "Disclosure of fuse_rdata_i can expose security-sensitive data."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1618,
          "line_end": 1708,
          "module": "riscv_peripherals",
          "object": "i_pkt_wrapper, i_fuse_mem",
          "evidence_type": "source",
          "description": "Top-level wiring connects pkt_wrapper fuse request/address/data directly to fuse_mem.",
          "supports_claim": "The vulnerable PKT wrapper path is the visible path controlling fuse_mem reads in the top-level integration."
        }
      ],
      "reasoning_summary": "pkt_wrapper permits an accessor with PKT peripheral permission to write fuse_addr_o and fuse_req_o. fuse_mem then returns the selected fuse word as fuse_rdata_i. In the read path, pkt_wrapper sets rdata = fuse_rdata_i for any enabled read before decoding address[7:3]. The intended explicit fuse-data register at address index 4 masks fuse_rdata_i when reglk_ctrl_i[6] is set, but the default branch lacks that mask and only overwrites rdata to zero if fuse_addr_o <= 110. Therefore, for reads to unmapped/default PKT addresses with fuse_addr_o > 110, the response can remain raw fuse_rdata_i even when the explicit locked register would return zero. This is inconsistent permission enforcement and likely a register-lock bypass for fuse data.",
      "security_impact": "An attacker or lower-privilege requester that has access to the PKT peripheral may be able to read fuse contents despite register-lock settings intended to block fuse-data reads. Since the fuse memory contains cryptographic keys, hashes, access-control values, and other security data, exploitation could lead to key disclosure, debug/JTAG authentication compromise, access-control policy exposure or bypass, and broader privilege escalation.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The source for the NoC/AXI-lite bridge and the exact system address map behavior for unmapped/default PKT offsets was not visible. The sources for reglk_wrapper and acct_wrapper were also not present, so reset defaults and write permissions for reglk_ctrl_i and acct_ctrl_i could not be verified. The top-level sets FUSE_MEM_SIZE to 150 while the visible fuse_mem initializer appears shorter; without elaboration, the exact contents of all indices above 110 cannot be confirmed. The lock-bypass logic pattern itself is visible in source.",
      "recommended_follow_up": [
        "Change pkt_wrapper read logic so rdata defaults to zero, not fuse_rdata_i.",
        "Apply reglk_ctrl_i[6] or a stricter fuse-read authorization check to every path that can return fuse_rdata_i.",
        "Make the default case return zero or an error value unconditionally.",
        "Review whether all fuse indices, including indices above 110 under the top-level FUSE_MEM_SIZE parameter, contain sensitive or reserved data.",
        "Verify the NoC/AXI-lite bridge allows reads to default/unmapped PKT offsets; if so, add address-range enforcement."
      ]
    },
    {
      "finding_id": "FINDING-002",
      "status": "potential_warning",
      "summary": "fuse_mem containing secure data has no intrinsic permission enforcement and relies entirely on external access-control logic.",
      "vulnerability_category": "Missing internal authorization / insufficient defense in depth",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 5,
          "line_end": 135,
          "module": "fuse_mem",
          "signal_or_register": "req_i, addr_i, rdata_o, mem"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1699,
          "line_end": 1708,
          "module": "riscv_peripherals",
          "signal_or_register": "fuse_req, fuse_addr, fuse_rdata"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 5,
          "line_end": 13,
          "module": "fuse_mem",
          "object": "module ports",
          "evidence_type": "source",
          "description": "fuse_mem interface has no privilege, access-control, lock, debug-state, or authentication inputs.",
          "supports_claim": "The fuse memory cannot enforce permissions internally because it receives only request and address inputs for reads."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 127,
          "line_end": 131,
          "module": "fuse_mem",
          "object": "addr_q",
          "evidence_type": "source",
          "description": "fuse_mem latches any requested address when req_i is asserted.",
          "supports_claim": "Any driving logic that can assert req_i and control addr_i can select fuse entries."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 135,
          "line_end": 135,
          "module": "fuse_mem",
          "object": "rdata_o",
          "evidence_type": "source",
          "description": "fuse_mem outputs memory contents based only on the latched address.",
          "supports_claim": "There is no internal masking or permission check before returning fuse contents."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1699,
          "line_end": 1708,
          "module": "riscv_peripherals",
          "object": "i_fuse_mem",
          "evidence_type": "source",
          "description": "Top-level connects fuse_mem request/address to pkt_wrapper-generated signals.",
          "supports_claim": "The fuse memory relies on the external PKT wrapper path for access policy enforcement."
        }
      ],
      "reasoning_summary": "fuse_mem is explicitly used to store secure data, but its interface and implementation contain no built-in authorization or lock checks. It accepts a request/address and returns the selected memory word. In the visible integration, it is driven by pkt_wrapper, so the immediate exploitability depends on wrapper correctness. Because Finding 001 shows an inconsistent wrapper check, the lack of intrinsic fuse_mem protection creates a defense-in-depth failure for high-value secrets.",
      "security_impact": "If wrapper logic is incorrect or a future integration exposes req_i/addr_i to a less-trusted requester, fuse contents can be read without internal enforcement. Exposure of keys, hashes, and access-control fuses can compromise confidentiality and may enable further permission bypass.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "This may be an intentional architectural choice if fuse_mem is always placed behind a trusted, verified controller. The visible top-level shows only pkt_wrapper driving it, not a direct external bus. Therefore, this is classified as a potential warning/defense-in-depth issue rather than a standalone confirmed bypass.",
      "recommended_follow_up": [
        "Consider adding direct authorization or lock inputs to fuse_mem, especially for key-bearing fuse entries.",
        "Partition fuse contents by sensitivity and enforce per-range read permissions in or immediately adjacent to fuse_mem.",
        "Ensure only a hardened, verified controller can drive req_i and addr_i.",
        "Add assertions or formal checks that no path can return protected fuse contents when the corresponding lock/access bit denies reads."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The analysis is based only on visible source files under the input scope. Several referenced modules, including acct_wrapper, reglk_wrapper, noc_axilite_bridge, and some peripheral wrappers, were not available in the inspected scope, so their exact reset defaults, address filtering, and permission semantics could not be verified. No simulation, elaboration, lint, synthesis, or formal checks were run. Conclusions are therefore based on static source evidence only."
}