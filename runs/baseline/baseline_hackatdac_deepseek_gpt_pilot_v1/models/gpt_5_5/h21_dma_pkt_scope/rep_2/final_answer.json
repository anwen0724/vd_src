{
  "analysis_summary": "Inspected the visible RTL under the provided scope: local wrappers for DMA, packet/key table (PKT), register lock (REGLK), access control table (ACCT), and integration evidence from riscv_peripherals.sv. The design implements privilege-indexed access gating via acc_ctrl_c[priv_lvl_i][peripheral], register-lock masking, and wrapper-level AXI-lite enable gating. However, visible source evidence shows multiple permission-related weaknesses: the ACCT wrapper exposes too few access-control storage words for the top-level's 14 peripheral permission matrix and then indexes/writes beyond that storage; its output only drives the first three words while the top-level consumes 56 permission bits; reset defaults permissions to all ones; and the PKT wrapper exposes fuse data by default on many reads. These issues can cause unintended peripheral access grants and leakage of fuse/key-related information.",
  "findings": [
    {
      "finding_id": "PERM-ACCT-001",
      "status": "confirmed_finding",
      "summary": "Access-control table sizing and output mapping are inconsistent with the top-level 14-peripheral permission matrix, creating a permission-enforcement vulnerability.",
      "vulnerability_category": "Permission bypass / incorrect access-control mapping",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 33,
          "line_end": 33,
          "module": "acct_wrapper",
          "signal_or_register": "AcCt_MEM_SIZE / acct_mem"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 49,
          "line_end": 49,
          "module": "acct_wrapper",
          "signal_or_register": "acc_ctrl_o"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 108,
          "line_end": 108,
          "module": "acct_wrapper",
          "signal_or_register": "acct_mem[09]"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 216,
          "line_end": 222,
          "module": "riscv_peripherals",
          "signal_or_register": "acc_ctrl_c / acc_ctrl"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 517,
          "line_end": 1906,
          "module": "riscv_peripherals",
          "signal_or_register": "acc_ctrl_c[priv_lvl_i][*]"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 212,
          "line_end": 216,
          "module": "riscv_peripherals",
          "object": "NB_PERIPHERALS / acc_ctrl / acc_ctrl_c",
          "evidence_type": "source_search",
          "description": "Top-level declares a 14-peripheral access-control vector and a privilege-indexed permission matrix.",
          "supports_claim": "Shows the integration expects 4 permission bits for each of 14 peripherals, i.e. 56 bits of access-control state."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 220,
          "line_end": 222,
          "module": "riscv_peripherals",
          "object": "assign acc_ctrl_c[i][j] = acc_ctrl[j*4+i] | (j==5 && acc_ctrl[4*4+i]);",
          "evidence_type": "source_search",
          "description": "Top-level forms each permission bit from acc_ctrl[j*4+i], with a special OR for peripheral index 5.",
          "supports_claim": "Shows all 14 peripheral permissions are consumed from the flattened acc_ctrl bus."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 517,
          "line_end": 1906,
          "module": "riscv_peripherals",
          "object": "acc_ctrl_c[priv_lvl_i][...]",
          "evidence_type": "source_search",
          "description": "Top-level gates peripheral access using acc_ctrl_c[priv_lvl_i][peripheral], including ROM and many wrappers such as PKT, ACCT, REGLK, DMA.",
          "supports_claim": "Shows these access-control bits directly determine whether a privilege level can access peripherals."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 33,
          "line_end": 33,
          "module": "acct_wrapper",
          "object": "localparam AcCt_MEM_SIZE = NB_SLAVE*3",
          "evidence_type": "source_search",
          "description": "ACCT wrapper allocates only NB_SLAVE*3 32-bit words. In the top-level NB_SLAVE is 1, so this is three words.",
          "supports_claim": "Only 96 internal permission bits are allocated for the default one slave, but downstream code assumes at least 10 words for programming and 56 output bits for permissions."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 49,
          "line_end": 49,
          "module": "acct_wrapper",
          "object": "assign acc_ctrl_o = {acct_mem[3*0+2], acct_mem[3*0+1], acct_mem[3*0+0]|{8{we_flag}}};",
          "evidence_type": "source_search",
          "description": "ACCT wrapper output only concatenates acct_mem[2], acct_mem[1], and acct_mem[0] ORed with we_flag, regardless of NB_PERIPHERALS.",
          "supports_claim": "The output does not construct a full 4*NB_PERIPHERALS permission vector for 14 peripherals; high permission bits consumed by the top-level are not driven by corresponding storage."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 108,
          "line_end": 108,
          "module": "acct_wrapper",
          "object": "acct_mem[09] <= reglk_ctrl[7] ? acct_mem[09] : wdata;",
          "evidence_type": "source_search",
          "description": "ACCT write map includes writes up to acct_mem[09].",
          "supports_claim": "With NB_SLAVE=1 and AcCt_MEM_SIZE=3, the visible code indexes beyond the declared acct_mem range, indicating an inconsistent permission table implementation."
        }
      ],
      "reasoning_summary": "The top-level treats acc_ctrl_o as a 4*NB_PERIPHERALS permission vector and indexes it for privilege-level permission checks. NB_PERIPHERALS is 14, so 56 bits are required and consumed. But acct_wrapper allocates acct_mem using AcCt_MEM_SIZE = NB_SLAVE*3; top-level evidence shows NB_SLAVE=1, so only three 32-bit words are intended. More importantly, acc_ctrl_o is assigned from only acct_mem[2:0], while the write/read map references entries as high as acct_mem[09]. This is a structural mismatch in permission-state storage and output generation. Depending on elaboration/tool behavior for out-of-range references and vector width extension/truncation, some permission bits consumed by acc_ctrl_c may be undriven, zero-extended, incorrectly sourced, or not software-configurable. Because acc_ctrl_c gates access to peripherals, this can create incorrect grants or denials; in a security context, incorrect grants are permission bypasses.",
      "security_impact": "Privilege-based peripheral isolation may be ineffective. A lower-privileged requester could be granted access to sensitive peripherals such as PKT, REGLK, DMA, RNG, or crypto blocks if permission bits are miswired, undriven, defaulted permissively, or not lockable. Conversely, administrators may believe permissions were programmed for all 14 peripherals when only a subset is actually represented by the ACCT output.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact elaboration behavior for out-of-range acct_mem references and width mismatch is tool-dependent and could not be simulated or linted under the task constraints. However, the structural inconsistency is visible in source and directly affects permission-gating signals.",
      "recommended_follow_up": [
        "Redesign acct_wrapper so the internal storage and acc_ctrl_o width exactly cover 4*NB_PERIPHERALS bits for all integrated peripherals and privilege levels.",
        "Eliminate out-of-range acct_mem references; parameterize the address map from NB_PERIPHERALS/NB_SLAVE and add synthesis-time assertions for storage bounds and output width.",
        "Define fail-closed behavior for any unimplemented or invalid access-control bit rather than allowing width-extension or unknown behavior to determine permissions.",
        "Add verification that each acc_ctrl_c[priv][peripheral] bit maps to exactly one writable, lockable ACCT register field."
      ]
    },
    {
      "finding_id": "PERM-ACCT-002",
      "status": "potential_warning",
      "summary": "ACCT permission registers reset to all ones while permission bits are used as positive access enables, producing a permissive default state.",
      "vulnerability_category": "Permissive default access control",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 84,
          "line_end": 84,
          "module": "acct_wrapper",
          "signal_or_register": "acct_mem[j]"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 517,
          "line_end": 1906,
          "module": "riscv_peripherals",
          "signal_or_register": "acc_ctrl_c[priv_lvl_i][*]"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 84,
          "line_end": 84,
          "module": "acct_wrapper",
          "object": "acct_mem[j] <= 32'hffffffff;",
          "evidence_type": "source_search",
          "description": "On reset, every ACCT memory word is initialized to 32'hffffffff.",
          "supports_claim": "Shows access-control state resets to all ones."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 517,
          "line_end": 517,
          "module": "riscv_peripherals",
          "object": "assign rom_req = rom_req_acct && acc_ctrl_c[priv_lvl_i][0];",
          "evidence_type": "source_search",
          "description": "Top-level access decisions use acc_ctrl_c[priv_lvl_i][peripheral] as positive enables for peripheral access.",
          "supports_claim": "A permission bit of one enables access for at least ROM."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 926,
          "line_end": 1906,
          "module": "riscv_peripherals",
          "object": ".acct_ctrl_i ( acc_ctrl_c[priv_lvl_i][...] )",
          "evidence_type": "source_search",
          "description": "Multiple wrappers receive acct_ctrl_i from acc_ctrl_c[priv_lvl_i][peripheral].",
          "supports_claim": "Permission bits are consistently used as positive enables across sensitive peripherals, including DMA, REGLK, ACCT, and PKT."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/dma/dma_wrapper.sv",
          "line_start": null,
          "line_end": null,
          "module": "dma_wrapper",
          "object": "assign en = en_acct && acct_ctrl_i;",
          "evidence_type": "source_read",
          "description": "Wrapper-local AXI-lite enable is gated by acct_ctrl_i.",
          "supports_claim": "Shows acct_ctrl_i high grants access inside DMA wrapper."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": null,
          "line_end": null,
          "module": "pkt_wrapper",
          "object": "assign en = en_acct && acct_ctrl_i;",
          "evidence_type": "source_read",
          "description": "Wrapper-local AXI-lite enable is gated by acct_ctrl_i.",
          "supports_claim": "Shows acct_ctrl_i high grants access inside PKT wrapper."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": null,
          "line_end": null,
          "module": "reglk_wrapper",
          "object": "assign en = en_acct && acct_ctrl_i;",
          "evidence_type": "source_read",
          "description": "Wrapper-local AXI-lite enable is gated by acct_ctrl_i.",
          "supports_claim": "Shows acct_ctrl_i high grants access inside REGLK wrapper."
        }
      ],
      "reasoning_summary": "The access-control bits appear to be positive enables: requests or wrapper-local accesses proceed when acc_ctrl_c/ acct_ctrl_i is one. The ACCT state resets to all ones, which makes the reset/default state permissive. If software or secure boot code does not immediately reprogram and lock the ACCT table before any untrusted requester can access the bus, lower privilege modes may access all protected peripherals by default. A permission system generally should fail closed until policy is configured.",
      "security_impact": "During reset release or after a reset of the ACCT block, protected peripherals may become accessible to all privilege levels. This can permit unauthorized reads/writes to security-critical blocks before policy lockdown, including register-lock configuration, packet/fuse/key data, or DMA setup.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The complete boot/reset sequencing and whether untrusted masters can access the bus before ACCT reprogramming were not visible. Therefore this is reported as a potential warning rather than a fully confirmed exploit path.",
      "recommended_follow_up": [
        "Change reset defaults for access-control bits to deny-by-default unless a documented secure boot stage explicitly requires temporary access.",
        "Gate external/untrusted bus access until ACCT and REGLK policy programming is complete and locked.",
        "Document the intended boot-time trust model and verify that no lower-privilege or DMA/NOC request can occur while acct_mem is all ones."
      ]
    },
    {
      "finding_id": "PERM-PKT-001",
      "status": "potential_warning",
      "summary": "PKT read path can expose fuse/key-related data under weak permission and lock conditions and is not fail-closed for all address paths.",
      "vulnerability_category": "Sensitive data exposure due to insufficient permission gating",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": null,
          "line_end": null,
          "module": "pkt_wrapper",
          "signal_or_register": "rdata / fuse_rdata_i / pkey_loc"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1627,
          "line_end": 1627,
          "module": "riscv_peripherals",
          "signal_or_register": "acct_ctrl_i for PKT"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1627,
          "line_end": 1627,
          "module": "riscv_peripherals",
          "object": ".acct_ctrl_i ( acc_ctrl_c[priv_lvl_i][5] )",
          "evidence_type": "source_search",
          "description": "PKT wrapper is access-gated by acct_ctrl_i derived from acc_ctrl_c[priv_lvl_i][5].",
          "supports_claim": "Shows PKT access depends on the ACCT permission bit for the current privilege level."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": null,
          "line_end": null,
          "module": "pkt_wrapper",
          "object": "assign en = en_acct && acct_ctrl_i;",
          "evidence_type": "source_read",
          "description": "PKT wrapper gates AXI-lite internal enable with acct_ctrl_i.",
          "supports_claim": "If the PKT permission bit is high, the read-side logic can return PKT/fuse data."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": null,
          "line_end": null,
          "module": "pkt_wrapper",
          "object": "rdata = fuse_rdata_i; case(address[7:3]) ... rdata = reglk_ctrl_i[4] ? 'b0 : pkey_loc[63:32]; ... rdata = reglk_ctrl_i[6] ? 'b0 : fuse_rdata_i; default: if (fuse_addr_o <= 110) rdata = 32'b0;",
          "evidence_type": "source_read",
          "description": "PKT read-side initializes rdata to fuse_rdata_i for any enabled read before decoding the address; specific addresses expose pkey_loc halves when corresponding reglk bits are not set and fuse_rdata_i at address 4 when reglk_ctrl_i[6] is not set.",
          "supports_claim": "Shows sensitive fuse/key-related data can be returned when permission and lock bits allow it; the default preassignment to fuse_rdata_i can leak data for addresses not zeroed by the default branch."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": null,
          "line_end": null,
          "module": "pkt_wrapper",
          "object": ".req_i(1'b1), .fuse_indx_i(fuse_addr_o), .pkey_loc_o(pkey_loc)",
          "evidence_type": "source_read",
          "description": "PKT instance always receives req_i tied high and uses fuse_addr_o to produce pkey_loc_o.",
          "supports_claim": "PKT key-location logic is continuously active rather than only on an authorized request signal."
        }
      ],
      "reasoning_summary": "The PKT wrapper contains sensitive outputs: fuse_rdata_i and pkey_loc. Access is gated only by acct_ctrl_i, and key/fuse reads are masked only by specific reglk_ctrl_i bits. The read-side logic preloads rdata with fuse_rdata_i for any enabled access before address decode, and only some default cases overwrite it with zero depending on fuse_addr_o <= 110. This creates a risky permission boundary: if ACCT is permissive or misconfigured, a requester can read key/fuse-related data; additionally, certain out-of-map address/default paths may return fuse_rdata_i instead of denying by default.",
      "security_impact": "Unauthorized software with PKT access, or any privilege level erroneously granted by the ACCT issues above, may read fuse contents or private key location data. Leakage of fuse/key material can compromise device secrets, secure boot, or cryptographic isolation.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The implementation of pkt and fuse memory contents was not present in the visible scope, and exact AXI address behavior for out-of-map reads was not simulated. The finding is based on visible read-data assignment and permission/lock gating logic.",
      "recommended_follow_up": [
        "Make PKT read data fail-closed: initialize rdata to zero and explicitly return fuse/key data only for authorized, valid addresses.",
        "Require both a positive access-control permission and appropriate lock/key-read authorization before exposing pkey_loc or fuse_rdata_i.",
        "Avoid tying PKT req_i permanently high; drive it from a validated, authorized read request.",
        "Verify that all unmapped addresses return zero or an error, independent of fuse_addr_o."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "Analysis was limited to source files visible via the provided tool outputs. Several instantiated modules, including axi_lite_interface, dma, pkt internals, and other peripheral wrappers, were not available or not fully visible. No simulation, elaboration, lint, formal checks, or synthesis were performed, so tool-specific effects of width mismatches/out-of-range indexing are inferred from source structure only."
}