{
  "analysis_summary": "The inspected RTL implements memory-mapped access-control (ACCT) and register-lock (REGLK) mechanisms for peripherals. The visible source shows a fail-open permission model: ACCT registers reset to all ones, which are then used as enable bits indexed by current privilege level; REGLK registers reset to zero, leaving lock protections disabled; and both ACCT and REGLK blocks are themselves gated by those same default-enabled access-control bits. This creates permission-related vulnerabilities where untrusted or lower-privilege software may access sensitive peripherals and modify the permission/lock policy unless trusted firmware configures the system before any attacker-controlled access. PKT/fuse-derived data is also readable when default locks are unset. The exact exploitability depends on boot sequencing, external NoC filters, and debug/lifecycle controls not visible in scope.",
  "findings": [
    {
      "finding_id": "PERM-001",
      "status": "confirmed_finding",
      "summary": "Access-control registers reset to all ones, causing protected peripheral access to be enabled by default for all privilege levels.",
      "vulnerability_category": "Fail-open access control / insecure reset default",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 49,
          "line_end": 49,
          "module": "acct_wrapper",
          "signal_or_register": "acc_ctrl_o / acct_mem"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 84,
          "line_end": 84,
          "module": "acct_wrapper",
          "signal_or_register": "acct_mem"
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
          "line_start": 926,
          "line_end": 1819,
          "module": "riscv_peripherals",
          "signal_or_register": "acct_ctrl_i peripheral gates"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 49,
          "line_end": 49,
          "module": "acct_wrapper",
          "object": "assign acc_ctrl_o = {acct_mem[3*0+2], acct_mem[3*0+1], acct_mem[3*0+0]|{8{we_flag}}};",
          "evidence_type": "source_assignment",
          "description": "Access-control output is derived directly from access-control memory, with one field ORed by we_flag.",
          "supports_claim": "The permission bits used by the rest of the design come from acct_mem."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 84,
          "line_end": 84,
          "module": "acct_wrapper",
          "object": "acct_mem[j] <= 32'hffffffff;",
          "evidence_type": "reset_assignment",
          "description": "On reset, all access-control memory entries are initialized to all ones.",
          "supports_claim": "The design resets access-control policy to all enabled rather than deny-by-default."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 216,
          "line_end": 216,
          "module": "riscv_peripherals",
          "object": "logic [3:0][NB_PERIPHERALS-1:0] acc_ctrl_c;",
          "evidence_type": "source_declaration",
          "description": "Top-level declares privilege-indexed access-control matrix.",
          "supports_claim": "Access control is indexed by privilege level and peripheral."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 222,
          "line_end": 222,
          "module": "riscv_peripherals",
          "object": "assign acc_ctrl_c[i][j] = acc_ctrl[j*4+i] | (j==5 && acc_ctrl[4*4+i]);",
          "evidence_type": "source_assignment",
          "description": "Top-level maps acc_ctrl bits into acc_ctrl_c and includes an additional OR condition for peripheral index 5.",
          "supports_claim": "acct_mem-derived bits directly become privilege/peripheral enable bits."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1536,
          "line_end": 1819,
          "module": "riscv_peripherals",
          "object": ".acct_ctrl_i ( acc_ctrl_c[priv_lvl_i][4] ), .acct_ctrl_i ( acc_ctrl_c[priv_lvl_i][5] ), .acct_ctrl_i ( acc_ctrl_c[priv_lvl_i][6] ), .acct_ctrl_i ( acc_ctrl_c[priv_lvl_i][9] )",
          "evidence_type": "integration_wiring",
          "description": "Examples of peripheral access gates use acc_ctrl_c indexed by priv_lvl_i, including HMAC, PKT, ACCT, and REGLK.",
          "supports_claim": "Peripheral access is enabled when the corresponding acc_ctrl_c bit is high."
        }
      ],
      "reasoning_summary": "The wrappers use acct_ctrl_i as an access enable. Because acct_mem resets to 32'hffffffff and acc_ctrl_o is derived directly from acct_mem, all privilege/peripheral access bits are initially enabled. The top-level wires these bits into many peripheral wrappers using acc_ctrl_c[priv_lvl_i][...]. Therefore the design appears to grant broad peripheral access immediately after reset unless trusted software reprograms ACCT before any untrusted access occurs. This is a fail-open permission policy.",
      "security_impact": "Lower-privilege or early-boot code may access security-sensitive peripherals such as HMAC, PKT/fuse interface, ACCT, REGLK, and other gated cryptographic/control blocks before policy is configured. This can lead to unauthorized reads/writes, privilege escalation through policy modification, and exposure or tampering of sensitive configuration.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The source scope does not show boot ROM/firmware sequencing, external NoC filters, or whether any other access-control layer blocks low-privilege accesses before ACCT is configured.",
      "recommended_follow_up": [
        "Reset access-control registers to a deny-by-default value for all nonessential peripherals and privilege levels.",
        "Allow only trusted boot/secure mode to program ACCT registers after reset.",
        "Add explicit hardware privilege checks for ACCT programming rather than relying solely on software sequencing.",
        "Verify boot sequence formally or by review to ensure no untrusted agent can access peripherals before ACCT is configured."
      ]
    },
    {
      "finding_id": "PERM-002",
      "status": "confirmed_finding",
      "summary": "The permission-control blocks ACCT and REGLK are themselves gated by mutable access-control bits that reset enabled.",
      "vulnerability_category": "Mutable self-protection / access-control bypass",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 80,
          "line_end": 80,
          "module": "acct_wrapper",
          "signal_or_register": "en"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1729,
          "line_end": 1730,
          "module": "riscv_peripherals",
          "signal_or_register": "i_acct_wrapper.acct_ctrl_i / acc_ctrl_o"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1817,
          "line_end": 1819,
          "module": "riscv_peripherals",
          "signal_or_register": "i_reglk_wrapper.acct_ctrl_i / reglk_ctrl_o"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 88,
          "line_end": 99,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_mem"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 80,
          "line_end": 80,
          "module": "acct_wrapper",
          "object": "assign en = en_acct && acct_ctrl_i;",
          "evidence_type": "source_assignment",
          "description": "ACCT wrapper enables its internal register interface only with acct_ctrl_i and AXI-lite enable.",
          "supports_claim": "Access to the access-control control block depends on an access-control bit."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1729,
          "line_end": 1730,
          "module": "riscv_peripherals",
          "object": ".acct_ctrl_i ( acc_ctrl_c[priv_lvl_i][6] ), .acc_ctrl_o ( acc_ctrl )",
          "evidence_type": "integration_wiring",
          "description": "ACCT top-level instance uses acc_ctrl_c[priv_lvl_i][6] to gate access to ACCT itself and emits acc_ctrl used globally.",
          "supports_claim": "The access-control block is itself protected by a bit that defaults enabled under PERM-001."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1817,
          "line_end": 1819,
          "module": "riscv_peripherals",
          "object": ".reglk_ctrl_o ( reglk_ctrl ), .acct_ctrl_i ( acc_ctrl_c[priv_lvl_i][9] )",
          "evidence_type": "integration_wiring",
          "description": "REGLK top-level instance emits reglk_ctrl and is gated by acc_ctrl_c[priv_lvl_i][9].",
          "supports_claim": "The register-lock block is itself protected by a bit that defaults enabled under PERM-001."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 88,
          "line_end": 99,
          "module": "reglk_wrapper",
          "object": "else if(en && we) case(address[7:3]) ... reglk_mem[...] <= ... wdata;",
          "evidence_type": "write_logic",
          "description": "REGLK accepts writes to lock registers when en && we, subject only to current lock bits.",
          "supports_claim": "If access is enabled, software can update lock settings."
        }
      ],
      "reasoning_summary": "ACCT and REGLK are control-plane blocks for permissions and locks, but the top-level protects them using the same acc_ctrl_c matrix that resets permissive. This means the mechanism for configuring permissions and locks may be available to all privilege levels after reset. Since ACCT writes can alter access permissions and REGLK writes can alter lock policy, an untrusted requester may be able to grant itself access or prevent later lockdown.",
      "security_impact": "An attacker that can issue memory-mapped accesses while policy is permissive may rewrite access-control registers or register-lock registers, gaining persistent access to restricted peripherals and undermining the entire permission system.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The scope does not include all external interconnect filters or boot sequencing; such mechanisms could reduce exploitability, but no immutable hardware restriction for ACCT/REGLK was visible in the inspected files.",
      "recommended_follow_up": [
        "Hardwire ACCT and REGLK access to secure/trusted privilege only, independent of mutable ACCT policy.",
        "Separate policy-control permissions from ordinary peripheral permissions.",
        "Make ACCT/REGLK write access dependent on immutable lifecycle/boot state or hardware root-of-trust authorization.",
        "Add assertions that nonsecure privilege levels cannot write ACCT/REGLK at any time."
      ]
    },
    {
      "finding_id": "PERM-003",
      "status": "potential_warning",
      "summary": "Register-lock state resets unlocked and can be cleared through jtag_unlock, disabling lock protections.",
      "vulnerability_category": "Debug unlock / insecure lock reset default",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 27,
          "line_end": 27,
          "module": "reglk_wrapper",
          "signal_or_register": "jtag_unlock"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 80,
          "line_end": 85,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_mem"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 48,
          "line_end": 48,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_ctrl_o"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac_wrapper.sv",
          "line_start": 165,
          "line_end": 179,
          "module": "hmac_wrapper",
          "signal_or_register": "key0"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 27,
          "line_end": 27,
          "module": "reglk_wrapper",
          "object": "input logic jtag_unlock;",
          "evidence_type": "source_declaration",
          "description": "REGLK wrapper has a jtag_unlock input.",
          "supports_claim": "A debug/JTAG-related signal participates in lock reset behavior."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 80,
          "line_end": 85,
          "module": "reglk_wrapper",
          "object": "if(~(rst_ni && ~jtag_unlock && ~rst_9)) begin for (j=0; j < 6; j=j+1) begin reglk_mem[j] <= 'h0; end end",
          "evidence_type": "reset_assignment",
          "description": "REGLK reset condition includes jtag_unlock and clears all lock registers to zero.",
          "supports_claim": "Asserting jtag_unlock forces the reset branch and clears locks; normal reset also initializes all locks to zero."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 48,
          "line_end": 48,
          "module": "reglk_wrapper",
          "object": "assign reglk_ctrl_o = {reglk_mem[5], reglk_mem[4], reglk_mem[3], reglk_mem[2], reglk_mem[1], reglk_mem[0]};",
          "evidence_type": "source_assignment",
          "description": "Lock bits are exported directly from reglk_mem to other peripherals.",
          "supports_claim": "Clearing reglk_mem clears the lock controls consumed by peripherals."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/hmac/hmac_wrapper.sv",
          "line_start": 165,
          "line_end": 179,
          "module": "hmac_wrapper",
          "object": "key0[7] <= reglk_ctrl_i[5] ? key0[7] : wdata; ... key0[0] <= reglk_ctrl_i[5] ? key0[0] : wdata;",
          "evidence_type": "write_logic",
          "description": "HMAC key registers are writable whenever reglk_ctrl_i[5] is not set.",
          "supports_claim": "A cleared lock bit permits modification of sensitive HMAC key registers."
        }
      ],
      "reasoning_summary": "The REGLK lock memory resets to zero, so lock protections start disabled. Additionally, because jtag_unlock is part of the reset condition as ~(rst_ni && ~jtag_unlock && ~rst_9), asserting jtag_unlock clears reglk_mem to zero. Since reglk_ctrl_o is a direct concatenation of reglk_mem and other blocks use these bits to block writes/reads, clearing them disables protections such as HMAC key write lock. If jtag_unlock is not strictly authenticated and lifecycle-gated, this is a direct lock bypass.",
      "security_impact": "An attacker with access to the debug unlock path, or code executing before locks are configured, may modify sensitive registers such as cryptographic keys or policy registers. This can compromise confidentiality and integrity of cryptographic operations and system configuration.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The source scope does not show how jtag_unlock is generated or protected. If it is only available in a secure manufacturing lifecycle state, exploitability may be reduced. However, the clearing behavior is visible and security-sensitive.",
      "recommended_follow_up": [
        "Initialize security-critical lock bits to locked-by-default where feasible.",
        "Do not allow jtag_unlock to clear production security locks unless authenticated and lifecycle-authorized.",
        "Separate debug unlock behavior from runtime security lock reset, and make it one-way or fuse/lifecycle controlled.",
        "Add verification that lock bits cannot be cleared in production mode after being set."
      ]
    },
    {
      "finding_id": "PERM-004",
      "status": "potential_warning",
      "summary": "PKT/fuse-derived values are readable by default when access-control and register-lock protections are unset after reset.",
      "vulnerability_category": "Sensitive data exposure due to default-unlocked permissions",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 87,
          "line_end": 97,
          "module": "pkt_wrapper",
          "signal_or_register": "rdata / pkey_loc / fuse_rdata_i"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1627,
          "line_end": 1627,
          "module": "riscv_peripherals",
          "signal_or_register": "i_pkt_wrapper.acct_ctrl_i"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 80,
          "line_end": 85,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_mem"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 87,
          "line_end": 97,
          "module": "pkt_wrapper",
          "object": "2: rdata = reglk_ctrl_i[4] ? 'b0 : pkey_loc[63:32]; 3: rdata = reglk_ctrl_i[5] ? 'b0 : pkey_loc[31:0]; 4: rdata = reglk_ctrl_i[6] ? 'b0 : fuse_rdata_i;",
          "evidence_type": "read_logic",
          "description": "PKT read path returns pkey_loc and fuse_rdata_i when corresponding register-lock bits are not set.",
          "supports_claim": "Sensitive-looking fuse/key-location values are exposed unless lock bits are set."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1627,
          "line_end": 1627,
          "module": "riscv_peripherals",
          "object": ".acct_ctrl_i ( acc_ctrl_c[priv_lvl_i][5] )",
          "evidence_type": "integration_wiring",
          "description": "PKT top-level instance is gated by acc_ctrl_c[priv_lvl_i][5].",
          "supports_claim": "PKT access depends on access-control bit 5, which resets enabled under PERM-001."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 80,
          "line_end": 85,
          "module": "reglk_wrapper",
          "object": "reglk_mem[j] <= 'h0;",
          "evidence_type": "reset_assignment",
          "description": "Register-lock bits reset to zero, so reglk_ctrl_i[4], [5], and [6] are initially unset unless configured later.",
          "supports_claim": "The PKT read-hiding lock bits are disabled by default."
        }
      ],
      "reasoning_summary": "PKT exposes pkey_loc and fuse_rdata_i through reads when reglk_ctrl_i bits 4, 5, and 6 are zero. REGLK resets all lock bits to zero, and PKT access is enabled by acc_ctrl_c[priv_lvl_i][5], which is default-enabled due to ACCT reset behavior. Thus, after reset and before secure configuration, PKT/fuse-derived values may be readable by unauthorized privilege levels.",
      "security_impact": "Unauthorized software may read fuse-backed data, public-key location data, device identity, lifecycle configuration, or other sensitive values exposed via the PKT interface. Depending on fuse contents, this could aid key extraction, device cloning, or bypass of secure boot policy.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The exact sensitivity of pkey_loc and fuse_rdata_i is not shown in the provided files, and external filters or boot-time programming may restrict practical access. The visible RTL nevertheless defaults the relevant protections to open.",
      "recommended_follow_up": [
        "Default-lock PKT/fuse readout registers until trusted firmware explicitly enables access.",
        "Treat fuse and key-location read permissions as immutable or secure-only controls.",
        "Avoid returning fuse_rdata_i as default rdata for unspecified read cases unless explicitly authorized.",
        "Document and verify which privilege levels may read pkey_loc and fuse_rdata_i."
      ]
    },
    {
      "finding_id": "PERM-005",
      "status": "potential_warning",
      "summary": "Suspicious REGLK locked-write assignment may corrupt reglk_mem[2] by copying reglk_mem[3].",
      "vulnerability_category": "Register-lock policy corruption / implementation bug",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 93,
          "line_end": 93,
          "module": "reglk_wrapper",
          "signal_or_register": "reglk_mem[2]"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 93,
          "line_end": 93,
          "module": "reglk_wrapper",
          "object": "reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[3] : wdata;",
          "evidence_type": "write_logic_anomaly",
          "description": "Locked write to reglk_mem[2] preserves reglk_mem[3] rather than reglk_mem[2], unlike surrounding assignments.",
          "supports_claim": "This appears inconsistent with preserve-on-lock behavior and may corrupt lock policy."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/reglk/reglk_wrapper.sv",
          "line_start": 48,
          "line_end": 48,
          "module": "reglk_wrapper",
          "object": "assign reglk_ctrl_o = {reglk_mem[5], reglk_mem[4], reglk_mem[3], reglk_mem[2], reglk_mem[1], reglk_mem[0]};",
          "evidence_type": "source_assignment",
          "description": "The exported lock control vector includes reglk_mem[2].",
          "supports_claim": "Corruption of reglk_mem[2] affects exported lock controls."
        }
      ],
      "reasoning_summary": "The write logic for reglk_mem[2] uses reglk_mem[3] as the retained value when locked. Surrounding cases retain their own register when locked. If this is not intentional, a write attempt while locked can overwrite reglk_mem[2] with reglk_mem[3], corrupting the lock policy and potentially enabling or disabling locks incorrectly.",
      "security_impact": "A malformed locked write could corrupt register-lock settings and potentially bypass or unintentionally disable protections controlled by reglk_mem[2]. The exact affected peripherals depend on the bit mapping not fully visible in scope.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The exact mapping of reglk_mem[2] bits to peripherals/registers is not provided, so the security impact cannot be fully determined from visible source alone.",
      "recommended_follow_up": [
        "Confirm whether reglk_mem[2] locked-write behavior is intentional.",
        "If not intentional, change preserve path to reglk_mem[2].",
        "Review all lock-register write paths for copy/paste errors.",
        "Add assertions that locked writes do not alter the addressed lock register."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The inspected source view omits several system-level elements that affect exploitability: boot ROM/firmware ordering, external NoC/interconnect filters, lifecycle/debug authentication, generation of priv_lvl_i, definitions of axi_lite_interface and pkt internals, and the contents/sensitivity of fuse data. Findings are based only on visible RTL evidence under the provided input scope."
}