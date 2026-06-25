{
  "analysis_summary": "Inspected the visible RTL/source evidence under the provided scope, focusing on permission/access-control paths for fuse memory, PKT, RNG, RSA, and the subsystem integration in riscv_peripherals.sv. The strongest confirmed issue is in the PKT/fuse-memory path: a memory-mapped PKT wrapper lets any subject that has PKT peripheral access drive arbitrary fuse_mem address and request signals and read fuse_rdata_i back through an AXI-readable register. This exposes fuse memory contents that include comments indicating secure data, HMAC key material, hashes, RNG polynomials, access-control words, SHA/AES keys. There are also potential permission weaknesses around debug-mode bypass of RNG register locks and incomplete evidence for ACCT/REGLK implementation because their module sources were not present in the visible scope.",
  "findings": [
    {
      "finding_id": "FINDING-001",
      "status": "confirmed_finding",
      "summary": "PKT provides a memory-mapped path to arbitrarily address and read fuse_mem contents containing security-sensitive data.",
      "vulnerability_category": "permission_bypass / improper access control for sensitive fuse memory",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 73,
          "line_end": 107,
          "module": "pkt_wrapper",
          "signal_or_register": "fuse_req_o, fuse_addr_o, fuse_rdata_i, rdata"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 10,
          "line_end": 135,
          "module": "fuse_mem",
          "signal_or_register": "req_i, addr_i, rdata_o, mem"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1618,
          "line_end": 1708,
          "module": "riscv_peripherals",
          "signal_or_register": "i_pkt_wrapper, i_fuse_mem, fuse_req, fuse_addr, fuse_rdata"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 68,
          "line_end": 85,
          "module": "pkt_wrapper",
          "object": "en, fuse_req_o, fuse_addr_o",
          "evidence_type": "source",
          "description": "The PKT wrapper gates general bus enable only with acct_ctrl_i, then on writes exposes fuse_req_o and fuse_addr_o as writable AXI-mapped state.",
          "supports_claim": "A requester with PKT access can assert fuse_req_o and choose fuse_addr_o via memory-mapped writes."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 91,
          "line_end": 107,
          "module": "pkt_wrapper",
          "object": "rdata, fuse_rdata_i",
          "evidence_type": "source",
          "description": "The PKT wrapper read side returns fuse_rdata_i directly at address selector 4 when reglk_ctrl_i[6] is not set; it also initializes rdata to fuse_rdata_i before the case.",
          "supports_claim": "Fuse memory read data is exposed through the PKT AXI-readable register map, with only a register-lock bit masking the explicit address-4 read path."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 1,
          "line_end": 135,
          "module": "fuse_mem",
          "object": "mem, addr_q, rdata_o",
          "evidence_type": "source",
          "description": "The fuse_mem module documents that it has secure data, accepts req_i/addr_i, latches an address, and returns mem[addr_q] on rdata_o for in-range addresses.",
          "supports_claim": "Arbitrary fuse address selection can disclose entries from the fuse memory array."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/fuse_mem/fuse_mem.sv",
          "line_start": 17,
          "line_end": 122,
          "module": "fuse_mem",
          "object": "mem",
          "evidence_type": "source",
          "description": "The fuse memory contents include comments and constants for HMAC key/hash material, access-control values, SHA/AES keys, RNG polynomials, and JTAG hash material.",
          "supports_claim": "The exposed memory contains security-sensitive data and permission policy values."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1618,
          "line_end": 1708,
          "module": "riscv_peripherals",
          "object": "i_pkt_wrapper, i_fuse_mem, fuse_req, fuse_addr, fuse_rdata",
          "evidence_type": "source",
          "description": "Top-level integration wires PKT wrapper fuse_req_o/fuse_addr_o/fuse_rdata_i directly to the shared fuse_mem instance, whose rdata_o returns fuse_rdata.",
          "supports_claim": "The vulnerable PKT register interface is connected to the actual fuse memory read port in the subsystem."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 215,
          "line_end": 1628,
          "module": "riscv_peripherals",
          "object": "acc_ctrl_c, acct_ctrl_i",
          "evidence_type": "source",
          "description": "Access control into PKT is privilege-indexed acc_ctrl_c[priv_lvl_i][5], but no per-fuse-address authorization is visible in the PKT/fuse path.",
          "supports_claim": "The visible permission check controls peripheral access broadly, not whether a requester may read specific secure fuse rows."
        }
      ],
      "reasoning_summary": "The top-level connects a memory-mapped PKT peripheral to fuse_mem. Inside pkt_wrapper, if en_acct and acct_ctrl_i are true, software can write fuse_req_o and fuse_addr_o, then read fuse_rdata_i through the PKT register map. fuse_mem uses req_i/addr_i to select mem[addr_q] and returns the selected word. The fuse array is explicitly described as holding secure data and includes key material and access-control values. Therefore, any agent granted PKT access can use PKT as a fuse-read oracle unless reglk_ctrl_i[6] happens to mask the explicit read register; the visible logic does not show per-address fuse permissions or enforcement that only non-sensitive rows are readable. The default rdata assignment to fuse_rdata_i further increases concern, though the case/default behavior may mask some addresses depending on address decoding.",
      "security_impact": "Unauthorized disclosure of fuse-resident secrets and policy data is possible for any requester that can access the PKT peripheral. Exposed entries include HMAC key/hash material, AES/SHA key constants, JTAG hash material, RNG configuration, and access-control words, potentially enabling key extraction, bypass of authentication/debug protections, weakening of cryptographic functions, or reconnaissance to defeat permission settings.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The actual reset/default values and mutability of acc_ctrl and reglk_ctrl are not visible because acct_wrapper and reglk_wrapper sources were not present in the inspected scope. If system policy permanently denies PKT access to all untrusted privilege levels and permanently sets reglk_ctrl_i[6], exploitability would be reduced; however, the visible RTL still implements the unsafe read path once PKT access is available.",
      "recommended_follow_up": [
        "Verify intended policy for PKT fuse reads: if PKT should only translate public key locations, remove direct fuse_rdata_i readback or restrict it to non-sensitive indices.",
        "Add per-fuse-row permission checks or a whitelist of readable fuse addresses before asserting fuse_req_o or returning fuse_rdata_i.",
        "Ensure reglk_ctrl_i[6] is locked by immutable boot-time policy before untrusted software can access PKT; audit the missing reglk_wrapper implementation.",
        "Consider separating key/secret fuse storage from software-readable fuse-index metadata."
      ]
    },
    {
      "finding_id": "FINDING-002",
      "status": "potential_warning",
      "summary": "RNG debug mode bypasses register-lock permission checks for sensitive RNG reads and writes.",
      "vulnerability_category": "debug/privilege bypass of register-lock permissions",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/rand_num/rng_wrapper.sv",
          "line_start": 123,
          "line_end": 206,
          "module": "rng_wrapper",
          "signal_or_register": "debug_mode_i, reglk_ctrl_i, seed, poly*, seed*_big_o, rand_seg_o, cs_state_o"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 53,
          "line_end": 55,
          "module": "riscv_peripherals",
          "signal_or_register": "debug_mode_i, priv_lvl_i"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/rand_num/rng_wrapper.sv",
          "line_start": 123,
          "line_end": 141,
          "module": "rng_wrapper",
          "object": "debug_mode_i, reglk_ctrl_i[5], poly128, poly64, poly32_big, poly16_big",
          "evidence_type": "source",
          "description": "RNG write path allows writes to polynomial registers in debug_mode_i regardless of reglk_ctrl_i[5].",
          "supports_claim": "Debug mode bypasses register lock protection for RNG polynomial/configuration writes."
        },
        {
          "file": "piton/design/chip/tile/ariane/src/rand_num/rng_wrapper.sv",
          "line_start": 150,
          "line_end": 206,
          "module": "rng_wrapper",
          "object": "seed, poly*_big, seed*_big_o, rand_seg_o, cs_state_o",
          "evidence_type": "source",
          "description": "RNG read path returns seed and internal/debug signals in debug_mode_i regardless of corresponding register-lock mask bits.",
          "supports_claim": "Debug mode bypasses register-lock masking for sensitive RNG state reads."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 53,
          "line_end": 55,
          "module": "riscv_peripherals",
          "object": "debug_mode_i",
          "evidence_type": "source",
          "description": "Top-level exposes debug_mode_i as an input alongside priv_lvl_i; no visible local qualification in rng_wrapper restricts debug bypass to a trusted/debug-authenticated context beyond this signal.",
          "supports_claim": "The bypass depends on an external debug_mode_i signal; local authorization for use of debug bypass is not visible in the RNG wrapper."
        }
      ],
      "reasoning_summary": "The RNG wrapper intentionally treats debug_mode_i as overriding register-lock controls for both writes and reads. If debug_mode_i can be asserted in contexts where the requester is not fully trusted, locked RNG configuration and internal state can be read or modified despite reglk policy. This is permission-related because a debug-state input bypasses normal register-lock permission checks. The issue is marked potential because the visible evidence does not establish how debug_mode_i is generated or whether it is cryptographically/authentically gated by JTAG unlock or secure debug policy.",
      "security_impact": "If debug_mode_i is reachable by an attacker, RNG seeds, internal state, and polynomial configuration can be disclosed or modified despite lock bits. This can reduce entropy, predict RNG output, or tamper with security mechanisms relying on random numbers.",
      "confidence": "medium",
      "uncertainty_or_missing_evidence": "The source of debug_mode_i and debug authentication policy were not visible. The bypass may be intentional and safe if debug_mode_i is only asserted after robust authentication and disabled in production.",
      "recommended_follow_up": [
        "Trace debug_mode_i generation and confirm it cannot be asserted by unprivileged software or unauthenticated external debug.",
        "Require both authenticated debug authorization and appropriate privilege/access-control state before bypassing reglk_ctrl_i in RNG.",
        "Avoid exposing seed/internal RNG state even in debug builds for production configurations, or make this conditional on a production fuse."
      ]
    },
    {
      "finding_id": "FINDING-003",
      "status": "needs_more_evidence",
      "summary": "Core permission state generators for access-control and register-lock policy are missing from the visible source, preventing verification of their protections.",
      "vulnerability_category": "access-control policy implementation missing evidence",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 215,
          "line_end": 223,
          "module": "riscv_peripherals",
          "signal_or_register": "acc_ctrl, acc_ctrl_c"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1719,
          "line_end": 1730,
          "module": "riscv_peripherals",
          "signal_or_register": "i_acct_wrapper, acc_ctrl_o, acct_ctrl_i"
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1808,
          "line_end": 1823,
          "module": "riscv_peripherals",
          "signal_or_register": "i_reglk_wrapper, reglk_ctrl_o, jtag_unlock"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 215,
          "line_end": 223,
          "module": "riscv_peripherals",
          "object": "acc_ctrl, acc_ctrl_c",
          "evidence_type": "source",
          "description": "Top-level derives privilege/peripheral access bits from acc_ctrl and feeds many wrappers with acc_ctrl_c[priv_lvl_i][peripheral].",
          "supports_claim": "Permission enforcement depends on mutable acc_ctrl values and current priv_lvl_i."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1719,
          "line_end": 1730,
          "module": "riscv_peripherals",
          "object": "i_acct_wrapper",
          "evidence_type": "source",
          "description": "ACCT wrapper is connected to output acc_ctrl and is itself gated by acc_ctrl_c[priv_lvl_i][6].",
          "supports_claim": "The access-control policy appears to be configured by a memory-mapped wrapper, but its internal protections are not visible."
        },
        {
          "file": "piton/design/chip/tile/ariane/openpiton/riscv_peripherals.sv",
          "line_start": 1808,
          "line_end": 1823,
          "module": "riscv_peripherals",
          "object": "i_reglk_wrapper",
          "evidence_type": "source",
          "description": "REGLK wrapper outputs reglk_ctrl and receives jtag_unlock, but implementation is not visible in the source results.",
          "supports_claim": "Register-lock policy depends on a wrapper whose internal authorization and lock semantics cannot be verified from visible files."
        },
        {
          "file": ".",
          "line_start": null,
          "line_end": null,
          "module": "",
          "object": "acct_wrapper/reglk_wrapper definitions",
          "evidence_type": "tool_result",
          "description": "Search for module acct_wrapper and module reglk_wrapper returned no definitions in the visible scope.",
          "supports_claim": "There is missing evidence needed to confirm whether access-control and register-lock configuration are protected."
        }
      ],
      "reasoning_summary": "The subsystem's permission model relies on acc_ctrl and reglk_ctrl, but the modules that generate/control these values are instantiated without visible source definitions. Because many wrappers only gate access using acc_ctrl_c[priv_lvl_i][N] and lock sensitive registers using reglk_ctrl_i bits, any weakness in ACCT/REGLK configurability would undermine the entire permission scheme. This cannot be confirmed from visible code, so it is reported as needing more evidence rather than a confirmed vulnerability.",
      "security_impact": "If ACCT or REGLK registers are writable by untrusted or insufficiently privileged requesters, attackers could grant themselves access to protected peripherals or clear locks protecting keys, fuse reads, RNG state, RSA registers, DMA, and other security-sensitive resources.",
      "confidence": "low",
      "uncertainty_or_missing_evidence": "No source definitions for acct_wrapper or reglk_wrapper were visible, so no definitive claim can be made about their reset values, write permissions, or one-way lock behavior.",
      "recommended_follow_up": [
        "Inspect acct_wrapper and reglk_wrapper implementations when available to verify reset defaults, write permissions, one-way lock semantics, and JTAG/debug unlock behavior.",
        "Confirm acc_ctrl cannot be modified by lower privilege levels to grant themselves peripheral access.",
        "Confirm reglk_ctrl bits are fail-closed on reset and cannot be cleared after being set, except under authenticated secure lifecycle/debug conditions."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "Analysis is limited to the visible files and tool outputs. Several instantiated security-relevant modules, especially acct_wrapper, reglk_wrapper, and other peripheral wrappers, were not present in the visible scope or not fully readable before the tool-step limit. No simulation/formal/lint was run. Conclusions are based only on static RTL evidence shown above."
}