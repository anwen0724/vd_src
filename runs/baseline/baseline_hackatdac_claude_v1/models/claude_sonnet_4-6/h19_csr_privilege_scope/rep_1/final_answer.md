{
  "analysis_summary": "Analyzed the HackAtDAC 2019 Ariane RISC-V processor CSR (Control and Status Register) subsystem for permission-related security vulnerabilities. Three source files were inspected: include/riscv_pkg.sv (architectural definitions and privilege-level types), src/csr_regfile.sv (CSR register file with read, write, and privilege enforcement logic), and src/ariane.sv (top-level processor module). Two distinct, high-confidence permission-related security vulnerabilities were identified: (1) a hardware-level privilege escalation backdoor introduced via the external input signal `umode_i` that unconditionally forces the reported privilege level to Machine mode when asserted, and (2) an intentional bypass of the privilege check specifically for the Machine-mode Exception PC register (CSR_MEPC), allowing lower-privilege code to read and write this M-mode CSR without raising an illegal instruction exception. Both vulnerabilities are structurally unambiguous and consistent with intentional hardware Trojan insertions typical of the HackAtDAC competition dataset.",
  "findings": [
    {
      "finding_id": "FINDING-001",
      "status": "confirmed_finding",
      "summary": "External input `umode_i`, when asserted, unconditionally forces `priv_lvl_o` to Machine mode (PRIV_LVL_M = 2'b11), creating a hardware privilege-escalation backdoor accessible from outside the processor core.",
      "vulnerability_category": "Privilege Escalation / Hardware Backdoor",
      "affected_locations": [
        {
          "file": "src/csr_regfile.sv",
          "line_start": 938,
          "line_end": 938,
          "module": "csr_regfile",
          "signal_or_register": "priv_lvl_o"
        },
        {
          "file": "src/csr_regfile.sv",
          "line_start": 83,
          "line_end": 83,
          "module": "csr_regfile",
          "signal_or_register": "umode_i"
        },
        {
          "file": "src/ariane.sv",
          "line_start": 51,
          "line_end": 51,
          "module": "ariane",
          "signal_or_register": "umode_i"
        },
        {
          "file": "src/ariane.sv",
          "line_start": 520,
          "line_end": 520,
          "module": "ariane",
          "signal_or_register": "umode_i"
        }
      ],
      "evidence": [
        {
          "file": "src/csr_regfile.sv",
          "line_start": 938,
          "line_end": 938,
          "module": "csr_regfile",
          "object": "priv_lvl_o assignment",
          "evidence_type": "Buggy logic statement",
          "description": "The combinatorial assignment `assign priv_lvl_o = (debug_mode_q || umode_i) ? riscv::PRIV_LVL_M : priv_lvl_q;` bundles the external input `umode_i` together with the internal `debug_mode_q` register in the condition for elevating privilege to M-mode. When `umode_i` is high, `priv_lvl_o` becomes PRIV_LVL_M (2'b11) regardless of the actual architectural privilege state `priv_lvl_q`.",
          "supports_claim": "Directly implements the backdoor: any assertion of the top-level input umode_i silently forces machine-mode privilege."
        },
        {
          "file": "src/ariane.sv",
          "line_start": 51,
          "line_end": 51,
          "module": "ariane",
          "object": "umode_i port declaration",
          "evidence_type": "Port declaration",
          "description": "`input logic umode_i` is declared as a primary input of the top-level `ariane` module with no description, no qualification, and no gating logic. It is passed directly to `csr_regfile` unchanged.",
          "supports_claim": "Confirms umode_i is externally controllable at the SoC/board boundary, making the backdoor accessible from outside the processor."
        },
        {
          "file": "src/ariane.sv",
          "line_start": 520,
          "line_end": 520,
          "module": "ariane",
          "object": "csr_regfile instantiation",
          "evidence_type": "Module instantiation",
          "description": "`.umode_i ( umode_i )` passes the top-level primary input directly into `csr_regfile` without any intermediate logic, buffering, or security gating.",
          "supports_claim": "No filtering or sanitization is applied between the external pin and the privilege-level override logic."
        },
        {
          "file": "src/csr_regfile.sv",
          "line_start": 852,
          "line_end": 863,
          "module": "csr_regfile",
          "object": "Privilege check gate (exception_ctrl always_comb)",
          "evidence_type": "Security-critical dependent logic",
          "description": "The CSR privilege check at lines 852-857 uses `priv_lvl_o` directly: `if ((riscv::priv_lvl_t'(priv_lvl_o & csr_addr.csr_decode.priv_lvl) != csr_addr.csr_decode.priv_lvl) ...)`. When `umode_i` forces `priv_lvl_o = PRIV_LVL_M`, this check passes for all CSR addresses, granting unrestricted CSR access.",
          "supports_claim": "Confirms that spoofing priv_lvl_o via umode_i disables all CSR privilege enforcement downstream."
        },
        {
          "file": "src/csr_regfile.sv",
          "line_start": 948,
          "line_end": 950,
          "module": "csr_regfile",
          "object": "en_translation_o assignment",
          "evidence_type": "Security-critical dependent logic",
          "description": "`assign en_translation_o = (satp_q.mode == 4'h8 && priv_lvl_o != riscv::PRIV_LVL_M) ? 1'b1 : 1'b0;` — When `umode_i` forces `priv_lvl_o = PRIV_LVL_M`, virtual address translation is unconditionally disabled, collapsing all memory isolation.",
          "supports_claim": "Asserting umode_i also silently disables page-table-based memory isolation, compounding the privilege escalation impact."
        },
        {
          "file": "src/csr_regfile.sv",
          "line_start": 689,
          "line_end": 689,
          "module": "csr_regfile",
          "object": "ld_st_priv_lvl_o assignment",
          "evidence_type": "Security-critical dependent logic",
          "description": "`ld_st_priv_lvl_o = (mprv) ? mstatus_q.mpp : priv_lvl_o;` — The load/store privilege level is derived from `priv_lvl_o`, so asserting `umode_i` also elevates memory access privilege for loads and stores to M-mode.",
          "supports_claim": "The backdoor's effect propagates to memory access privilege, not just CSR access."
        },
        {
          "file": "include/riscv_pkg.sv",
          "line_start": 22,
          "line_end": 25,
          "module": "riscv package",
          "object": "priv_lvl_t enum",
          "evidence_type": "Architectural definition",
          "description": "PRIV_LVL_M = 2'b11 is defined as the highest RISC-V privilege level (Machine mode). PRIV_LVL_S = 2'b01 and PRIV_LVL_U = 2'b00 are lower. Forcing priv_lvl_o to PRIV_LVL_M grants unrestricted access to all architectural resources.",
          "supports_claim": "Confirms the magnitude of privilege escalation: the backdoor reaches the absolute highest privilege tier."
        }
      ],
      "reasoning_summary": "The signal `umode_i` is a top-level primary input of the Ariane processor. It is passed without any filtering to `csr_regfile`, where it is OR-ed with the legitimate `debug_mode_q` internal state register in a single combinatorial assignment that sets `priv_lvl_o`. When `umode_i = 1`, the output `priv_lvl_o` is forced to `PRIV_LVL_M` (Machine mode, 2'b11) — the highest RISC-V privilege level — regardless of the actual architectural privilege state held in `priv_lvl_q`. `priv_lvl_o` is consumed by the CSR privilege enforcement gate, the MMU address-translation enable, the load/store privilege level, and trap delegation logic. Asserting `umode_i` therefore simultaneously bypasses all CSR access controls, disables virtual address translation (collapsing process isolation), elevates memory access privilege, and corrupts trap routing. The signal name 'umode' (suggesting user mode) is semantically inverted relative to its actual effect, consistent with an intentional hardware Trojan insertion. The original legitimate use of the ternary condition was only `debug_mode_q`; `umode_i` is the inserted backdoor term.",
      "security_impact": "Full Machine-mode privilege escalation from any lower privilege level. An attacker who can drive `umode_i = 1` at the chip boundary gains: (1) unrestricted read/write access to all M-mode CSRs (mstatus, mepc, mtvec, medeleg, mideleg, mie, mip, mscratch, mcause, mtval, etc.); (2) silent disabling of all virtual address translation, eliminating MMU-based memory isolation between processes and the OS kernel; (3) elevated load/store privilege equivalent to M-mode; (4) ability to redirect machine-mode trap/exception handlers (mtvec) and manipulate interrupt delegation, enabling persistent control of the system.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The external driver of `umode_i` at the board/SoC integration level is not in scope. If `umode_i` is hardwired to logic 0 at integration time, the attack surface is physically reduced; however, the vulnerability exists unconditionally in the RTL as delivered. No additional filtering or gating of `umode_i` was found in any in-scope file.",
      "recommended_follow_up": [
        "Remove `umode_i` from the `priv_lvl_o` assignment entirely; the legitimate debug-mode elevation is correctly handled by `debug_mode_q` alone.",
        "Audit all top-level primary inputs for undocumented or semantically inconsistent privilege-affecting signals.",
        "Ensure `priv_lvl_o` is only derived from the internally maintained `priv_lvl_q` register (and `debug_mode_q` for debug), never from external primary inputs.",
        "Add formal verification assertions: `priv_lvl_o` must equal `priv_lvl_q` whenever `debug_mode_q == 0`."
      ]
    },
    {
      "finding_id": "FINDING-002",
      "status": "confirmed_finding",
      "summary": "The CSR privilege enforcement check unconditionally exempts `CSR_MEPC` (Machine Exception PC, address 0x341) from privilege level verification, allowing Supervisor-mode or User-mode code to read and write this M-mode register without raising an illegal instruction exception.",
      "vulnerability_category": "Insufficient Privilege Enforcement / CSR Access Control Bypass",
      "affected_locations": [
        {
          "file": "src/csr_regfile.sv",
          "line_start": 854,
          "line_end": 854,
          "module": "csr_regfile",
          "signal_or_register": "csr_exception_o"
        }
      ],
      "evidence": [
        {
          "file": "src/csr_regfile.sv",
          "line_start": 853,
          "line_end": 854,
          "module": "csr_regfile",
          "object": "Privilege check conditional expression",
          "evidence_type": "Buggy logic statement",
          "description": "Line 853 (commented out) contains the original, correct check: `if ((riscv::priv_lvl_t'(priv_lvl_o & csr_addr.csr_decode.priv_lvl) != csr_addr.csr_decode.priv_lvl))`. Line 854 (active) appends `&& !(csr_addr.address==riscv::CSR_MEPC)`, which unconditionally suppresses the illegal instruction exception for any access to CSR_MEPC regardless of current privilege level. The commented original is preserved directly above as a structural artifact of the intentional modification.",
          "supports_claim": "The bypass is explicit and targeted: exactly one CSR address (MEPC) is excluded from the otherwise universal privilege check."
        },
        {
          "file": "include/riscv_pkg.sv",
          "line_start": 365,
          "line_end": 365,
          "module": "riscv package",
          "object": "CSR_MEPC address definition",
          "evidence_type": "Architectural definition",
          "description": "`CSR_MEPC = 12'h341`. Bits [11:10] of the CSR address are `11` (binary), which per the RISC-V privileged specification encodes a required privilege level of Machine mode. Any access from S-mode or U-mode should produce an illegal instruction exception. The bypass at line 854 defeats this architectural guarantee.",
          "supports_claim": "Confirms MEPC is architecturally M-mode only; the bypass violates the RISC-V specification privilege requirement."
        },
        {
          "file": "include/riscv_pkg.sv",
          "line_start": 457,
          "line_end": 466,
          "module": "riscv package",
          "object": "csr_addr_t / csr_t definitions",
          "evidence_type": "Architectural definition",
          "description": "`csr_addr_t` struct encodes bits [11:10] as `rw` (read/write attribute) and bits [9:8] as `priv_lvl` (required privilege level). The `csr_t` union exposes this as `csr_decode.priv_lvl`, which is what the privilege check compares against. For CSR_MEPC (0x341 = 0b0011_0100_0001), bits [9:8] = `11` = PRIV_LVL_M.",
          "supports_claim": "The address-based privilege encoding confirms the check at line 854 would correctly reject non-M-mode access to MEPC under the original (commented-out) logic."
        },
        {
          "file": "src/csr_regfile.sv",
          "line_start": 220,
          "line_end": 220,
          "module": "csr_regfile",
          "object": "CSR_MEPC read path",
          "evidence_type": "Supporting logic",
          "description": "In `csr_read_process`, `riscv::CSR_MEPC: csr_rdata = mepc_q;` is listed without any additional privilege guard, meaning the read bypass also applies: an S-mode or U-mode CSRRS/CSRRC/CSRRW instruction targeting 0x341 will successfully read `mepc_q`.",
          "supports_claim": "The bypass applies to both reads and writes of MEPC, not writes only."
        },
        {
          "file": "src/csr_regfile.sv",
          "line_start": 484,
          "line_end": 484,
          "module": "csr_regfile",
          "object": "CSR_MEPC write path",
          "evidence_type": "Supporting logic",
          "description": "In `csr_update`, `riscv::CSR_MEPC: mepc_d = {csr_wdata[63:1], 1'b0};` executes without any additional privilege guard. Combined with the suppressed exception at line 854, lower-privilege writes to MEPC will complete silently.",
          "supports_claim": "Write path to mepc_d is reachable from non-M-mode due to the bypassed exception."
        },
        {
          "file": "src/csr_regfile.sv",
          "line_start": 906,
          "line_end": 910,
          "module": "csr_regfile",
          "object": "epc_o output assignment (priv_output always_comb)",
          "evidence_type": "Security-critical dependent logic",
          "description": "`epc_o = mepc_q;` (line 906) is the default EPC output, used by the frontend to resume execution after MRET. An attacker who writes an arbitrary value to MEPC (via the bypassed access) can redirect the processor's program counter on the next machine-mode trap return to an attacker-controlled address.",
          "supports_claim": "Unauthorized write to MEPC via the bypass can achieve arbitrary control-flow redirection at machine-mode on MRET."
        }
      ],
      "reasoning_summary": "The RISC-V privileged specification encodes the required privilege level for each CSR in bits [9:8] of the 12-bit CSR address. For CSR_MEPC (0x341), these bits are `11` (Machine mode), meaning only M-mode code may access it. The CSR regfile enforces this via a bitwise AND of the current privilege level and the decoded required level in the `exception_ctrl` always_comb block. The original correct check (preserved as a comment on line 853) would raise `ILLEGAL_INSTR` on any S-mode or U-mode access to MEPC. The active check on line 854 appends `&& !(csr_addr.address == riscv::CSR_MEPC)`, which is false when the target CSR is MEPC, causing the entire exception condition to evaluate to false and silently permitting the access. The presence of the original check as a comment immediately above the modified line is strong evidence of intentional modification. MEPC is security-critical because it holds the saved PC for machine-mode trap returns, and unauthorized writes redirect the processor's control flow on MRET to attacker-chosen addresses, achieving arbitrary code execution at M-level.",
      "security_impact": "A process running at Supervisor or User privilege mode can: (1) Read `mepc_q` to leak the saved machine-mode program counter, defeating KASLR or exposing trusted-firmware code layout; (2) Write an arbitrary address to `mepc_q`, causing the processor to jump to an attacker-controlled location upon the next MRET instruction, achieving arbitrary code execution at Machine-mode privilege. This represents a complete machine-mode code execution primitive accessible from unprivileged code.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "Other pipeline stages (decode, commit) are not in scope and could theoretically apply additional filtering, but the CSR regfile is the canonical privilege enforcement boundary per the RISC-V specification. No upstream guards for MEPC were observed in the in-scope files. The bypass is structurally complete and self-contained within the exception_ctrl logic.",
      "recommended_follow_up": [
        "Restore the original privilege check by removing the `&& !(csr_addr.address==riscv::CSR_MEPC)` clause from line 854, reverting to the logic on the commented-out line 853.",
        "Audit all other CSR addresses in the read and write case statements for similar per-address privilege exemptions.",
        "Add formal verification cover properties asserting that any CSR access from S-mode or U-mode targeting address ranges [0x300–0x3FF] always produces csr_exception_o.valid = 1.",
        "Consider adding a second, independent privilege check in the decode/issue stage to provide defense-in-depth against CSR access control bypasses in the regfile."
      ]
    }
  ],
  "no_finding_reason": "",
  "global_uncertainty": "The CSR regfile and top-level ariane module are fully in scope and provide sufficient evidence for both findings. Files not in scope include: ariane_pkg.sv (package parameters such as FP_PRESENT, ZERO_TVAL, ENABLE_CYCLE_COUNT — none affect the identified vulnerabilities), pipeline stage modules (frontend, decode, issue, execute, commit — could theoretically add upstream filtering but CSR regfile is the architectural enforcement authority), and the SoC integration level (external driver of umode_i is unknown, but the RTL vulnerability is unconditional). No additional uncertainty affects the confidence of either finding."
}