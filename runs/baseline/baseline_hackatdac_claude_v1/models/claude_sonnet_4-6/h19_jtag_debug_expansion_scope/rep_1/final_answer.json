{
  "analysis_summary": "The RTL files under the input scope implement a RISC-V (Ariane/CVA6) SoC with a JTAG debug module. The scope covers: the JTAG DMI interface (dmi_jtag.sv, dmi_jtag_tap.sv, dmi_cdc.sv), debug CSRs (dm_csrs.sv, dm_pkg.sv, dm_top.sv), the CSR register file (csr_regfile.sv), a key-storage ROM (rom2.sv), and peripheral/testbench wrappers. Three distinct permission-related vulnerabilities were identified:\n\n1. **JTAG privilege escalation via combinatorial `pass_chk`**: The password-check signal `pass_chk` in `dmi_jtag.sv` is declared as a plain `logic` wire driven combinatorially inside an `always_comb` block. It is never registered. When `DTM_PASS` is submitted, `pass_chk` is set to `1'b1` within the same combinatorial evaluation, but because it has no flip-flop backing it, the value is immediately lost after the `always_comb` block completes — the authentication result does not persist across clock cycles. Furthermore, `umode_o` (which elevates the core to machine-mode privilege) is driven directly from the transient `pass_chk` value in the same combinatorial block, creating a glitch-width elevation window. The write path (DTM_WRITE) is not gated by `pass_chk` at all, allowing debug writes without any password authentication.\n\n2. **JTAG write access entirely bypasses authentication**: Examination of the `Idle` state FSM in `dmi_jtag.sv` shows that `DTM_WRITE` operations proceed unconditionally (no `pass_chk` guard), while only `DTM_READ` is gated on `pass_chk == 1'b1`. This means an attacker can freely write to any debug module register (program buffer, abstract commands, system bus address/data, dmcontrol — including `ndmreset` and `haltreq`) without ever submitting a valid password.\n\n3. **Privilege-check bypass for CSR_MEPC**: In `csr_regfile.sv` line 854, the standard privilege-level check that raises an `ILLEGAL_INSTR` exception when a CSR is accessed below the required privilege level contains an extra condition `&& !(csr_addr.address==riscv::CSR_MEPC)`. This unconditionally exempts the machine-mode EPC register (`MEPC`, privilege level M) from the privilege check, allowing software running at supervisor or user privilege to read/write MEPC without triggering an exception.\n\n4. **rom2 secure register is software-writable**: In `rom2.sv`, the \"secure\" fuse registers holding JTAG keys and access-control tables can be written via the AXI bus (`we_i` path), and this write path is not restricted by privilege or lock logic in the RTL. Any bus master able to address the ROM2 peripheral can overwrite the JTAG key, invalidating the password mechanism entirely.",
  "findings": [
    {
      "finding_id": "FIND-001",
      "status": "confirmed_finding",
      "summary": "JTAG password check (`pass_chk`) is a combinatorial wire — authentication result does not persist, and the umode privilege elevation is transient/glitchy",
      "vulnerability_category": "Authentication Bypass / Privilege Escalation",
      "affected_locations": [
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 79,
          "line_end": 79,
          "module": "dmi_jtag",
          "signal_or_register": "pass_chk"
        },
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 93,
          "line_end": 184,
          "module": "dmi_jtag",
          "signal_or_register": "pass_chk, umode_o"
        },
        {
          "file": "src/csr_regfile.sv",
          "line_start": 938,
          "line_end": 938,
          "module": "csr_regfile",
          "signal_or_register": "priv_lvl_o, umode_i"
        }
      ],
      "evidence": [
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 79,
          "line_end": 79,
          "module": "dmi_jtag",
          "object": "pass_chk",
          "evidence_type": "signal_declaration",
          "description": "`pass_chk` is declared as `logic pass_chk;` — a plain combinatorial wire, not a flip-flop register. It has no `always_ff` driver and is not included in the sequential reset block at lines 212-226.",
          "supports_claim": "Authentication state is not stored across clock cycles."
        },
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 114,
          "line_end": 120,
          "module": "dmi_jtag",
          "object": "DTM_PASS handler",
          "evidence_type": "control_flow",
          "description": "Inside the `always_comb` block, when `DTM_PASS` is received, `pass_chk` is set to `1'b1` only for the duration of that combinatorial evaluation, then lost. The FSM immediately returns to `Idle` (`state_d = Idle`). No registered version of `pass_chk` is updated.",
          "supports_claim": "The password check result evaporates after the combinatorial block completes; any subsequent READ will see `pass_chk == 0`."
        },
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 177,
          "line_end": 182,
          "module": "dmi_jtag",
          "object": "umode_o assignment",
          "evidence_type": "control_flow",
          "description": "`umode_o` is driven combinatorially from the transient `pass_chk` in the same `always_comb` block. When `pass_chk` is momentarily `1`, `umode_o` pulses high, causing `priv_lvl_o` in `csr_regfile` to transiently become `PRIV_LVL_M`.",
          "supports_claim": "Machine-mode privilege elevation is glitch-width only; or, if the combinatorial pulse is wide enough to be latched downstream, it could be exploited."
        },
        {
          "file": "src/csr_regfile.sv",
          "line_start": 938,
          "line_end": 938,
          "module": "csr_regfile",
          "object": "priv_lvl_o",
          "evidence_type": "signal_assignment",
          "description": "`assign priv_lvl_o = (debug_mode_q || umode_i) ? riscv::PRIV_LVL_M : priv_lvl_q;` — `umode_i` (connected to `umode_o` from `dmi_jtag`) can override the actual privilege level to machine mode whenever the JTAG signal is high.",
          "supports_claim": "If `umode_o` were ever reliably held high, it unconditionally forces machine-mode privilege, bypassing the RISC-V privilege hierarchy."
        }
      ],
      "reasoning_summary": "`pass_chk` is a combinatorial `logic` signal (line 79), set inside an `always_comb` block (lines 93-184). There is no `always_ff` that captures `pass_chk` into a flip-flop. The JTAG authentication scheme requires the password submitted via `DTM_PASS` to be remembered so that subsequent `DTM_READ` operations can be conditionally allowed. Because `pass_chk` is purely combinatorial, every time the `always_comb` block re-evaluates (i.e., every TCK cycle), `pass_chk` reverts to `0` unless the `DTM_PASS` condition is simultaneously true. This means the authentication check effectively never persists — no session is established. The `umode_o` signal, which elevates the processor to machine mode (PRIV_LVL_M) via `csr_regfile`, is driven by this same transient signal, creating a design that either never enables elevated mode or produces a glitch-width enable. The design intent (locked read access via JTAG password) is broken.",
      "security_impact": "The JTAG debug interface's read-access authentication is effectively non-functional. An attacker with physical JTAG access can trivially bypass the password gate: since `pass_chk` is never persistently set, they simply need to simultaneously assert `DTM_PASS` with the correct or incorrect password alongside a `DTM_READ` within the same `always_comb` evaluation. Additionally, the transient pulse on `umode_o` could be exploitable for a glitch-based privilege escalation, forcing machine-mode on the CSR file for one combinatorial window.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The exact synthesis behavior of the unregistered `pass_chk` may differ across tools (some may infer latches). The downstream impact on `priv_lvl_o` depends on clock-domain crossing details. The `serpent_peripherals.sv` instantiation of `dmi_jtag` does not connect `umode_o` or `jtag_key`, suggesting this vulnerability path is testbench/FPGA-specific.",
      "recommended_follow_up": [
        "Change `pass_chk` from `logic` to a registered flip-flop driven from `always_ff` clocked on `tck_i`, with reset on `trst_ni`.",
        "Ensure `umode_o` is only driven from a registered, stable signal.",
        "Gate both DTM_READ and DTM_WRITE behind `pass_chk`."
      ]
    },
    {
      "finding_id": "FIND-002",
      "status": "confirmed_finding",
      "summary": "JTAG DTM_WRITE operations are not gated by the password check (`pass_chk`), allowing unauthenticated debug register writes",
      "vulnerability_category": "Missing Authentication for Critical Function / Privilege Escalation",
      "affected_locations": [
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 110,
          "line_end": 122,
          "module": "dmi_jtag",
          "signal_or_register": "state_d, DTM_WRITE path"
        }
      ],
      "evidence": [
        {
          "file": "src/debug/dmi_jtag.sv",
          "line_start": 110,
          "line_end": 120,
          "module": "dmi_jtag",
          "object": "Idle state FSM",
          "evidence_type": "control_flow",
          "description": "Line 110: `DTM_READ` is conditionally allowed only when `pass_chk == 1'b1`. Line 112-113: `DTM_WRITE` transitions to `Write` state with NO check on `pass_chk`. Any JTAG client can write debug module registers without providing a password.",
          "supports_claim": "Write path to the debug module (progbuf, command, sbaddress, sbdata, dmcontrol) requires no authentication."
        },
        {
          "file": "src/debug/dm_csrs.sv",
          "line_start": 171,
          "line_end": 171,
          "module": "dm_csrs",
          "object": "dmstatus.authenticated",
          "evidence_type": "signal_assignment",
          "description": "`dmstatus.authenticated = 1'b1` is hardwired to 1, indicating the debug module reports itself as always-authenticated regardless of JTAG password state.",
          "supports_claim": "The debug module never enforces authentication at the CSR level — it always presents as authenticated."
        },
        {
          "file": "src/debug/dm_pkg.sv",
          "line_start": 184,
          "line_end": 184,
          "module": "dm (package)",
          "object": "DTM_PASS = 2'h3",
          "evidence_type": "type_definition",
          "description": "`DTM_PASS = 2'h3` is defined as a non-standard op-code extension. `DTM_WRITE = 2'h2` is the standard RISC-V debug write op and is not guarded.",
          "supports_claim": "The password mechanism was added as an extension only for reads; writes remain unprotected."
        }
      ],
      "reasoning_summary": "The design introduces a custom `DTM_PASS` operation (op-code `2'h3`) to authenticate JTAG read access. However, in the FSM `Idle` state, `DTM_WRITE` (op-code `2'h2`) branches unconditionally to the `Write` state without checking `pass_chk`. This means any JTAG user — without knowing or submitting the password — can write to any debug module register including: program buffer (`progbuf`), abstract command register (`Command`), system bus address/data registers, and `dmcontrol` (which can issue `ndmreset` and `haltreq`). The debug module itself (`dm_csrs.sv`) hardwires `dmstatus.authenticated = 1'b1`, meaning it never rejects commands on authentication grounds.",
      "security_impact": "An attacker with JTAG physical access can: (1) load arbitrary code into the program buffer and execute it on halted harts; (2) halt arbitrary harts; (3) trigger a non-debug-module reset; (4) write arbitrary data to any memory address via the system bus access (SBA) module — all without providing the JTAG password. This completely undermines the debug access-control intent.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "No additional access-control layer between the JTAG interface and `dm_csrs` was found in the inspected files. The `serpent_peripherals.sv` version of `dmi_jtag` lacks `jtag_key` and `umode_o` ports entirely, meaning the password mechanism is absent there.",
      "recommended_follow_up": [
        "Add `pass_chk` guard to the DTM_WRITE branch in the FSM Idle state.",
        "Remove the hardwired `dmstatus.authenticated = 1'b1` and make it conditional on actual authentication state.",
        "Ensure the registered (flip-flop) version of `pass_chk` is used for all gating."
      ]
    },
    {
      "finding_id": "FIND-003",
      "status": "confirmed_finding",
      "summary": "CSR privilege check unconditionally exempts `MEPC` (machine EPC) from the privilege-level enforcement, allowing lower-privilege software to read/write a machine-mode CSR",
      "vulnerability_category": "Improper Privilege Check / CSR Access Control Bypass",
      "affected_locations": [
        {
          "file": "src/csr_regfile.sv",
          "line_start": 854,
          "line_end": 854,
          "module": "csr_regfile",
          "signal_or_register": "csr_exception_o, priv_lvl_o, CSR_MEPC"
        }
      ],
      "evidence": [
        {
          "file": "src/csr_regfile.sv",
          "line_start": 853,
          "line_end": 857,
          "module": "csr_regfile",
          "object": "Privilege check block",
          "evidence_type": "control_flow",
          "description": "The commented-out original check (line 853) was: `if ((riscv::priv_lvl_t'(priv_lvl_o & csr_addr.csr_decode.priv_lvl) != csr_addr.csr_decode.priv_lvl))`. The active line 854 adds `&& !(csr_addr.address==riscv::CSR_MEPC)`, which suppresses the exception for `MEPC` regardless of current privilege level.",
          "supports_claim": "Supervisor-mode (S) or user-mode (U) code can access MEPC without receiving an ILLEGAL_INSTR exception."
        },
        {
          "file": "src/csr_regfile.sv",
          "line_start": 853,
          "line_end": 853,
          "module": "csr_regfile",
          "object": "Commented original check",
          "evidence_type": "comment",
          "description": "The original privilege check (line 853 comment) had no MEPC carve-out. The modified check (line 854) deliberately introduces the bypass. This is a deliberate RTL modification from the baseline.",
          "supports_claim": "This is an intentional backdoor — the original correct check is preserved as a comment for comparison."
        }
      ],
      "reasoning_summary": "RISC-V privilege specification requires that M-mode CSRs (address bits [11:10] = `11`) raise an `ILLEGAL_INSTR` exception when accessed from S or U mode. `CSR_MEPC` is a machine-mode register (address `0x341`). The modified privilege check at line 854 explicitly exempts `MEPC` from this enforcement. As a result, supervisor or user code can freely read the machine exception return address (leaking the PC of the last M-mode exception) and write it (allowing arbitrary redirection of mret execution flow). This breaks RISC-V isolation between privilege levels.",
      "security_impact": "Supervisor or user-mode software can: (1) read `MEPC` to leak the machine-mode exception PC (information disclosure); (2) write `MEPC` to redirect the next `mret` instruction to an arbitrary address (privilege escalation / control-flow hijack). An attacker in S or U mode could use this to escalate to M-mode by planting a crafted `MEPC` value before triggering a machine-mode return.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The CSR decode logic for `priv_lvl` in `csr_addr.csr_decode.priv_lvl` was not fully traced (it depends on the `riscv` package not included in scope). However, the comment alongside the active line makes the intent of the bypass unambiguous.",
      "recommended_follow_up": [
        "Revert line 854 to the original check (line 853 comment) removing the `&& !(csr_addr.address==riscv::CSR_MEPC)` carve-out.",
        "Audit all other CSR privilege checks for similar exemptions."
      ]
    },
    {
      "finding_id": "FIND-004",
      "status": "confirmed_finding",
      "summary": "The `rom2` secure key register (holding JTAG keys and access-control tables) is software-writable via the AXI bus with no privilege or lock protection",
      "vulnerability_category": "Insecure Key Storage / Missing Write Protection",
      "affected_locations": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 35,
          "line_end": 43,
          "module": "rom2",
          "signal_or_register": "secure_reg, we_i"
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 217,
          "module": "ariane_peripherals",
          "signal_or_register": "jtag_key, access_ctrl_reg"
        }
      ],
      "evidence": [
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 35,
          "line_end": 43,
          "module": "rom2",
          "object": "always_ff write path",
          "evidence_type": "control_flow",
          "description": "Lines 35-43: `if(req_i) begin if (!we_i) ... else begin secure_reg[addr_i[...]] <= wdata_i; end`. The only condition for writing `secure_reg` is `req_i && we_i` — no privilege check, no lock bit, no access-zone restriction. Any AXI master that can address the ROM2 peripheral can overwrite the JTAG key.",
          "supports_claim": "Secure registers holding cryptographic keys are unprotected against software writes."
        },
        {
          "file": "tb/ariane_peripherals.sv",
          "line_start": 215,
          "line_end": 217,
          "module": "ariane_peripherals",
          "object": "jtag_key and access_ctrl_reg assignment",
          "evidence_type": "signal_assignment",
          "description": "`assign jtag_key = key_reg_out[1][31:0];` and `assign access_ctrl_reg[0] = key_reg_out[2][47:0];` — both JTAG key and access-control tables are live outputs of `secure_reg`, which is writable at runtime.",
          "supports_claim": "An attacker can write a known value to the JTAG key register and then authenticate trivially via JTAG DTM_PASS."
        },
        {
          "file": "src/rom2/rom2.sv",
          "line_start": 11,
          "line_end": 17,
          "module": "rom2",
          "object": "ROM comment vs. actual behavior",
          "evidence_type": "comment",
          "description": "The module is named `rom2` and described as 'ROM2: Which have all the keys' and 'Replication of fuse', suggesting it should be read-only fuse storage. Despite this, it implements a full read/write register file with no hardware write-protection.",
          "supports_claim": "Module naming implies read-only fuse semantics, but the implementation allows unrestricted writes — a security design flaw."
        }
      ],
      "reasoning_summary": "The `rom2` module is described as a fuse replica storing cryptographic keys (JTAG authentication key and bus access-control tables). However, the `always_ff` block unconditionally writes to `secure_reg` when `req_i && we_i` is asserted, with no privilege-level enforcement, no lock register, and no one-time-programmable (OTP) semantics. The AXI-to-memory bridge (`axi2mem`) connected to this peripheral exposes the write path to any AXI bus master. An attacker who can execute code (even at S/U privilege given FIND-003) can overwrite the JTAG key to a known value, then authenticate via JTAG DTM_PASS with that value, fully defeating the authentication scheme.",
      "security_impact": "An attacker who can write to the ROM2 peripheral address space can: (1) overwrite the JTAG authentication key to a known value and authenticate via JTAG; (2) overwrite access-control tables for bus masters, potentially expanding permissions for malicious peripherals. Combined with FIND-003, this can be exploited from supervisor or user mode without physical JTAG access.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "The AXI address map for the ROM2 peripheral and the bus access-control enforcement for that slave port are not fully visible in the provided scope. It is possible (but not evident from the RTL) that the interconnect restricts which bus masters can reach ROM2.",
      "recommended_follow_up": [
        "Add a hardware lock bit that, once set (e.g., after boot), prevents further writes to `secure_reg`.",
        "Restrict AXI write access to ROM2 to trusted machine-mode agents only via bus access-control logic.",
        "Consider making the JTAG key truly read-only by removing the `we_i` write path after initialization."
      ]
    }
  ],
  "no_finding_reason": "N/A — multiple confirmed findings were identified.",
  "global_uncertainty": "The analysis is based solely on the RTL files in scope. Some referenced packages (e.g., `ariane_pkg`, `riscv` package for CSR address decode) and the AXI interconnect/address-decode logic are not in scope and could not be inspected. The `serpent_peripherals.sv` instantiation of `dmi_jtag` omits the `jtag_key` and `umode_o` ports, suggesting FIND-001/002 may only be present in the testbench/FPGA flow. Full exploitability of FIND-003 depends on the CSR address decode for `priv_lvl` bits in `csr_addr.csr_decode.priv_lvl`, which was not visible. No synthesis or simulation was performed to confirm gate-level behavior of the combinatorial `pass_chk`."
}