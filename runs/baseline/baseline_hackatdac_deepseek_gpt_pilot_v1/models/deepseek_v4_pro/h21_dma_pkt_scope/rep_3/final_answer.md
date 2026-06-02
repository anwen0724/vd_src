{
  "analysis_summary": "Analyzed five SystemVerilog RTL source files under the hackatdac21 DMA/PKT scope: dma_wrapper.sv, pkt_wrapper.sv, acct_wrapper.sv, reglk_wrapper.sv, and riscv_peripherals.sv. The design implements a register-lock (reglk) and access-control (acct) based permission scheme intended to protect security-critical registers (DMA config, access-control tables, cryptographic keys, fuses). Multiple permission-related vulnerabilities were identified: (1) In acct_wrapper.sv, the write-lock for access-control registers at addresses 3-5 references reglk_ctrl[13] which is always 0 because the input reglk_ctrl_i is only 8 bits wide, permanently disabling write-lock protection on those access-control entries. (2) In dma_wrapper.sv, the reglk_ctrl_i input is completely ignored in the write path, so all DMA registers (start, length, source/dest addresses) are writable regardless of register-lock policy. (3) In reglk_wrapper.sv, a copy-paste bug causes reglk_mem[2] to reload from reglk_mem[3] instead of reglk_mem[2] when write-locked, corrupting the stored lock value. (4) In pkt_wrapper.sv, write operations to fuse control registers (fuse_req, fuse_addr) bypass the register-lock mechanism. (5) In reglk_wrapper.sv, reglk_mem[2] write-lock always references reglk_mem[3] for its locked source, indicating a mismatch. These weaknesses allow an attacker who can access the AXI-lite bus to bypass intended register-lock protections and modify security-sensitive configuration.",
  "findings": [
    {
      "finding_id": "F-01",
      "status": "confirmed_finding",
      "summary": "Access-control write-lock permanently disabled for acct_mem entries 3-5 due to out-of-bounds reglk_ctrl bit index",
      "vulnerability_category": "Permission bypass / Missing register lock protection",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 96,
          "line_end": 100,
          "module": "acct_wrapper",
          "signal_or_register": "acct_mem[03:05], reglk_ctrl[13]"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 26,
          "line_end": 26,
          "module": "acct_wrapper",
          "object": "reglk_ctrl_i",
          "evidence_type": "code",
          "description": "reglk_ctrl_i is declared as 8 bits wide: input logic [7:0] reglk_ctrl_i",
          "supports_claim": "Shows input width is 8 bits, making bit 13 always zero"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 40,
          "line_end": 40,
          "module": "acct_wrapper",
          "object": "reglk_ctrl",
          "evidence_type": "code",
          "description": "Internal signal declared as logic [15:0] reglk_ctrl; but assigned from 8-bit input",
          "supports_claim": "Shows the internal signal is wider than the input"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/acct/acct_wrapper.sv",
          "line_start": 96,
          "line_end": 100,
          "module": "acct_wrapper",
          "object": "acct_mem write logic",
          "evidence_type": "code",
          "description": "acct_mem[03] <= reglk_ctrl[13] ? acct_mem[03] : wdata; (same for [04] and [05]). Since reglk_ctrl[13] is tied to 0 from the 8-bit input, the lock is never engaged.",
          "supports_claim": "Direct evidence that write-lock uses out-of-bounds bit index"
        }
      ],
      "reasoning_summary": "The acct_wrapper module uses a 16-bit internal reglk_ctrl signal but its input is only 8 bits wide. Bits [15:8] are always 0. The write-lock for acct_mem[03], [04], [05] checks reglk_ctrl[13], which is always 0, meaning these access-control registers can always be written regardless of the intended register-lock policy. This allows an attacker to modify access-control permissions for peripherals that are supposed to be locked.",
      "security_impact": "An attacker with AXI-lite bus access can bypass the register-lock mechanism and modify access-control entries 3-5 at will, potentially granting unauthorized access to protected peripherals or resources. This defeats the entire purpose of the register-lock-based access-control hardening.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "None. The width mismatch and out-of-bounds access are clearly visible in the source code. The reglk_ctrl_i is confirmed as [7:0] and the write lock references bit 13.",
      "recommended_follow_up": [
        "Change reglk_ctrl[13] to the correct lock bit within [7:0] range (possibly reglk_ctrl[3] or another appropriate bit) for acct_mem[03:05] write protection",
        "Consider reducing internal reglk_ctrl width to match input or adding bounds checks",
        "Review all reglk_ctrl bit assignments to ensure consistent read/write lock mapping"
      ]
    },
    {
      "finding_id": "F-02",
      "status": "confirmed_finding",
      "summary": "DMA registers completely lack register-lock enforcement in write path",
      "vulnerability_category": "Missing permission check / Register lock bypass",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/dma/dma_wrapper.sv",
          "line_start": 95,
          "line_end": 125,
          "module": "dma_wrapper",
          "signal_or_register": "start_reg, length_reg, source_addr_lsb_reg, source_addr_msb_reg, dest_addr_lsb_reg, dest_addr_msb_reg, done_reg, end_reg"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/dma/dma_wrapper.sv",
          "line_start": 46,
          "line_end": 46,
          "module": "dma_wrapper",
          "object": "reglk_ctrl_i",
          "evidence_type": "code",
          "description": "input logic [7:0] reglk_ctrl_i; // register lock values — declared but never used in write logic",
          "supports_claim": "Shows reglk_ctrl_i is an input but is not referenced in the write path"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/dma/dma_wrapper.sv",
          "line_start": 95,
          "line_end": 125,
          "module": "dma_wrapper",
          "object": "always @(posedge clk_i) write block",
          "evidence_type": "code",
          "description": "Write cases use: start_reg <= wdata; length_reg <= wdata; etc. without any reglk_ctrl_i check. The condition is else if(en && we) with no lock gating.",
          "supports_claim": "Direct evidence that DMA registers are written unconditionally when en && we"
        }
      ],
      "reasoning_summary": "The dma_wrapper accepts a reglk_ctrl_i input for register-lock enforcement but never uses it in the write path. All DMA control registers — including start, length, source address, and destination address — are writable whenever the bus enables and writes. This completely bypasses the intended register-lock security mechanism for DMA, which controls memory transfers and could be used to read/write arbitrary physical memory.",
      "security_impact": "An attacker can configure and launch arbitrary DMA transfers regardless of register-lock policy, enabling unauthorized memory reads, writes, and potential privilege escalation. The DMA engine is a powerful bus master; unrestricted control over it constitutes a severe security vulnerability.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "None. The reglk_ctrl_i input is visibly unused in the write always block; the write conditions only check en && we.",
      "recommended_follow_up": [
        "Add reglk_ctrl_i-based lock checks in the DMA write path for each register",
        "Determine which reglk_ctrl bits should gate each DMA register",
        "Ensure consistency with the reglk_wrapper lock-bit assignment policy"
      ]
    },
    {
      "finding_id": "F-03",
      "status": "confirmed_finding",
      "summary": "Register lock for reglk_mem[2] reloads from wrong source (reglk_mem[3]) when locked",
      "vulnerability_category": "Permission logic error / Register lock integrity violation",
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
          "line_start": 88,
          "line_end": 99,
          "module": "reglk_wrapper",
          "object": "reglk_mem write case statement",
          "evidence_type": "code",
          "description": "Address 0: reglk_mem[0] <= reglk_ctrl[3] ? reglk_mem[0] : wdata; Address 2: reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[3] : wdata; All others correctly reload themselves when locked. Address 2 incorrectly reloads from reglk_mem[3] instead of reglk_mem[2].",
          "supports_claim": "Direct evidence of copy-paste error causing incorrect lock-preservation source"
        }
      ],
      "reasoning_summary": "When reglk_ctrl[1] is asserted (lock enabled), writing to reglk_mem[2] should preserve its current value. Instead, the code loads reglk_mem[3]'s value into reglk_mem[2]. This corrupts the lock state for register index 2 and breaks the integrity of the register-lock mechanism.",
      "security_impact": "If reglk_mem[2] holds lock bits for security-critical peripherals, this bug can cause unintended lock state changes. An attacker who triggers a write to reglk_mem[2] while locked could corrupt the lock bits with values from reglk_mem[3], potentially disabling locks on other peripherals.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "None. The code clearly shows reglk_mem[3] instead of reglk_mem[2] in address case 2.",
      "recommended_follow_up": [
        "Fix the copy-paste error: change reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[3] : wdata; to reglk_mem[2] <= reglk_ctrl[1] ? reglk_mem[2] : wdata;"
      ]
    },
    {
      "finding_id": "F-04",
      "status": "confirmed_finding",
      "summary": "PKT wrapper lacks write-lock protection on fuse control registers",
      "vulnerability_category": "Missing permission check / Register lock bypass",
      "affected_locations": [
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 73,
          "line_end": 84,
          "module": "pkt_wrapper",
          "signal_or_register": "fuse_req_o, fuse_addr_o"
        }
      ],
      "evidence": [
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 73,
          "line_end": 84,
          "module": "pkt_wrapper",
          "object": "fuse_req_o/fuse_addr_o write block",
          "evidence_type": "code",
          "description": "Write path: else if(en && we) case(address[7:3]) 0: fuse_req_o <= wdata[0]; 1: fuse_addr_o <= wdata; — no reglk_ctrl_i check on writes",
          "supports_claim": "Shows writes to fuse control registers bypass register lock"
        },
        {
          "file": "piton/design/chip/tile/ariane/src/pkt/pkt_wrapper.sv",
          "line_start": 13,
          "line_end": 13,
          "module": "pkt_wrapper",
          "object": "reglk_ctrl_i",
          "evidence_type": "code",
          "description": "reglk_ctrl_i is a module input but is only used in the read path (to mask key data at addresses 2-4), never in the write path",
          "supports_claim": "Confirms reglk_ctrl_i is available but unused for write protection"
        }
      ],
      "reasoning_summary": "The pkt_wrapper module implements register-lock reads for key material (pkey_loc) and fuse data (fuse_rdata_i) but does not apply any register-lock check to writes. The fuse_req_o and fuse_addr_o registers control which fuse location is read. An attacker can set the fuse address and trigger a fuse read without any lock enforcement, potentially extracting sensitive data from arbitrary fuse locations.",
      "security_impact": "An attacker can read any fuse location by writing to the unprotected fuse_addr register, potentially extracting cryptographic material or other sensitive stored constants. Combined with the unprotected fuse operation trigger (fuse_req), this exposes the entire fuse storage to unauthorized readout.",
      "confidence": "high",
      "uncertainty_or_missing_evidence": "None. The write path clearly lacks any reglk_ctrl_i check.",
      "recommended_follow_up": [
        "Add reglk_ctrl_i-based lock checks to the write path for fuse_req_o and fuse_addr_o",
        "Determine which reglk_ctrl bit(s) should gate fuse control writes"
      ]
    }
  ],
  "no_finding_reason": "N/A - multiple permission-related vulnerabilities found",
  "global_uncertainty": "The analysis covers only the five wrapper modules within the scope. Dependent modules such as the internal 'dma', 'pkt', and 'axi_lite_interface' were not available for review and may contain additional permission logic or vulnerabilities. The we_flag signal's role in access-control gating at a higher integration level (riscv_peripherals.sv) is partially visible but not fully traced. The exact mapping of reglk_ctrl bits to specific peripherals/registers was inferred from context and may need verification against design documentation."
}