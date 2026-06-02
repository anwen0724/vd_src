# Batch Plan

## Status

Initialized from seed mapping. This is a description-level batch plan, not RTL-confirmed.

## Counts

- official_all_cases: 66
- in_scope: 46
- likely_in_scope: 18
- unclear: 0
- out_of_scope: 2

## Current Batch

Current RTL evidence batch 1:

- #1 / H19-001: CLINT/PLIC access-control connectivity.
- #9 / H19-009: user-mode control incorrectly forces machine privilege.
- #10 / H19-010: AES key exposed through bus-readable registers.
- #11 / H19-011: AES internal intermediate state exposed through bus-readable registers.
- #17 / H19-017: boot ROM write path.
- #20 / H19-020: lower-privilege CSR access via privilege-check exception.
- #24 / H19-024: SATP read not mediated by TVM.
- #25 / H19-025: SATP write not mediated by TVM.
- #45 / H19-045: secure registers exposed through AXI/ROM2 path.

Batch 1 covers access-control mapping, privilege/CSR, virtual-memory control, protected code storage, and secret/internal-state exposure. It intentionally does not start from the full JTAG group because Hack@DAC18 already contains several debug/JTAG cases.

Completed RTL evidence batch 2:

- #5 / H19-005: debug module reports authenticated without implemented authentication.
- #47 / H19-047: JTAG DMI write path is not consistently password guarded.
- #48 / H19-048: JTAG unlock path can force processor privilege output to machine mode.
- #51 / H19-051: JTAG password flag is not reset properly.
- #54 / H19-054: JTAG key is derived from hardcoded ROM2 constant.
- #56 / H19-056: debug control path can drive secondary SoC reset.
- #58 / H19-058: access-control or lock-like security configuration can be reprogrammed after boot.

Completed RTL evidence batch 3:

- #14 / H19-014: AES operation interface is exposed as a crypto oracle.
- #15 / H19-015: AES key is derived from a hardcoded ROM2 constant.
- #41 / H19-041: DRAM region is accessible from lower privilege through SoC access-control configuration.
- #49 / H19-049: JTAG password path is only 32 bits wide.
- #50 / H19-050: debug SBA path can access ROM2/FUSE memory.

## Seed Priority Groups

建议优先进入 RTL evidence 分析的 case：

1. **DMA / memory protection / privilege：** #4, #7, #39, #40, #60
2. **Debug / JTAG authorization：** #5, #46, #47, #48, #49, #50, #51, #52, #53, #54, #55, #56, #57, #59
3. **Register lock / access control：** #6, #58, #62, #63
4. **CSR / privilege / virtual memory：** #9, #20, #24, #25, #26, #34
5. **Address map / AXI / protected resource：** #1, #18, #41, #43, #45
6. **Secret / crypto state residue：** #10, #11, #14, #44, #64, #65

## Next Step

Continue RTL evidence review for the remaining H19 cases. A later batch should cover DMA/register-lock/JTAG cases after the first mixed batch is validated.

## Deferred Cases

All cases remain deferred until a specific RTL evidence batch is selected.
