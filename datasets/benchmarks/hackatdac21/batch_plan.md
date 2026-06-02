# Batch Plan

## Status

RTL evidence review completed for the current Hack@DAC21 target set. Remaining cases are still description-level candidates unless explicitly marked otherwise in `task_gt.csv`.

## Counts

- official_all_cases: 99
- in_scope: 62
- likely_in_scope: 36
- unclear: 0
- out_of_scope: 1

## Confirmed Case Set

Current confirmed set contains 22 cases:

| Case | Official bug | Status | Reason selected |
|---|---|---|---|
| H21-005 | #5 | `rtl_confirmed` | HMAC access bit can enable PKT access through `acc_ctrl_c` coupling. |
| H21-013 | #13 | `rtl_confirmed` | AES internal state/key/plaintext registers are externally readable through wrapper read logic. |
| H21-031 | #31 | `rtl_confirmed` | DMA programming registers are written without lock mediation. |
| H21-035 | #35 | `rtl_confirmed` | Register-lock memory resets to zero and exports unlocked state. |
| H21-036 | #36 | `rtl_confirmed` | SHA input registers remain readable after hash operation path. |
| H21-039 | #39 | `rtl_confirmed` | AES plaintext registers remain readable after encryption path. |
| H21-042 | #42 | `rtl_confirmed` | Access-control memory resets to all ones/full access. |
| H21-043 | #43 | `rtl_confirmed` | ACCT write map uses ineffective/inconsistent lock indices. |
| H21-047 | #47 | `rtl_confirmed` | AES0 debug-mode masking omits one key path. |
| H21-048 | #48 | `rtl_confirmed` | `jtag_unlock` participates in register-lock reset/clear behavior. |
| H21-049 | #49 | `rtl_confirmed` | `we_flag` can force effective access-control output bits. |
| H21-059 | #59 | `rtl_confirmed` | PKT read/default handling can expose fuse data. |
| H21-060 | #60 | `rtl_confirmed` | AES0 default read behavior can retain key0 value. |
| H21-073 | #73 | `rtl_confirmed` | AES2 access gate depends on reset-open privilege-indexed access-control state. |
| H21-074 | #74 | `rtl_confirmed` | HMAC access gate depends on privilege-indexed access-control state that resets open. |
| H21-075 | #75 | `rtl_confirmed` | HMAC key-derived registers use inconsistent lock bits. |
| H21-078 | #78 | `rtl_confirmed` | PKT fuse-control registers are writable without lock guards. |
| H21-079 | #79 | `rtl_confirmed` | SHA data registers use inconsistent read/write lock bits. |
| H21-080 | #80 | `rtl_confirmed` | AES1 key registers use inconsistent read/write lock bits. |
| H21-097 | #97 | `rtl_confirmed` | HMAC key-related registers are omitted from reset clearing. |
| H21-098 | #98 | `rtl_confirmed` | AES1 debug-mode masking leaves one key path unmasked. |
| H21-099 | #99 | `rtl_confirmed` | CLINT bridge lacks explicit access-control gating. |

## Seed Priority Groups

建议优先进入 RTL evidence 分析的 case：

1. **JTAG / debug authorization：** #1, #2, #3, #4, #7, #29, #30, #46, #47, #48, #53, #84, #98
2. **DMA / PMP / syscall：** #11, #25, #31, #45, #52, #54, #55, #56, #57, #64
3. **Register lock / access control：** #31-#35, #42, #43, #48-#50, #72, #75-#81, #99
4. **Privilege / CSR / memory protection：** #18, #21, #27, #41, #73, #74, #88, #91-#94
5. **Secret / crypto state residue：** #13, #15, #28, #36, #39, #46, #47, #59, #60, #83, #95, #97, #98
6. **Reset / lifecycle / state consistency：** #24, #29, #35, #42, #65-#67, #72, #95, #97

## Next Step

Do not add more Hack@DAC21 cases by quantity pressure. The current set already meets the 20-35 target. Further additions should only happen if a case has clearly better source evidence or improves scenario diversity.

## Deferred Cases

JTAG password/authentication cases remain deferred until the actual H21 JTAG password/auth RTL is located. Do not confirm them from README descriptions alone.

Also deferred:

- H21-050 / #50: chicken-bit corruption of register-lock value. Related source paths exist but need a cleaner evidence chain before scoring.
- H21-046 / #46: fuse data not disconnected in debug mode. Needs explicit debug-to-fuse path review before confirmation.
- Remaining functional, side-channel, bootrom, or pure FSM issues are not prioritized for the permission-related agent-evaluation dataset unless later needed for diversity.
