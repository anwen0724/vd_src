# Scope Evaluation Summary

## 1. Basic Info

- input_scope: `h19_debug_jtag_scope`
- benchmark: `hackatdac19`
- models: `deepseek_v4_pro`, `gpt_5_5`
- repetitions: 3 per model
- expected GT cases: `H19-005`, `H19-047`, `H19-048`, `H19-049`, `H19-050`, `H19-051`, `H19-054`, `H19-056`

## 2. GT Cases

| case_id | brief meaning |
|---|---|
| `H19-005` | Debug module reports authenticated without implemented authentication. |
| `H19-047` | Some DMI/JTAG operations are not password guarded. |
| `H19-048` | JTAG unlock can force processor machine privilege. |
| `H19-049` | JTAG password is only 32 bits. |
| `H19-050` | Authorized debug can access FUSE memory. |
| `H19-051` | JTAG password flag is not reset properly. |
| `H19-054` | JTAG key is hardcoded. |
| `H19-056` | Debug path exposes secondary reset control. |

## 3. Per-run Results

DeepSeek detects selected pass-check, JTAG privilege, and password/key cases but produces several ROM2/SimDTM FPs. GPT consistently detects always-authenticated debug and DMI write bypass, and detects pass-state residue in one run.

## 4. Main Observations

The models find broad debug authentication failures, but coverage is uneven across specific JTAG/debug GT cases. No run identifies debug-to-FUSE access (`H19-050`) or secondary reset control (`H19-056`). GPT is better on `dmstatus.authenticated` and DMI write bypass; DeepSeek is better on JTAG privilege escalation and 32-bit/hardcoded password cases in some runs.

## 5. Notes for Later Scoring

Do not merge all ROM2 key exposure findings into JTAG hardcoded-key or debug-to-FUSE cases. `H19-050` requires debug/SBA-to-ROM2/FUSE reachability; `H19-056` requires `dmcontrol.ndmreset` reset-path evidence.
