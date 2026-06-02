# Scope Evaluation Summary

## 1. Basic Info

- input_scope: `h21_dma_pkt_scope`
- benchmark: `hackatdac21`
- models: `deepseek_v4_pro`, `gpt_5_5`
- repetitions: 3 per model
- expected GT cases: `H21-031`, `H21-059`, `H21-078`

## 2. GT Cases

| case_id | brief meaning |
|---|---|
| `H21-031` | DMA programming registers are not protected by register locks. |
| `H21-059` | PKT default read path can leak fuse data. |
| `H21-078` | PKT fuse control registers are not register-locked. |

## 3. Per-run Results

DeepSeek reliably detects DMA missing register locks and detects PKT fuse-control lock issue in rep3. GPT detects PKT fuse-data leakage in rep1 and only partially detects DMA lock semantics through broader permission findings.

## 4. Main Observations

Models often produce adjacent ACCT/REGLK/we_flag findings that are not scored in this DMA/PKT scope. DeepSeek is better on explicit DMA register-lock absence; GPT is better on the PKT fuse default read leakage in one run.

## 5. Notes for Later Scoring

For `H21-031`, require missing register-lock enforcement on DMA programming registers. For `H21-059`, require `fuse_rdata_i` default/read-path leakage. For `H21-078`, require unprotected writes to PKT fuse-control registers such as `fuse_req_o` and `fuse_addr_o`.
