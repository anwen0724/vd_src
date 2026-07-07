# Current Four Runs Evaluation With FP Clustering

This directory preserves the strict evaluation in `evaluation_results/current_four_runs/` and recalculates metrics after clustering repeated FP findings.

Policy:

- TP duplicates are handled as before: only one TP per GT case per run is counted.
- FP findings are clustered within the same model/method/input_scope/repetition by similar claimed root issue, using summary, affected location, module, signal/register, and file tokens.
- `fp_cluster_review.csv` records every FP cluster and its member count for manual review.
- `finding_review_with_fp_clusters.csv` records each original finding and its cluster role.

| Method | Model | TP cases | FN cases | FP clusters | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|
| baseline | claude_sonnet_4-6 | 21 | 64 | 35 | 0.375000 | 0.247059 | 0.297872 |
| baseline | gemini_3.1_pro_preview | 0 | 85 | 0 | undefined | 0.000000 | undefined |
| ours_chain_context | claude_sonnet_4-6 | 46 | 39 | 354 | 0.115000 | 0.541176 | 0.189691 |
| ours_chain_context | gemini_3.1_pro_preview | 31 | 54 | 197 | 0.135965 | 0.364706 | 0.198083 |
