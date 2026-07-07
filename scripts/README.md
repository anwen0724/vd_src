# Scripts Directory

本目录存放可直接运行的实验脚本和辅助脚本。日常实验优先使用 `run/` 目录；其他目录按用途分组，避免误用旧脚本。

## run/

正式运行入口，适合在 PyCharm 中右键运行。

- `run_ours_chain_context_batch.py`：通用 ours 批量入口，通过 `--config` 指定 `configs/ours_chain_context_*.yaml`。
- `run_ours_chain_context_gemini.py`：固定读取 `configs/ours_chain_context_gemini.yaml`，右键即跑 Gemini。
- `run_ours_chain_context_claude.py`：固定读取 `configs/ours_chain_context_claude.yaml`，右键即跑 Claude。
- `run_baseline_pilot.py`：baseline 批量入口，通过 `--config` 指定 baseline 配置。
- `run_baseline_pilot.bat`：Windows 下启动 baseline 的批处理入口。

## build/

生成 ours 方法中间产物的脚本。通常在重新构建数据产物时使用，不是每次模型实验都要运行。

- `batch_build_rtl_structure_graphs.py`：批量生成模块1 RTL 结构图。
- `build_rtl_structure_graph.py`：单个 repo 生成 RTL 结构图。
- `batch_build_permission_check_targets.py`：批量生成模块2权限检查目标。
- `build_permission_check_targets.py`：单个 repo 生成权限检查目标。
- `batch_build_permission_chain_graphs.py`：批量生成权限链路图。
- `build_permission_chain_graphs.py`：单个 repo 生成权限链路图。
- `batch_build_permission_chain_contexts.py`：批量生成模块3输入的权限链路上下文。
- `build_permission_chain_contexts.py`：单个 repo 生成权限链路上下文。

## evaluate/

覆盖率、执行开销和实验结果汇总脚本。

- `evaluate_chain_context_coverage.py`：评估 chain context 的 GT evidence 后验覆盖率。
- `evaluate_chain_graph_coverage.py`：评估 chain graph 的 GT evidence 后验覆盖率。
- `summarize_ours_execution_cost.py`：汇总 ours 运行后的 RQ3 执行开销 CSV。

## evaluation/

人工评估和指标计算流程脚本，服务于 baseline/ours 输出的 Precision、Recall、F1 和失败机制分析。

- `01_build_gt_cases.py`：整理 GT case 表。
- `02_build_finding_review_draft.py`：生成 finding 人工评审草稿。
- `03_validate_finding_review.py`：校验人工评审表。
- `04_compute_single_run_metrics.py`：计算 single-run 指标。
- `05_compute_anyhit3_metrics.py`：计算 any-hit@3 指标。
- `06_build_failure_candidates.py`：生成失败机制候选样本。
- `07_init_failure_analysis.py`：初始化失败分析表。
- `08_summarize_failure_mechanisms.py`：汇总失败机制。
- `09_collect_model_summaries.py`：汇总模型级结果。

## analysis/

研究分析和压缩实验脚本。除非重新做 context 压缩或分析，不作为正式模型运行入口。

- `compress_chain_contexts_semantic.py`：从原始 context 生成无 GT 的语义代表去重版本，例如 1748 -> 1049。
- `compress_chain_contexts_by_gt_coverage.py`：基于 GT coverage 的上限压缩分析，只用于诊断冗余，不用于主实验输入。
- `compress_chain_contexts_global_diverse.py`：全局多样性压缩试验脚本，当前不作为主实验默认输入。
- `dedupe_chain_contexts_by_snippets.py`：早期按 snippet 区间 exact 去重的分析脚本。

## legacy/

旧版非配置驱动脚本，保留用于追溯和对比，不建议日常运行。

- `batch_run_chain_context_analysis.py`：旧的模块3批量运行脚本。
- `run_chain_context_analysis.py`：旧的模块3单次运行脚本。
- `batch_run_tool_guided_chain_analysis.py`：旧的方案A工具调用批量脚本。
- `run_tool_guided_chain_analysis.py`：旧的方案A工具调用单次脚本。

## dev/

开发调试脚本，不作为正式实验入口。

- `preflight_baseline_pilot.py`：baseline 运行前环境检查。
- `rerun_failed_baseline.py`：重跑失败 baseline run 的辅助脚本。
- `test_gpt_client.py`：GPT client 手动连通性测试。
