# Proposed Method

本目录实现论文方法设计文档中的完整初版方法。

当前实现对应：

```text
docs/05_method_notes/02_method_design_initial_and_final.md
```

## 顶层模块

```text
Module 1: Permission-oriented RTL Fact Layer Construction
Module 2: Knowledge-augmented Obligation-driven Analysis
Module 3: Evidence Closure and Verdict Calibration
```

## 代码结构

```text
method/proposed/
├─ fact_layer/
│  └─ extractor.py
├─ knowledge/
│  ├─ loader.py
│  └─ permission_vulnerability_knowledge.md
├─ closure/
│  └─ checker.py
├─ langchain_initial.py
├─ mock_llm.py
├─ models.py
└─ pipeline.py
```

## 主要产物

每次运行会保存：

```text
static_fact_layer.json
permission_fact_layer.json
obligations.json
inspection_records.json
closure_records.json
structured_output.json
run_metadata.json
```

其中 `structured_output.json` 使用与 baseline 相同的 `schemas.agent_output.AgentOutput`。

