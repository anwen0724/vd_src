# Method Project Root

`src/` 是本课题后续代码实现与实验运行的独立项目根目录。

本目录不只是外层研究项目的普通源码目录，而是后续 baseline 实验、proposed method 实现、LLM/agent 调用、实验数据副本、运行配置、运行输出和评估结果的代码项目空间。

外层 `docs/`、`data/`、`experiments/` 等目录主要用于研究讨论、数据准备、人工整理和历史留存。正式代码运行时需要的内容应逐步整理进入 `src/` 内部对应目录。

## 当前定位

当前阶段先搭建 baseline 实验地基：

- 运行 baseline LLM / agent 方法；
- 调用模型并保存输出；
- 管理实验输入、运行配置和运行结果；
- 为后续人工评分和指标汇总提供代码支持。

后续提出的方法也继续在本目录中实现。

## 目录结构

```text
src/
├─ README.md
├─ method/
│  ├─ baseline/
│  └─ proposed/
├─ llm/
├─ tools/
├─ runtime/
├─ evaluation/
├─ datasets/
│  ├─ benchmarks/
│  └─ agent_inputs/
├─ runs/
│  ├─ baseline/
│  └─ proposed/
├─ results/
│  ├─ baseline/
│  └─ proposed/
├─ prompts/
│  ├─ baseline/
│  └─ proposed/
├─ schemas/
├─ templates/
├─ configs/
├─ scripts/
├─ utils/
└─ tests/
```

## 目录说明

`method/`

存放实验中运行的方法实现。

- `method/baseline/`：baseline 方法实现，例如 direct LLM baseline、read/search-only baseline。
- `method/proposed/`：后续本文提出的方法实现。

`llm/`

存放 LLM 调用相关代码，例如统一模型接口、mock client、OpenAI / Claude / DeepSeek / Qwen 等模型 client。

`tools/`

存放方法运行时可调用的工具代码。当前 baseline 阶段优先实现 read/search-only 工具。

`runtime/`

存放实验运行管理逻辑，例如加载配置、加载数据集、组织 prompt、调用方法、保存输出和记录日志。

`evaluation/`

存放评估相关代码，例如 ground truth 加载、输出格式校验、评分表初始化、人工评分结果汇总和指标计算。

`datasets/`

存放整理后供本代码项目直接运行的数据集副本。

- `datasets/benchmarks/`：benchmark GT、case inventory、evidence 标注等评估侧数据。
- `datasets/agent_inputs/`：agent/LLM 实际可见的清洗后源码输入。

`runs/`

存放具体实验运行过程文件，例如 raw output、structured output、trace、run metadata 和运行日志。

`results/`

存放实验评分和汇总结果，例如 run summary、模型对比表和错误分析结果。

`prompts/`

存放代码运行时实际读取的 prompt。

- `prompts/baseline/`：baseline 实验 prompt。
- `prompts/proposed/`：后续 proposed method prompt。

`schemas/`

存放结构化输出、run metadata、评分输入输出等 schema。

`templates/`

存放 CSV 模板、评分表模板和报告模板。

`configs/`

存放模型配置、运行配置和默认参数。

`scripts/`

存放本代码项目内部的辅助执行脚本。正式运行入口后续可以由统一 CLI 或这里的脚本触发。

`utils/`

存放通用工具函数，例如路径处理、CSV/JSON 读写和日志辅助。

`tests/`

存放本代码项目自己的测试。
