# Baseline Method

本目录存放当前阶段的 baseline 方法实现。

当前 baseline 定义为：

```text
LLM + read/search-only code access tools
```

该 baseline 只给 LLM 提供基础代码阅读能力，用于观察主流模型在 SoC RTL 跨模块权限漏洞检测任务中的原始能力和可靠性。

## 能力边界

允许：

- 列举指定 input scope 内的目录；
- 读取指定 input scope 内的文件；
- 在指定 input scope 内搜索文本；
- 基于读取到的代码证据生成最终安全分析结果。

禁止：

- 修改文件；
- 执行代码或脚本；
- 运行 simulation、formal、lint、synthesis；
- 联网搜索；
- 读取 hidden GT、case 文档、evidence GT 或评分材料；
- 自动 patch；
- 生成并执行 SVA、testbench 或验证脚本。

## 第一版实现目标

第一版 baseline 保留两种实现：

```text
read_search_llm.py
langchain_read_search_llm.py
```

其中：

- `read_search_llm.py`：轻量 JSON 文本协议实现，不依赖 LangChain。
- `langchain_read_search_llm.py`：LangChain tool calling 实现，使用同一套只读文件工具。

两者都应通过统一 runtime 调用 LLM client 和只读工具，并保存：

- final answer；
- tool trace；
- run metadata；
- raw model outputs。

## 后续对比关系

该 baseline 不是本文提出的方法。后续 proposed method 将放在：

```text
src/method/proposed/
```

baseline 结果用于建立对比，并为后续方法设计提供错误分析依据。
