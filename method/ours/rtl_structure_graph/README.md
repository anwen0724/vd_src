# RTL 结构关系图构建

本目录实现四阶段方法中的模块1：从输入 `rtl repo` 构建完整 RTL 结构关系图。

正式模块接口只输出：

```text
rtl_structure_graph.json
```

该文件顶层只包含：

```text
graph_id
nodes
edges
```

工程诊断信息单独输出到：

```text
rtl_structure_graph_diagnostics.json
```

命令行入口：

```bash
python src/scripts/build/build_rtl_structure_graph.py --repo <rtl_repo> --out <output_dir>
```

模块1不生成权限检查目标，不做权限语义判断，不判断漏洞。
