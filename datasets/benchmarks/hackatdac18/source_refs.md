# Hack@DAC18 Source References

日期：2026-05-22

## 1. Hack@DAC18 GitHub Repository

- 名称：HACK-EVENT/hackatdac18
- URL：https://github.com/HACK-EVENT/hackatdac18
- 用途：Hack@DAC 2018 Phase 2 buggy SoC 源码与 README。
- 当前使用内容：README 中 31 个 bug 的官方描述。
- 访问日期：2026-05-22

## 2. Hack@DAC18 README Bug List

- URL：https://github.com/HACK-EVENT/hackatdac18/blob/master/README.md
- 用途：官方 bug list。
- 关键说明：README 明确说明 “The following bugs were inserted into the SoC”，并列出 31 个 bug。
- 访问日期：2026-05-22

## 3. HardFails Paper

- 标题：HardFails: Insights into Software-Exploitable Hardware Bugs
- 会议：USENIX Security 2019
- URL：https://www.usenix.org/system/files/sec19-dessouky.pdf
- 用途：Table 1 补充 inserted/native、CVE、SPV/FPV/M&S detection、module count、LOC 和 states。
- 访问日期：2026-05-22

## 4. Hack The Silicon Learn Page

- URL：https://hackthesilicon.com/learn/
- 用途：确认 Hack@DAC 2018 资源入口，页面将 `SOC` 和 `Bug List` 指向 Hack@DAC18 GitHub 仓库。
- 访问日期：2026-05-22

## 5. Intel Hack@DAC Review Article

- 标题：Raising Awareness of Hardware Security Weaknesses: Intel Research and Hack@DAC
- URL：https://www.intel.com/content/www/us/en/security/security-practices/blogs/raising-awareness-hardware-security-weaknesses.html
- 用途：确认 Hack@DAC 的发布机制和公开 benchmark 意图。文章说明比赛结束后，带有完整 inserted vulnerabilities 列表的模型会发布到 Hack-Events GitHub 项目。
- 访问日期：2026-05-22

## 6. 当前限制

- 当前尚未整理 line-level RTL evidence。
- 当前尚未建立 task-level GT 和 evidence-level GT。

## 7. 本地源码镜像

- 本地路径：`third_party/hackatdac18/`
- Clone URL：https://github.com/HACK-EVENT/hackatdac18.git
- Clone 日期：2026-05-22
- 当前 commit：`60534635d40f397d71b45be511d954af2c0c7b3d`
- 用途：作为后续 baseline agent 可读取的 RTL/source 输入，以及人工补充 evidence-level GT 的源码依据。

注意：

- `third_party/hackatdac18/` 是外部源码镜像，不保存本课题 GT。
- baseline agent 可以读取源码镜像，但不应读取 `data/benchmarks/hackatdac18/` 下的 GT 文件。
