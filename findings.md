# 审计发现

## 基线

- 当前仓库：`D:\陈光豪初审2`
- 当前分支：`main`
- GitHub `origin/main` 落后于本地提交；本地还有 GitLink 远程，但本次验收不处理 GitLink。
- 未跟踪申报材料存在，必须保留原样。
- 本地 MoonBit：`moon 0.1.20260814 (a2de5b2 2026-08-14)`。
- 真实源文件统计：`src/` 与 `cmd/` 下 `.mbt` 共 4,921 行，其中生产代码 4,287 行、测试 634 行；不能把 `_build/` 生成文件计入源码。
- `moon check --deny-warn` 通过；`moon test` 通过 43/43。

## 现有结构

`binary`、`pcap`、`pcapng`、`layers`、`reassembly`、`analyzer`、`exporter`、`cli`、`wasm` 和 `cmd/main` 已形成可用模块边界。

## 文档问题

README 仍含 OSC 2026、作者/单贡献者、代码规模、双远程同步等内部验收内容；版本徽章和源码数字也已过时。申报书中已有规模和路线描述，但不纳入本次修改。

## CI 发现

已有三平台 CI，包含工具链安装、格式化、`moon check --deny-warn`、测试和主程序运行；需增加格式差异失败、`moon info`、全目标检查/测试、覆盖率摘要和手动 Mooncakes 发布工作流。

## 外部规范

- 参考 CI 使用三平台、稳定工具链安装、`moon fmt --check`、`moon check --deny-warn`、覆盖率和 native/默认目标测试。
- MoonBit 社区模板的 `check.yml` 使用 `moon version --all`、`moon update`、`moon check/test --target all`、`moon info` 和 `git diff --exit-code`。
- 社区模板的 `publish.yml` 使用手动触发、GitHub Secret 注入 Mooncakes token、发布前检查和发布后删除临时凭据文件。
- `Milky2018/osc2026-guide` 仓库公开说明包含仓库结构、README、LICENSE、提交历史、默认分支、MoonBit 源码规模和黑客松适配检查维度；本机没有其可执行 skill，因此采用手工等价核验。

