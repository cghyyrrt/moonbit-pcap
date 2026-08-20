# MoonBit PCAP 验收完善设计

## 目标

把 `moonbit-pcap` 完善为可供应用集成的纯 MoonBit PCAP/PCAPNG 解析与网络分析库，在不改动申报书的前提下增加真实协议能力、边界测试、可重复基准和可发布的仓库工程化配置。源码规模只统计仓库中手写的 `.mbt` 文件，不把 `_build` 或生成文件计入。

## 方案

### 工业协议模块

在 `src/layers` 增加 EtherNet/IP 和 DNP3 的分层解析 API。每个解析器接收 `Bytes` 和偏移/长度边界，返回明确的可选结果或错误结果，拒绝截断数据、非法长度和校验不通过的数据。公共结构体只暴露协议字段和原始 payload，不引入外部依赖。

EtherNet/IP 覆盖封装头、命令、状态、会话句柄、长度、选项、RegisterSession 和 SendRRData 的常见字段；DNP3 覆盖链路头、长度、控制字段、源/目的地址、链路 CRC、传输控制字段、应用控制字段、对象头和常见静态二进制/模拟量对象读取。

### 解析质量

补充 PCAP/PCAPNG、IPv4/IPv6、TCP/DNS/HTTP、重组和过滤器的边界测试，优先覆盖空包、截断包、长度溢出、错误校验、重复/重叠序列、极值时间戳和未知类型。新增测试必须先验证失败再实现，通过后再做小范围重构。

### 基准

添加一个仓库内可运行的 benchmark 模块或命令，使用固定的合成 PCAP 数据，报告输入大小、包数、解析成功数、总耗时和 MB/s。基准不得伪造性能数字；README 只记录实际命令输出中的稳定结果和运行环境。

### CI 与发布

将现有 CI 调整为三平台矩阵，使用稳定 MoonBit 安装器，执行 `moon version --all`、`moon update`、`moon fmt --check`、`moon check --target all`、`moon test --target all`、`moon info` 和格式差异检查。增加覆盖率摘要但不把覆盖率阈值写成未经验证的承诺。增加手动 `publish.yml`，从 `MOONCAKES_TOKEN` 或项目约定的 GitHub Secret 读取 token，发布前执行检查，发布后删除临时凭据。

### 文档

README 采用成熟库结构：简介、特性、安装、快速开始、模块、协议支持、CLI、WASM、测试与基准、CI、发布、贡献和许可证。删除竞赛名称、申报人、结项、唯一贡献者、内部审核和双远程同步等内容。申报书文件保持原样。

## 验收标准

- 生产与测试手写 `.mbt` 总行数由命令真实统计并超过 8,000 行，统计脚本排除 `_build`。
- `moon fmt --check`、`moon check --deny-warn --target all`、`moon test --target all` 和本地基准命令成功。
- 新协议和新增边界路径都有自动化测试，测试数量和结果来自真实命令输出。
- README 不含内部竞赛验收措辞，LICENSE 为 Apache-2.0，默认分支和远程状态可核对。
- GitHub Actions YAML 可解析，发布工作流不包含明文凭据。

