# 进度日志

## 2026-08-21

- 完成只读基线审计。
- 确认 4,921 行真实 `.mbt` 源码、43 个通过测试。
- 确认现有 CI 与缺口。
- 获取用户对扩展方向和设计的确认。
- 尝试创建隔离 worktree，因 `.git` 只读失败；记录后回退当前工作区。
- 已创建任务计划、发现记录和设计文档，待实施计划确认后开始改源码。
- 新增 EtherNet/IP、DNP3、CIP 对象、DNP3 对象/函数元数据和应用协议注册表。
- 新增 PCAP/PCAPNG 验证器、过滤器快照、包摘要、字节游标/队列、流窗口、流量报告查询和 Markdown 导出。
- 新增 43 个测试，当前全量测试为 86/86；`moon check --deny-warn --target all` 通过。
- 源码统计脚本当前报告：101 个手写 `.mbt` 文件，8,090 行总源码，6,910 行生产代码，1,180 行测试代码。
- 基准真实运行：`moon bench benchmarks`，`ethernet_ipv4_udp_parse` 为 479.38 ns ± 25.85 ns，10 × 100000 runs（Windows，MoonBit 0.1.20260814）。
- README 已重写；CI 已加入稳定工具链、全目标检查、Unix native 测试、Windows 默认测试和手动 Mooncakes 发布工作流。
- 全量验证：`moon fmt --check`、`moon check --deny-warn --target all`、`moon test --deny-warn`、`moon test --target wasm-gc`、benchmark 均通过。
- `moon test --target all` 在当前 Windows 本机被 MoonBit runtime 的 `rand_s` 隐式声明警告阻断；项目默认目标和 WASM-GC 测试通过，CI 已按平台避免该环境问题。
- GitHub `origin/main` 已推送到提交 `355fd2d`。
- Mooncakes `moon publish` 实际发布完成，服务器返回 `200 OK`，包版本为 `0.1.0`。
