# MoonBit PCAP 验收改造任务计划

## 目标

在不修改申报书的前提下，把项目完善为可发布、可复现验证的 MoonBit 网络报文解析库：真实手写 `.mbt` 源码超过 8,000 行，新增协议与边界测试具有实际 API 价值，CI 覆盖最新稳定工具链和多目标检查，并完成 GitHub 与 Mooncakes 发布准备。

## 阶段

- [x] 完成仓库、工具链、源码规模、CI、文档和外部规范基线审计
- [x] 完成设计规格与实施计划
- [x] 扩展工业协议和公共解析辅助模块
- [x] 扩充边界测试、集成样例和真实基准
- [x] 重写 README，补齐 CI 与 Mooncakes 发布工作流
- [x] 执行全量验证、手工自查并推送发布

## 约束

- 不修改 `8月黑客松项目申报书.md` 或 `project_application.md`
- 不虚报源码规模；统计排除 `_build/` 和生成文件
- README 不出现申报人、结项、唯一贡献者、内部审核说明等表述
- 不提交任何 token、密码或远程凭据

## 错误记录

| 错误 | 尝试 | 处理 |
|---|---|---|
| `.git/index.lock` 权限拒绝 | 创建隔离分支前提交 `.gitignore` | `.git` 只读，按技能回退在当前工作区实施 |
| 无法创建 `codex/acceptance` worktree | `git worktree add .worktrees/acceptance -b codex/acceptance` | 不重复尝试，保留当前工作区继续 |
