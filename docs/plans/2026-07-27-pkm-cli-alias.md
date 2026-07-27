# PacketMaster `pkm` 命令别名实施计划

日期：2026-07-27

状态：已确认

依据：`docs/specs/2026-07-27-pkm-cli-alias.md`

## 实施步骤

1. 在 Python 包控制台入口中注册 `pkm` 别名，同时保留 `packetmaster`。
2. 扩展 wheel 安装测试，验证两个命令均已安装并可显示帮助。
3. 更新 README 的 Web、对话和一次性诊断启动示例。
4. 运行打包测试、CLI 回归测试和 Ruff。
5. 使用中文 Git 提交信息提交变更。

## 完成定义

- `pkm web` 可以启动可视化界面；
- `pkm chat` 和 `pkm diagnose` 与原命令行为一致；
- Windows 和 macOS 安装后均不需要额外配置 shell alias；
- 原 `packetmaster` 命令无回归。
