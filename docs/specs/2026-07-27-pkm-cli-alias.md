# PacketMaster `pkm` 命令别名设计

日期：2026-07-27

状态：已确认

## 目标

为 PacketMaster 增加更短的终端命令 `pkm`，降低日常启动和操作成本。

## 行为

- `pkm` 与 `packetmaster` 指向同一个 Typer 应用；
- `pkm web`、`pkm chat` 和 `pkm diagnose` 的参数、输出和退出码保持一致；
- 原有 `packetmaster` 命令继续保留，现有脚本和文档保持兼容；
- 别名通过 Python 包的控制台入口安装，不依赖 shell alias，因此兼容 Windows 和 macOS。

## 验收标准

- 从 wheel 安装后同时存在 `packetmaster` 和 `pkm`；
- 两个命令的 `--help` 均可执行；
- `pkm web --no-browser` 能启动同一 Web 工作台；
- 不复制 CLI 实现，不引入第二套命令逻辑。
