# PacketMaster

PacketMaster 是 TCP 测速不达标原因分析 Agent。它在本机流式处理 pcap/pcapng，模型只接收全量聚合后的有界摘要和分页证据，不接收原始报文、Payload、API Key 或本地绝对路径。

当前提供三个入口。推荐使用短命令 `pkm`，完整命令 `packetmaster` 继续兼容：

- `pkm web`：本地 Web 对话与可视化工作台；
- `pkm chat`：终端多轮对话；
- `pkm diagnose`：一次性命令行诊断。

## 安装

支持 Python 3.11 至 3.13。正式运行需要 Wireshark/TShark。

```bash
conda create -n agent python=3.12
conda activate agent
python -m pip install -r requirements.txt
```

Windows 安装 Wireshark 时勾选 TShark。若不在 PATH：

```powershell
$env:TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"
```

macOS 开发环境可以使用：

```bash
brew install wireshark
export TSHARK_PATH=/opt/homebrew/bin/tshark
```

## 模型配置

推荐复制本地模板并填写模型配置：

```powershell
Copy-Item src\packetmaster\config_local.example.py src\packetmaster\config_local.py
```

macOS：

```bash
cp src/packetmaster/config_local.example.py src/packetmaster/config_local.py
```

`config_local.py` 已被 Git 忽略。也可以使用环境变量临时覆盖：

```powershell
$env:MODEL_API_KEY = "..."
$env:MODEL_BASE_URL = "https://api.deepseek.com"
$env:MODEL_NAME = "deepseek-v4-flash"
$env:MODEL_STRUCTURED_OUTPUT_METHOD = "auto"
```

`auto` 会为 DeepSeek 兼容服务选择 `json_mode`，其他服务默认使用 `json_schema`。也可显式设置 `json_mode`、`json_schema` 或 `function_calling`。

## Web 工作台

Web 模式默认只监听 `127.0.0.1`，启动 API、单 Worker 和已构建的 React 页面：

```bash
conda activate agent
pkm web
```

不自动打开浏览器：

```bash
pkm web --no-browser
```

默认访问地址为 `http://127.0.0.1:8765`。端口占用时会继续尝试后续本机端口。

Web 首版不上传报文。用户输入本机 pcap/pcapng 绝对路径，后端校验后返回 `capture_id`，后续浏览器请求不再使用真实路径。默认只允许注册当前工作目录内的报文；生产环境应显式配置允许目录：

```powershell
$env:WEB_ALLOWED_CAPTURE_ROOTS = '["D:\\captures"]'
$env:WEB_DATABASE_PATH = "D:\PacketMaster\packetmaster-web.sqlite"
```

macOS：

```bash
export WEB_ALLOWED_CAPTURE_ROOTS='["/Users/me/captures"]'
export WEB_DATABASE_PATH='/Users/me/PacketMaster/packetmaster-web.sqlite'
```

工作台支持会话恢复、普通对话、分轮参数补充、确认后后台分析、SSE 进度、取消与重试、报告、吞吐/RTT/TCP 事件图表、TCP 流分页、证据浏览和诊断后持续问答。

## RAG 知识库

RAG 是可选能力。基础安装和无 RAG 诊断不依赖本地 Embedding 模型。安装可选依赖：

```powershell
python -m pip install -e ".[rag]"
```

首次联网运行会下载 `intfloat/multilingual-e5-small`。正式 Windows 离线环境应预先准备模型目录：

```powershell
$env:EMBEDDING_MODEL_PATH = "D:\PacketMaster\models\multilingual-e5-small"
$env:KNOWLEDGE_DATABASE_PATH = "D:\PacketMaster\knowledge\packetmaster-knowledge.sqlite"
$env:RAG_ENABLED = "true"
$env:RAG_MODE = "shadow"
```

导入、审核和检查知识：

```powershell
pkm knowledge import ".\knowledge\tcp-window.md" `
  --knowledge-id rfc.tcp-window --title "TCP 窗口机制" `
  --type standard --authority high --source-name "RFC"
pkm knowledge approve rfc.tcp-window:v1 --reviewer network-reviewer
pkm knowledge list --status approved
pkm knowledge health
```

运行模式：

- `off`：不检索知识；
- `shadow`：执行检索但不改变诊断候选，适合上线前观察；
- `active`：已验证知识可以补充候选原因和建议，但不能覆盖报文证据。

`active` 不是只改环境变量即可启用。必须先用不少于 50 条正式脱敏样本执行 `pkm knowledge evaluate` 并达到质量门槛；否则启动时自动降级为 `shadow`。完整知识管理、备份恢复、评估和离线部署步骤见 [RAG 使用与运维手册](docs/rag-operations.md)。

## CLI 诊断

省略 `--target` 时固定使用 `download`：

```powershell
pkm diagnose "C:\captures\测速 报文.pcapng" --standard 1000 --actual 600
```

只有明确需要时才使用上行或双向：

```powershell
pkm diagnose "C:\captures\test.pcapng" --standard 1000 --actual 600 --target upload
pkm diagnose "C:\captures\test.pcapng" --standard 1000 --actual 600 --target both
```

指定报告目录并保留产物：

```bash
pkm diagnose samples/packetmaster_download_underperform.pcapng \
  --standard 1000 \
  --actual 20 \
  --output-dir artifacts/my-first-report \
  --keep-artifacts
```

## CLI 对话

```bash
pkm chat
```

可以一次提供完整参数，也可以分多轮补充：

```text
请分析 /Users/me/captures/test.pcapng，标准带宽 1Gbps，实际 600M
```

未明确方向时默认下载，参数完整后仍需用户确认。诊断完成后可继续询问当前报告和证据。

内置命令：`/new`、`/report`、`/evidence`、`/save`、`/help`、`/quit`。

## 前端开发

运行已构建 Web 不需要 Node.js。只有修改 React 前端时才需要 Node 20 至 24：

```bash
cd webui
npm ci
npm run dev
```

Vite 开发服务运行在 `http://127.0.0.1:5173`，并将 `/api` 代理到 PacketMaster Web 后端。生产构建：

```bash
npm run build
```

## 测试

```bash
python -m pytest -m "not performance" -q
python -m ruff check .

cd webui
npm run typecheck
npm run lint
npm test
npm run build
npm run test:e2e
```

`npm run test:e2e` 默认使用系统 Google Chrome 访问 `http://127.0.0.1:8765`。先启动 `pkm web --no-browser`。

大报文真实门禁：

```powershell
$env:PERF_PCAP_PATH = "D:\captures\release-2gb.pcapng"
$env:PERF_METADATA_PATH = "D:\captures\release-2gb.pcapng.metadata.json"
$env:PERF_MAX_RSS_BYTES = "1073741824"
python -m pytest tests/performance/test_large_capture.py -v
```

独立元数据需要包含 `input_size_bytes`、`total_packets_seen`、`tcp_packets_seen` 和 `speed_packets_analyzed`。Windows 真机发布步骤见 [Windows Web 发布验收清单](docs/windows-web-release-checklist.md)。

RAG 25,000 切片容量门禁：

```bash
python -m pytest tests/performance/test_rag_capacity.py -v
```
