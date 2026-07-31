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

### DashScope Embedding 配置

RAG 默认使用阿里云百炼 DashScope 的原生多模态模型 `qwen3-vl-embedding`（2560 维），不再提供本地 embedding 模型回退。Markdown 文件可导入同目录或子目录的相对 PNG、JPEG、WebP 图片（单图最多 5 MiB）；图片与所在章节首个切片的正文会做图文联合 Embedding。远程 URL、绝对路径、`data:` 图片及越出 Markdown 目录的引用会被忽略并提示警告。Web 的纯文本上传无法携带本机图片，请使用 CLI 文件导入。

```python
# src/packetmaster/config_local.py
EMBEDDING_API_KEY = "sk-..."
```

```bash
export EMBEDDING_API_KEY="sk-..."
export EMBEDDING_MODEL="qwen3-vl-embedding"
export EMBEDDING_DIMENSION="2560"
```

模型 API Key 和 Embedding API Key 都不会写入日志、Web API 响应或诊断报告。

### DashScope Reranker 配置

RAG 默认启用百炼 `qwen3-rerank`。它复用 `EMBEDDING_API_KEY`，仅在需要不同凭据时配置 `RERANK_API_KEY`：

```bash
export RERANKER_ENABLED="true"
export RERANKER_MODEL="qwen3-rerank"
export RERANKER_CANDIDATE_TOP_K="20"
export RAG_FINAL_TOP_K="8"
```

`qwen3-rerank` 是文本重排模型。多模态知识的图片参与 `qwen3-vl-embedding` 召回，重排阶段使用切片标题、正文和图片替代文本。

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

点击“加载报文”即可打开系统文件选择器，支持 `.pcap` 和 `.pcapng`。选中的文件会自动上传到本机 PacketMaster 受管目录 `artifacts/web-captures`，并作为待发送附件显示在输入区；补充描述后点击发送，文字和 `capture_id` 会一并进入对话。页面和 API 不返回浏览器路径或受管文件绝对路径。删除报文引用不会删除原始文件或受管副本。

路径注册 API 仍保留给 CLI 和已有本机自动化调用。默认只允许从当前工作目录注册路径；生产环境应显式配置允许目录：

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

右上角“知识库”提供知识列表、浏览器文件导入预览、草稿保存、审核发布、版本历史、停用、重建索引，以及最后一次正式评估与 active 门禁状态。知识文件支持 `.md`、`.markdown`、`.txt`、`.json`；浏览器只提交所选文件名和内容，不提交本地路径。

## RAG 知识库

RAG 是可选能力。基础安装和无 RAG 诊断不依赖 embedding 服务；启用 RAG 时需要 DashScope API Key。安装可选依赖：

```powershell
python -m pip install -e ".[rag]"
```

```bash
export EMBEDDING_API_KEY="sk-..."
export KNOWLEDGE_DATABASE_PATH="artifacts/knowledge/packetmaster-knowledge.sqlite"
export RAG_ENABLED=true
export RAG_MODE=shadow
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

当前检索使用 FTS5/BM25 与 DashScope 向量检索并行召回，经过环境过滤和 RRF 融合后取 Top 20，再由百炼 `qwen3-rerank` 重排，最终按 `RAG_FINAL_TOP_K`（默认 8）和上下文预算交给模型。Reranker 超时、限流或服务异常时自动回退到 RRF 排序。

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

## 项目结构

```text
SpeedAnalyzeAgent/
├── src/packetmaster/                 # Python 主包
│   ├── cli.py                        # pkm / packetmaster 命令入口
│   ├── config.py                     # 环境变量与本地配置加载
│   ├── config_local.example.py       # API Key 本地配置模板
│   ├── graph.py                      # LangGraph 诊断流程
│   ├── analyzer/                     # TShark 实报文与 mock 分析适配器
│   ├── application/                  # 诊断应用服务
│   ├── mcp/                          # MCP Server 与客户端
│   ├── prompts/                      # 模型提示词
│   ├── rag/                          # 知识导入、DashScope embedding、检索、评估、SQLite 存储
│   └── web/                          # FastAPI、会话、Worker、报文注册、已构建静态资源
├── webui/                            # React + TypeScript 前端工程
│   ├── src/                          # 工作台、知识管理、API 客户端与样式
│   ├── e2e/                          # Playwright 端到端测试
│   └── vite.config.ts                # 前端构建与开发代理配置
├── speed-analyze/scripts/            # 报文处理脚本及共享库
├── tests/                            # 自动化测试
│   ├── unit/                         # 单元测试
│   ├── integration/                  # CLI 与真实处理链路集成测试
│   ├── contract/                     # MCP 合约测试
│   ├── performance/                  # 大报文与 RAG 容量门禁
│   └── fixtures/                     # 测试数据
├── docs/                             # 使用手册、规格、计划、评估模板
├── samples/                          # 示例与合成测试数据
├── scripts/                          # 开发辅助脚本
├── artifacts/                        # 运行时产物、Web 数据库、知识库、上传报文（Git 忽略）
├── pyproject.toml                    # Python 依赖、命令和工具配置
└── requirements.txt                  # 开发环境安装入口
```

`src/packetmaster/config_local.py`、`artifacts/`、`webui/node_modules/`、`build/` 和测试缓存均属于本机生成内容，不应提交到 Git。

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
