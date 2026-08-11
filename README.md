# PacketMaster

[![CI](https://github.com/huangzekai1208/PacketMaster/actions/workflows/test.yml/badge.svg)](https://github.com/huangzekai1208/PacketMaster/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/Python-3.11--3.13-3776AB?logo=python&logoColor=white)](https://www.python.org/)

PacketMaster 是一个面向 PCAP/PCAPNG 的本地网络诊断 Agent。当前核心能力是分析 TCP 测速不达标问题：它通过 TShark 流式处理完整报文，提取吞吐、RTT、重传、乱序、窗口和流级证据，再由 LangGraph 编排诊断、证据复核和报告生成。

项目同时提供 Web 工作台、CLI、多轮对话、分页证据查询、断点恢复，以及带审核和评测门禁的 RAG 知识库。

> 当前稳定分析流水线面向 TCP 测速诊断。Web 已提供“测速分析 / 通用卡顿”模式入口；通用卡顿的独立协议分析与归因流水线仍在建设中，请勿将该入口视为完整卡顿分析能力。

## 核心特性

- **本地报文处理**：原始 PCAP、筛选报文和 Payload 不进入模型上下文。
- **全量流式聚合**：不只分析首个端口或第一条 TCP 流，适合大型抓包。
- **证据驱动诊断**：每个原因包含支持证据、反向证据、受影响流、置信度和建议。
- **多入口使用**：提供 Web 工作台、一次性 CLI 和终端多轮对话。
- **可恢复任务**：后台 Worker、SSE 进度、取消、失败重试和 LangGraph 检查点恢复。
- **受控证据查询**：通过本地 SQLite 分页读取白名单字段，不向模型发送完整逐包数据。
- **可治理 RAG**：支持知识导入、审核、版本、停用、重建索引、离线评测和 active 门禁。
- **模型可观测性**：记录脱敏调用元数据、Token usage、延迟、重试和可选成本估算。

## 工作方式

```text
PCAP / PCAPNG
    -> TShark 流式提取
    -> TCP 全量聚合与本地证据索引
    -> 候选原因生成
    -> RAG 知识增强（可选）
    -> 分页证据复核
    -> 结构化报告与持续追问
```

模型只接收有界摘要和按需查询的局部证据。原始报文、Payload、API Key 和本机绝对路径不会写入模型上下文、Web 响应或诊断报告。

## 快速开始

### 1. 环境要求

- Python 3.11、3.12 或 3.13，推荐 3.12
- Wireshark/TShark
- 一个支持 OpenAI 兼容接口的大模型
- 启用 RAG 时需要阿里云百炼 DashScope API
- Node.js 20-24 仅在修改前端时需要

安装 TShark：

```bash
# macOS
brew install wireshark

# Ubuntu / Debian
sudo apt update
sudo apt install tshark
```

Windows 请安装 Wireshark，并在安装向导中勾选 TShark。若它不在 `PATH`：

```powershell
$env:TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"
```

检查安装：

```bash
tshark --version
```

### 2. 安装项目

```bash
git clone git@github.com:huangzekai1208/PacketMaster.git
cd PacketMaster

conda create -n packetmaster python=3.12
conda activate packetmaster
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

确认命令入口：

```bash
pkm --help
```

若系统找不到 `pkm`，可以使用等价入口：

```bash
python -m packetmaster.cli --help
```

### 3. 配置主模型

复制本地配置模板：

```bash
cp src/packetmaster/config_local.example.py src/packetmaster/config_local.py
```

Windows PowerShell：

```powershell
Copy-Item src\packetmaster\config_local.example.py src\packetmaster\config_local.py
```

编辑 `src/packetmaster/config_local.py`：

```python
MODEL_API_KEY = "填写主模型 API Key"
MODEL_BASE_URL = "https://api.deepseek.com"
MODEL_NAME = "deepseek-v4-flash"
MODEL_STRUCTURED_OUTPUT_METHOD = "auto"

# 初次部署建议先关闭 RAG，完成基础分析后再启用。
RAG_ENABLED = False
RAG_MODE = "shadow"
```

`config_local.py` 已被 Git 忽略。环境变量优先级高于该文件，适合 CI 和部署使用。不要提交真实 API Key。

## Web 工作台

启动本机 Web 服务：

```bash
pkm web
```

不自动打开浏览器：

```bash
pkm web --no-browser
```

默认地址为 <http://127.0.0.1:8765>。端口被占用时会自动尝试后续端口，以终端输出为准。

完成一次测速诊断：

1. 新建会话。
2. 保持“测速分析”模式。
3. 点击输入框左侧的 `+`，选择 `.pcap` 或 `.pcapng`。
4. 描述标准带宽、实际带宽和分析方向。
5. 核对系统提取的参数，点击“开始分析”。
6. 在“报告”“指标”“TCP 流”和“证据”中查看结果。
7. 在对话框继续追问原因、证据或排查建议。

示例输入：

```text
标准带宽 1000 Mbps，实际只有 600 Mbps，请分析下载方向。
```

Web 支持任务取消、失败重试、刷新恢复、历史会话、实时进度、处理报文数和总耗时。分析中断后，系统会从最近成功的 LangGraph 节点恢复；如果中断发生在 TShark 解析阶段，该节点会使用新任务 ID 重新执行。

## CLI 使用

### 一次性诊断

```bash
pkm diagnose samples/packetmaster_download_underperform.pcapng \
  --standard 1000 \
  --actual 20 \
  --target download \
  --output-dir artifacts/first-run \
  --keep-artifacts
```

`--target` 支持 `download`、`upload` 和 `both`，默认是 `download`。主分析不设置固定完成时限，大型 PCAP 会持续运行，直到完成、主动取消或发生资源/TShark 错误。

任务目录通常包含：

| 文件 | 内容 |
|---|---|
| `report.json` | 最终结构化诊断报告 |
| `tcp_analysis.json` | TCP、流、区间和 SYN 聚合指标 |
| `analysis.sqlite` | 本地分页证据索引 |
| `manifest.json` | 状态、告警和产物清单 |
| `coverage.json` | 报文覆盖与完整性信息 |
| `trace.jsonl` | Agent 节点执行轨迹 |
| `llm_calls.jsonl` | 脱敏 LLM 调用元数据 |

### 多轮对话

```bash
pkm chat
```

可以一次提供完整参数，也可以分轮补充。参数完整后仍需用户确认才会开始分析。

```text
请分析 /data/captures/test.pcapng，标准带宽 1 Gbps，实际 600 Mbps，分析下载方向。
```

内置命令：`/new`、`/report`、`/evidence`、`/save`、`/help`、`/quit`。

## RAG 知识库

RAG 是可选能力。推荐先以 `shadow` 模式验证检索效果，再通过正式评测启用 `active`：

```bash
export EMBEDDING_API_KEY="填写 DashScope API Key"
export EMBEDDING_MODEL="qwen3-vl-embedding"
export EMBEDDING_DIMENSION="2560"
export RAG_ENABLED=true
export RAG_MODE=shadow
```

默认检索链路：

```text
FTS5/BM25 + DashScope 向量召回
    -> RRF 融合
    -> qwen3-rerank
    -> 有界 Top-K 上下文
```

导入、审核和检查知识：

```bash
pkm knowledge import knowledge/tcp-window.md \
  --knowledge-id runbook.tcp-window \
  --title "TCP 窗口排障" \
  --type runbook \
  --authority medium_high \
  --source-name "网络排障手册"

pkm knowledge approve runbook.tcp-window:v1 --reviewer network-reviewer
pkm knowledge list --status approved
pkm knowledge health
```

运行模式：

| 模式 | 行为 |
|---|---|
| `off` | 不构建 RAG 运行时 |
| `shadow` | 执行检索，但不让知识改变诊断候选 |
| `active` | 已验证知识可以补充候选原因和建议，但不能覆盖报文证据 |

`active` 需要不少于 50 条正式脱敏样本通过评测门禁，否则自动降级为 `shadow`。知识审核、多模态 Markdown、评测、备份和恢复流程见 [RAG 使用与运维手册](docs/rag-operations.md)。

## 配置摘要

| 配置 | 用途 | 默认/建议 |
|---|---|---|
| `MODEL_API_KEY` | 主诊断模型密钥 | 必填 |
| `MODEL_BASE_URL` | OpenAI 兼容接口 | 按供应商填写 |
| `MODEL_NAME` | 主模型名称 | 按供应商填写 |
| `MODEL_STRUCTURED_OUTPUT_METHOD` | 结构化输出 | `auto` |
| `TSHARK_PATH` | TShark 可执行文件 | 自动发现 |
| `ARTIFACT_ROOT` | 分析产物目录 | `artifacts` |
| `WEB_DATABASE_PATH` | Web 会话数据库 | `artifacts/packetmaster-web.sqlite` |
| `GRAPH_CHECKPOINT_DATABASE_PATH` | 诊断检查点 | `artifacts/packetmaster-checkpoints.sqlite` |
| `KNOWLEDGE_DATABASE_PATH` | RAG 知识数据库 | `artifacts/knowledge/packetmaster-knowledge.sqlite` |
| `WEB_PORT` | Web 端口 | `8765` |

完整配置项、Windows 示例、Judge、Token 成本和路径策略见 [PacketMaster 完整操作手册](docs/packetmaster-user-guide.md)。

## 项目结构

```text
PacketMaster/
├── src/packetmaster/
│   ├── analyzer/          # TShark 真实报文与 mock 分析适配器
│   ├── application/       # 诊断应用服务
│   ├── mcp/               # MCP Server 与客户端
│   ├── prompts/           # 结构化诊断提示词
│   ├── rag/               # 导入、检索、重排、评测和 SQLite 存储
│   ├── web/               # FastAPI、会话、Worker 和构建产物
│   ├── graph.py           # LangGraph 诊断流程
│   └── cli.py             # pkm / packetmaster 命令入口
├── speed-analyze/         # TShark 流水线和聚合脚本
├── webui/                 # React + TypeScript 工作台
├── tests/                 # unit / integration / contract / performance
├── docs/                  # 使用、运维、设计和发布文档
├── samples/               # 示例和合成测试数据
└── artifacts/             # 本地运行产物（Git 忽略）
```

## 开发与验证

Python：

```bash
python -m pytest -m "not performance" -q
python -m ruff check .
```

前端：

```bash
cd webui
npm ci
npm run typecheck
npm run lint
npm test
npm run build
```

运行已构建 Web 不需要 Node.js。Vite 开发服务默认使用 <http://127.0.0.1:5173>，并将 `/api` 代理到 PacketMaster 后端。

大型 PCAP、RAG 25,000 切片容量门禁和 Windows 发布验收步骤见完整手册及 [Windows Web 发布验收清单](docs/windows-web-release-checklist.md)。

## 数据与安全边界

- 原始报文、筛选报文和 Payload 只保留在本机。
- 模型仅接收聚合摘要和有界、白名单化的分页证据。
- API Key 不写入日志、报告、Web API 响应或评测结果。
- `config_local.py`、`artifacts/`、`webui/node_modules/` 和测试缓存不应提交到 Git。
- 报文能够证明网络现象，但不能总是证明服务端内部、应用逻辑或终端性能问题；报告会标注可观测性和证据限制。

## 文档

- [完整操作手册](docs/packetmaster-user-guide.md)
- [RAG 使用与运维手册](docs/rag-operations.md)
- [Windows Web 发布验收清单](docs/windows-web-release-checklist.md)
- [系统设计](docs/superpowers/specs/2026-07-20-packetmaster-design.md)
