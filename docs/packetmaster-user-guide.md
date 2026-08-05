# PacketMaster 完整操作手册

本文面向第一次接触 PacketMaster 的使用者，介绍如何从零完成环境安装、模型 API 配置、CLI 和 Web 报文分析、RAG 知识导入、审核发布、评测、备份迁移及常见故障处理。

PacketMaster 用于分析 TCP 测速不达标问题。PCAP/PCAPNG 在本机通过 TShark 流式处理，模型只接收聚合摘要和有界证据，不接收原始报文、Payload、API Key 或本机绝对路径。

## 1. 最短成功路径

如果只想尽快完成第一次分析，按以下顺序执行：

1. 安装 Python 3.11-3.13、Wireshark/TShark。
2. 在项目根目录安装 Python 依赖。
3. 创建 `src/packetmaster/config_local.py`，配置主模型 API。
4. 用 `tshark --version` 和 `pkm --help` 检查环境。
5. 执行一次 CLI 分析，或启动 `pkm web` 后选择报文。
6. 需要 RAG 时，再配置 DashScope Embedding API Key 并导入知识。

```bash
python -m pip install -r requirements.txt
cp src/packetmaster/config_local.example.py src/packetmaster/config_local.py
pkm diagnose samples/packetmaster_download_underperform.pcapng \
  --standard 1000 --actual 20 --target download \
  --output-dir artifacts/first-run --keep-artifacts
```

Windows PowerShell 使用：

```powershell
python -m pip install -r requirements.txt
Copy-Item src\packetmaster\config_local.example.py src\packetmaster\config_local.py
pkm diagnose "C:\captures\test.pcapng" `
  --standard 1000 --actual 600 --target download `
  --output-dir artifacts\first-run --keep-artifacts
```

## 2. 系统要求

### 2.1 必需软件

- Python 3.11、3.12 或 3.13；推荐 Python 3.12。
- Wireshark/TShark；正式报文分析必须使用。
- 可访问所配置的大模型 API。
- 启用 RAG 时，需要可访问阿里云百炼 DashScope。
- Node.js 20-24 仅在修改前端时需要，运行已构建 Web 不需要 Node.js。

### 2.2 安装 TShark

Windows：安装 Wireshark，并在安装向导中勾选 TShark。默认路径通常为：

```powershell
$env:TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"
```

macOS：

```bash
brew install wireshark
export TSHARK_PATH=/opt/homebrew/bin/tshark
```

Ubuntu/Debian：

```bash
sudo apt update
sudo apt install tshark
```

检查安装：

```bash
tshark --version
```

如果 `tshark` 不在 PATH，通过环境变量指定实际可执行文件路径。

## 3. 创建 Python 环境并安装项目

推荐使用 Conda：

```bash
conda create -n packetmaster python=3.12
conda activate packetmaster
cd /path/to/SpeedAnalyzeAgent
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` 会一次性安装核心运行依赖、RAG/评测依赖和 Python 开发测试工具，不需要再单独执行 `pip install -e ".[rag]"`。其中包括 FastAPI、FastMCP、LangChain、LangGraph、Scapy、Pydantic、TShark 调用辅助库、`numpy`、pytest 和 Ruff。

前端依赖不属于 Python 包，无法写入 `requirements.txt`。运行仓库中已经构建好的 Web 页面不需要安装前端依赖；只有修改或重新构建前端时，才需要在 `webui/` 中执行 `npm ci`。

检查命令入口：

```bash
pkm --help
```

如果系统找不到 `pkm`，可以始终使用等价命令：

```bash
python -m packetmaster.cli --help
```

## 4. 配置 API 和运行参数

PacketMaster 支持两种配置方式：

- `src/packetmaster/config_local.py`：适合个人开发机长期使用，已被 Git 忽略。
- 环境变量：适合临时测试、CI 和部署，优先级高于本地配置文件。

不要提交真实 API Key，也不要把 Key 写入 Markdown、评测集或报文描述。

### 4.1 创建本地配置文件

macOS/Linux：

```bash
cp src/packetmaster/config_local.example.py src/packetmaster/config_local.py
```

Windows PowerShell：

```powershell
Copy-Item src\packetmaster\config_local.example.py src\packetmaster\config_local.py
```

推荐的基础配置：

```python
# src/packetmaster/config_local.py

# 主诊断模型：使用 OpenAI 兼容接口。
MODEL_API_KEY = "填写主模型API-Key"
MODEL_BASE_URL = "https://api.deepseek.com"
MODEL_NAME = "deepseek-v4-flash"
MODEL_STRUCTURED_OUTPUT_METHOD = "auto"

# RAG Embedding：阿里云百炼 DashScope。
EMBEDDING_API_KEY = "填写DashScope-API-Key"

# Reranker 默认复用 EMBEDDING_API_KEY；使用不同凭据时再启用此项。
# RERANK_API_KEY = "填写单独的DashScope-API-Key"

# 初次部署建议先使用 shadow，评测通过后再改为 active。
RAG_ENABLED = True
RAG_MODE = "shadow"
RAG_KEYWORD_TOP_K = 20
RAG_VECTOR_TOP_K = 20
RERANKER_ENABLED = True
RERANKER_CANDIDATE_TOP_K = 20
RAG_FINAL_TOP_K = 8
```

如果暂时不使用知识库：

```python
RAG_ENABLED = False
RAG_MODE = "shadow"
```

### 4.2 主模型配置

主要配置项：

| 配置 | 说明 | 默认值/建议 |
|---|---|---|
| `MODEL_API_KEY` | 主模型密钥 | 必填 |
| `MODEL_BASE_URL` | OpenAI 兼容接口地址 | 按供应商填写 |
| `MODEL_NAME` | 模型名称 | 当前示例为 `deepseek-v4-flash` |
| `MODEL_STRUCTURED_OUTPUT_METHOD` | 结构化输出方式 | 推荐 `auto` |
| `MODEL_TIMEOUT_SECONDS` | 模型超时秒数 | 120 |

`auto` 对 DeepSeek 兼容服务使用 `json_mode`，其他服务默认使用 `json_schema`。如果持续出现 `INVALID_MODEL_OUTPUT`，先确认模型支持结构化 JSON，再尝试显式配置 `json_mode` 或 `function_calling`。

### 4.3 Embedding 配置

当前 RAG 默认使用百炼原生多模态模型：

```text
EMBEDDING_PROVIDER=dashscope
EMBEDDING_MODEL=qwen3-vl-embedding
EMBEDDING_DIMENSION=2560
```

环境变量示例：

```bash
export EMBEDDING_API_KEY="填写DashScope-API-Key"
export EMBEDDING_MODEL="qwen3-vl-embedding"
export EMBEDDING_DIMENSION="2560"
```

更换 Embedding 模型或向量维度后，旧向量不能继续混用，需要对所有已发布知识执行强制重建索引。

### 4.4 Reranker 配置

默认使用百炼 `qwen3-rerank`：

```bash
export RERANKER_ENABLED=true
export RERANKER_MODEL=qwen3-rerank
export RERANKER_CANDIDATE_TOP_K=20
export RAG_FINAL_TOP_K=8
```

检索链路为：

```text
BM25 Top 20 + 向量 Top 20 -> RRF 融合 -> qwen3-rerank Top 20 -> 最终 Top 8
```

Reranker 默认复用 `EMBEDDING_API_KEY`。超时、限流或服务异常时会自动降级到 RRF 结果，不会中断主对话。

使用独立 Reranker Key 时需要注意命名：`config_local.py` 中使用 `RERANK_API_KEY`，环境变量使用 `RERANKER_API_KEY`。

```bash
export RERANKER_API_KEY="填写单独的DashScope-API-Key"
```

### 4.5 LLM Judge 配置

Judge 主要用于高级 RAG 回答评测，普通分析不要求开启：

```bash
export JUDGE_ENABLED=true
export JUDGE_API_KEY="填写DashScope-API-Key"
export JUDGE_MODEL=qwen-plus
export JUDGE_MODEL_REVISION="填写固定模型版本"
```

生产评测应固定 `JUDGE_MODEL_REVISION`，避免模型更新后结果无法复现。

### 4.6 Token 和成本配置

模型返回 Token usage 时，PacketMaster 会自动记录。配置每百万 Token 单价后才能估算成本：

```bash
export MODEL_INPUT_COST_PER_MILLION_USD=0.28
export MODEL_OUTPUT_COST_PER_MILLION_USD=0.42
export LLM_OBSERVABILITY_ENABLED=true
```

Provider 不返回 usage 时显示“未知”，系统不会根据字符数估算。

### 4.7 路径和 Web 配置

常用环境变量：

```bash
export ARTIFACT_ROOT=artifacts
export WEB_DATABASE_PATH=artifacts/packetmaster-web.sqlite
export KNOWLEDGE_DATABASE_PATH=artifacts/knowledge/packetmaster-knowledge.sqlite
export WEB_PORT=8765
```

Web 只允许监听 `127.0.0.1`。路径注册 API 默认只允许访问项目当前目录；浏览器文件选择上传不受此限制，文件会复制到 `artifacts/web-captures/`。

## 5. 启动前检查

依次执行：

```bash
python --version
tshark --version
pkm --help
pkm knowledge health
```

检查主模型配置是否被读取，但不要打印密钥：

```bash
python -c "from packetmaster.config import Settings; s=Settings.load(); print(s.model_name, s.model_base_url, s.model_api_key is not None)"
```

检查 Embedding 配置是否完整：

```bash
python -c "from packetmaster.config import Settings; s=Settings.load(); print(s.embedding_model, s.embedding_dimension, s.embedding_api_key is not None)"
```

## 6. 使用 CLI 一次性分析报文

### 6.1 参数含义

- `PCAP_PATH`：`.pcap` 或 `.pcapng` 文件。
- `--standard`：标准/签约带宽，单位 Mbps。
- `--actual`：实际测速带宽，单位 Mbps。
- `--target`：`download`、`upload` 或 `both`，默认 `download`。
- `--output-dir`：报告和分析产物目录。
- `--keep-artifacts`：标记产物为保留，避免过期清理。

主报文分析默认不设置完成时限。大型 PCAP 会持续处理，直到分析完成、用户主动取消、Worker 退出或发生磁盘/内存/TShark 错误。模型、RAG、Reranker 和分页证据查询仍保留各自独立的网络或查询超时。

下载方向示例：

```bash
pkm diagnose /data/captures/test.pcapng \
  --standard 1000 \
  --actual 600 \
  --target download \
  --output-dir artifacts/test-download \
  --keep-artifacts
```

Windows：

```powershell
pkm diagnose "D:\captures\测速报文.pcapng" `
  --standard 1000 `
  --actual 600 `
  --target download `
  --output-dir artifacts\test-download `
  --keep-artifacts
```

上行和双向：

```bash
pkm diagnose test.pcapng --standard 1000 --actual 300 --target upload
pkm diagnose test.pcapng --standard 1000 --actual 300 --target both
```

### 6.2 查看结果

终端会打印诊断摘要，并输出 `report.json` 路径。任务目录通常包含：

```text
report.json            最终结构化报告
tcp_analysis.json      TCP 聚合指标
analysis.sqlite        分页证据数据库
manifest.json          任务清单
coverage.json          报文覆盖信息
trace.jsonl            Agent 执行轨迹
llm_calls.jsonl        LLM 调用元数据
```

命令退出码：

- `0`：成功。
- `2`：已识别的可操作错误，终端返回结构化错误 JSON。
- `1`：未分类 CLI 错误。

## 7. 使用 CLI 多轮对话

启动：

```bash
pkm chat
```

可以一次给出完整参数：

```text
请分析 /data/captures/test.pcapng，标准带宽 1Gbps，实际 600Mbps，分析下载方向。
```

也可以分轮补充：

```text
我想分析一个测速报文。
/data/captures/test.pcapng
标准带宽 1000Mbps，实际 600Mbps。
```

参数完整后，系统会要求确认。输入 `y`、`yes`、`是` 或 `确认` 才会启动分析。

内置命令：

| 命令 | 作用 |
|---|---|
| `/new` | 新建会话/任务 |
| `/report` | 查看当前诊断报告 |
| `/evidence` | 查看关键证据 |
| `/save` | 查看 JSON 报告路径 |
| `/help` | 查看帮助 |
| `/quit` | 退出 |

分析完成后可以继续追问，例如：

```text
为什么零窗口会限制吞吐？
哪些证据支持当前主因？
下一步应该在哪一端继续排查？
```

普通对话和诊断后追问都会尝试使用 RAG；RAG 不可用时会降级，但基础对话仍可继续。

## 8. 使用 Web 工作台分析报文

### 8.1 启动 Web

```bash
pkm web
```

不自动打开浏览器：

```bash
pkm web --no-browser
```

默认访问：

```text
http://127.0.0.1:8765
```

如果端口被占用，PacketMaster 会尝试后续本机端口，以终端打印的实际地址为准。

### 8.2 完成一次 Web 分析

1. 点击左侧“新建会话”。
2. 点击输入框左侧的 `+`，选择 `.pcap` 或 `.pcapng`。
3. 在输入框描述标准带宽、实际带宽和分析方向。
4. 点击发送。
5. 检查系统提取的参数，确认无误后点击“开始分析”。
6. 在对话区观察实时进度、阶段、已处理报文数和耗时。
7. 分析完成后，对话框显示总耗时和处理报文数。
8. 使用“报告”“指标”“TCP 流”“证据”标签查看详细结果。
9. 在对话框继续追问当前分析结论。

Web 支持取消、失败重试、刷新后恢复、历史会话删除和会话自动命名。

### 8.3 Web 中的 RAG 状态

使用知识时，回答下方会显示：

- `RAG 已使用` 或 `RAG 已降级`；
- 引用知识标题；
- `chunk_id`；
- Reranker 相关度分数。

RAG 降级不等于主模型失败。常见降级原因包括知识库不可用、active 门禁未通过、Embedding 超时和 Reranker 超时。

### 8.4 Web 中的 Token、成本和错误

顶部“模型用量”每 2 秒刷新，包含输入/输出 Token、调用次数、失败、重试和估算成本。

分析失败、部分完成或中断时，对话区显示错误码、错误原因、恢复建议和受控技术详情。为保护数据，不显示 API Key、绝对路径、原始报文、Payload 或完整堆栈。

## 9. RAG 模式和检索逻辑

配置：

```bash
export RAG_ENABLED=true
export RAG_MODE=shadow
```

模式含义：

| 模式 | 行为 |
|---|---|
| `off` | 完全不构建 RAG 运行时 |
| `shadow` | 执行检索，但不让知识改变诊断候选，适合上线前验证 |
| `active` | 知识可以补充候选原因和建议，但不能覆盖报文证据 |

`RAG_ENABLED=false` 时，无论 `RAG_MODE` 如何配置，实际模式都是 `off`。

`active` 必须通过正式评测门禁。未通过时系统自动降级为 `shadow`，原因通常为 `RAG_ACTIVE_GATE_NOT_PASSED`。

## 10. 知识文件准备

支持：

- `.md`、`.markdown`
- `.txt`
- `.json` 案例
- UTF-8 编码
- 单文件最大 5 MiB
- 单个文档最多 512 个切片

默认切片规则：目标约 800 字符、最大 1500 字符、相邻长切片重叠 100 字符。Markdown 优先按标题和段落组织切片。

建议知识结构：

```markdown
# TCP 零窗口排障

## 现象

接收端持续通告接收窗口为零，发送端停止发送新的有效载荷。

## 判断条件

- 检查零窗口事件是否持续出现；
- 确认受影响流和方向；
- 同时检查接收端应用读取速度。

## 处置建议

检查接收端应用、Socket 缓冲区和系统资源。
```

知识中不要包含 API Key、密码、原始 Payload、客户身份信息或本机绝对路径。

## 11. CLI 导入、审核和发布知识

### 11.1 元数据选项

知识类型：

- `standard`：RFC、正式协议标准。
- `vendor`：厂商官方文档。
- `runbook`：排障手册、教程。
- `case`：脱敏历史案例。

权威级别：

- `high`：正式标准或经过严格审核的内部规范。
- `medium_high`：厂商官方资料、高质量内部手册。
- `medium`：一般排障手册或技术文章。
- `low`：低可信来源，只适合作为线索。

### 11.2 导入草稿

```bash
pkm knowledge import knowledge/tcp-zero-window.md \
  --knowledge-id runbook.tcp-zero-window \
  --title "TCP 零窗口排障" \
  --type runbook \
  --authority medium_high \
  --source-name "网络排障手册" \
  --source-location "TCP/窗口" \
  --language zh-CN \
  --summary "零窗口识别、证据和处置建议" \
  --version 1
```

导入只保存草稿，不会直接进入在线检索。命令会显示切片数量、警告和风险标记。

如果内容触发 Prompt 注入等风险标记，必须人工检查原文，然后显式确认：

```bash
pkm knowledge import knowledge/tcp-zero-window.md ... --ack-risk
```

`--ack-risk` 不是忽略风险，而是记录操作者已经审核。

### 11.3 查看草稿和版本

```bash
pkm knowledge list
pkm knowledge list --status draft
pkm knowledge list --status approved
pkm knowledge show runbook.tcp-zero-window
```

### 11.4 审核发布

版本 ID 由知识 ID 和版本号组成：

```text
runbook.tcp-zero-window:v1
```

发布命令：

```bash
pkm knowledge approve runbook.tcp-zero-window:v1 \
  --reviewer network-reviewer
```

发布时会调用 Embedding API 为切片建立向量索引。成功后该版本状态变为 `approved`，旧版本会按版本规则处理。

### 11.5 发布新版本

修订知识后使用同一个 `knowledge-id` 和递增版本号：

```bash
pkm knowledge import knowledge/tcp-zero-window-v2.md \
  --knowledge-id runbook.tcp-zero-window \
  --title "TCP 零窗口排障" \
  --type runbook \
  --authority medium_high \
  --source-name "网络排障手册" \
  --version 2

pkm knowledge approve runbook.tcp-zero-window:v2 \
  --reviewer network-reviewer
```

不要使用新 `knowledge-id` 代替正常版本升级，否则会产生重复知识。

### 11.6 停用和重建索引

停用错误知识：

```bash
pkm knowledge disable runbook.tcp-zero-window:v2 \
  --actor network-reviewer \
  --reason "内容需要重新审核"
```

重建单个版本索引：

```bash
pkm knowledge reindex runbook.tcp-zero-window:v2 --force
```

更换 Embedding 模型后，需要对每个已发布版本执行 `--force` 重建，并重新评测。

### 11.7 检查知识库健康

```bash
pkm knowledge health
```

正常输出应包含 FTS5 可用、文档数、已发布数和索引代次。

## 12. Markdown 图片和多模态入库

CLI 支持 Markdown 相对图片：

```text
knowledge/
├── tcp-window.md
└── images/
    ├── zero-window.png
    └── window-scale.jpg
```

Markdown：

```markdown
## 零窗口示例

![Wireshark 零窗口截图](images/zero-window.png)
```

然后按普通 CLI 流程导入和审核发布。图片与所在章节首个切片正文会联合发送给 `qwen3-vl-embedding`。

图片限制：

- 支持 PNG、JPEG、WebP；
- 单图最大 5 MiB；
- 只允许 Markdown 所在目录或子目录中的相对路径；
- 不导入远程 URL、绝对路径、`data:` 图片或越出目录的引用；
- 文件扩展名、MIME 和实际内容必须匹配。

Web 浏览器导入只上传所选文本文件内容，不能同时读取本机图片目录。带图片的 Markdown 必须使用 CLI 导入。

## 13. 在 Web 中管理知识

1. 启动 `pkm web`。
2. 点击右上角“知识库”。
3. 点击导入并选择 `.md`、`.markdown`、`.txt` 或 `.json`。
4. 系统根据文件名自动填写知识 ID、标题、来源等信息。
5. 人工检查并按需修改元数据。
6. 执行预览，检查切片、警告和风险提示。
7. 保存为草稿。
8. 由审核人点击审核发布；发布时会建立向量索引。
9. 在版本列表中可停用或重建索引。

Web 还会显示最后一次正式评测和 active 门禁状态。

## 14. 构建 RAG 评测集并运行评测

正式评测集至少 50 条，并且必须脱敏。每条样本需要标注相关切片 ID。

最小样例：

```json
[
  {
    "case_id": "eval.tcp.001",
    "query": {
      "query_id": "eval.tcp.001",
      "query_text": "零窗口为什么会限制吞吐？",
      "keywords": ["零窗口", "吞吐"],
      "candidate_causes": ["接收端零窗口"],
      "knowledge_types": ["runbook"]
    },
    "relevant_chunk_ids": [
      "runbook.tcp-zero-window:v1:chunk-0"
    ],
    "relevance_grades": {
      "runbook.tcp-zero-window:v1:chunk-0": 3
    },
    "expected_causes": ["接收端零窗口"],
    "baseline_causes": [],
    "rag_causes": ["接收端零窗口"],
    "answer_citation_chunk_ids": [
      "runbook.tcp-zero-window:v1:chunk-0"
    ],
    "applicable_chunk_ids": [
      "runbook.tcp-zero-window:v1:chunk-0"
    ],
    "forbidden_conclusions": ["发送端带宽不足"]
  }
]
```

运行：

```bash
pkm knowledge evaluate evaluation/my-rag-evaluation.json \
  --output evaluation/my-rag-report.json
```

当前 active 基础门槛：

- 样本数不少于 50；
- Recall@5 不低于 0.85；
- 引用准确率不低于 0.95；
- 适用性准确率不低于 0.95；
- RAG 原因覆盖率必须高于无 RAG 基线；
- 不支持结论率必须为 0；
- P95 检索延迟不高于 2 秒。

知识内容、切片、Embedding 模型、Reranker 模型或检索参数发生变化后，旧评测结论不能直接代表新配置，应重新评测。

## 15. 启用 active RAG

推荐流程：

1. `RAG_MODE=shadow` 导入并发布知识。
2. 准备不少于 50 条人工标注样本。
3. 执行 `pkm knowledge evaluate`。
4. 确认报告中 `production_ready=true`。
5. 将配置改为 `RAG_MODE=active`。
6. 重启 CLI 或 Web 服务。
7. 在 Web 中检查 RAG 状态和引用。

```python
RAG_ENABLED = True
RAG_MODE = "active"
```

如果仍显示 `RAG_ACTIVE_GATE_NOT_PASSED`，先确认评测使用的是当前知识库中的实际 `chunk_id`，并检查最后一次评测是否达到全部门槛。

## 16. LLM 调用可观测性

全局记录：

```text
artifacts/llm-observability/llm_calls.jsonl
```

单个诊断任务记录：

```text
artifacts/<任务ID>/llm_calls.jsonl
```

汇总 API：

```bash
curl http://127.0.0.1:8765/api/llm-observability/summary
```

记录包括模型、调用类型、Prompt 哈希、输出 Schema、结构化方式、延迟、重试、错误码、Token usage 和估算成本。

记录不包含 Prompt 正文、用户问题、模型回答、API Key、原始报文、Payload 或绝对路径。

## 17. 数据目录、备份和迁移

重要目录：

```text
artifacts/knowledge/packetmaster-knowledge.sqlite  知识、切片和向量索引
artifacts/packetmaster-web.sqlite                  Web 会话和任务记录
artifacts/web-captures/                           Web 上传的报文副本
artifacts/<任务ID>/                               报告、证据和轨迹
src/packetmaster/config_local.py                  本机密钥配置
```

迁移到另一台电脑时，推荐通过 Git 获取代码，然后单独安全复制：

```text
src/packetmaster/config_local.py
artifacts/knowledge/
```

需要保留 Web 历史时，再复制 `artifacts/packetmaster-web.sqlite`、`artifacts/web-captures/` 和对应任务目录。旧 Web 数据库中的报文路径可能指向原电脑，迁移后应重新上传无法读取的报文。

备份前先停止 Web 服务，避免复制到正在写入的 SQLite 数据库。不要只复制 SQLite 的 `-wal` 文件；优先在服务停止后复制数据库主文件和同目录资源。

## 18. 常见故障排查

### 18.1 找不到 `pkm`

```bash
python -m pip install -r requirements.txt
python -m packetmaster.cli --help
```

确认当前终端已经激活安装项目的 Python 环境。

### 18.2 找不到 TShark

现象：`TSHARK_UNAVAILABLE` 或系统提示找不到 `tshark`。

处理：

```bash
export TSHARK_PATH=/actual/path/to/tshark
```

Windows：

```powershell
$env:TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"
```

### 18.3 分析长时间停在某个阶段

主报文分析没有动态时限，大报文在 `Writing filtered captures`、聚合或证据索引阶段可能运行较长时间。先观察 Web 进度，并检查：

```bash
tail -n 50 artifacts/<任务ID>/progress.jsonl
tail -n 100 artifacts/<任务ID>/logs/pipeline.log
```

同时检查 CPU、内存、剩余磁盘空间和 TShark 进程。如果确认进程卡死，应通过 Web“取消分析”停止任务，不要直接删除正在写入的任务目录。

### 18.4 主模型鉴权或连通失败

检查：

- `MODEL_API_KEY` 是否属于当前 Provider；
- `MODEL_BASE_URL` 是否是 OpenAI 兼容入口；
- `MODEL_NAME` 是否存在；
- 当前网络是否允许访问该服务。

不要通过打印完整 Settings 或日志来检查密钥。

### 18.5 `INVALID_MODEL_OUTPUT`

模型连续两次未返回符合 Schema 的 JSON。处理顺序：

1. 重试一次，排除偶发输出异常；
2. 确认模型支持 JSON/结构化输出；
3. DeepSeek 优先使用 `auto` 或 `json_mode`；
4. 检查是否误用了不支持结构化输出的模型；
5. 查看 `llm_calls.jsonl` 中的错误码、尝试次数和耗时。

### 18.6 RAG 已降级

先执行：

```bash
pkm knowledge health
```

再检查：

- `EMBEDDING_API_KEY` 是否配置；
- 知识是否已经 `approved`；
- 当前 Embedding 模型和索引模型是否一致；
- `active` 门禁是否通过；
- Web 引用区域是否显示 `RERANK_TIMEOUT`、`RAG_RETRIEVAL_FAILED` 等原因。

### 18.7 Reranker 失败

Reranker 失败会自动回退 RRF。检查 `RERANKER_MODEL`、有效 API Key、百炼配额和 1.5 秒默认超时。网络较慢时可适当提高：

```bash
export RERANKER_TIMEOUT_SECONDS=5
```

### 18.8 更换 Embedding 模型后检索异常

对每个已发布版本执行：

```bash
pkm knowledge reindex <version-id> --force
```

然后重新运行正式评测。旧向量索引不能与新模型或新维度混用。

### 18.9 Web 页面未更新

如果修改了 `webui/src/`，重新构建并重启后端：

```bash
cd webui
npm ci
npm run build
cd ..
pkm web --no-browser
```

必要时在浏览器执行强制刷新。

### 18.10 数据库锁定

确认没有多个进程同时维护同一个知识数据库。停止重复的 Web/CLI 进程后重试，不要直接删除数据库或 WAL 文件。

## 19. 前端开发和测试

只运行已构建 Web 不需要此步骤。修改 React 前端时：

```bash
cd webui
npm ci
npm run dev
```

Vite 默认运行在 `http://127.0.0.1:5173`，将 `/api` 代理到 `http://127.0.0.1:8765`。

生产构建：

```bash
npm run build
```

基础验证：

```bash
python -m pytest -m "not performance" -q
python -m ruff check .

cd webui
npm test -- --run
npm run build
```

## 20. 新手验收清单

完成部署后逐项确认：

- [ ] `python --version` 为 3.11-3.13。
- [ ] `tshark --version` 成功。
- [ ] `pkm --help` 成功。
- [ ] 主模型 Key、地址和模型名已配置。
- [ ] 使用示例或真实报文完成一次 CLI 分析。
- [ ] `report.json` 成功生成。
- [ ] `pkm web` 可以打开工作台。
- [ ] Web 可以上传报文、确认参数并完成分析。
- [ ] Web 能显示报告、指标、TCP 流、证据和总耗时。
- [ ] 需要 RAG 时，Embedding Key 已配置。
- [ ] `pkm knowledge health` 正常。
- [ ] 至少一份知识完成草稿、审核和发布。
- [ ] Web 回答显示 RAG 状态、知识标题、`chunk_id` 和相关度。
- [ ] 正式 active 使用前已经完成不少于 50 条评测。
- [ ] 已制定 `config_local.py` 和知识数据库的安全备份策略。
