# PacketMaster RAG V1 使用与运维手册

更新日期：2026-07-27

## 1. 适用范围

RAG 用经过审核的 TCP 标准、厂商资料、内部手册和历史案例补充诊断原因、机制解释及处置建议。当前报文证据始终优先。原始报文、Payload、完整逐包数据、密钥、本地绝对路径和未脱敏客户信息不得进入知识库或 Embedding。

RAG 故障不会阻止基础诊断、Web 启动和无 RAG 问答。生产默认保持关闭或 `shadow`；只有正式评估通过后才能使用 `active`。

## 2. 安装与模型

基础安装不包含大型模型依赖：

```powershell
python -m pip install -r requirements.txt
```

默认且唯一的 Embedding Provider 为百炼 DashScope，默认模型为 `text-embedding-v4`、维度为 1024。配置 API Key：

```powershell
$env:EMBEDDING_API_KEY = "..."
```

DashScope 会接收已经过导入脱敏的知识切片和检索查询。确认组织允许该数据流后可显式配置：

```powershell
$env:EMBEDDING_PROVIDER = "dashscope"
$env:EMBEDDING_API_KEY = "..."
$env:EMBEDDING_MODEL = "text-embedding-v4"
# v4 的本项目默认维度为 1024；只有在已验证模型规格时才覆盖。
$env:EMBEDDING_DIMENSION = "1024"
```

默认端点为 DashScope OpenAI 兼容地址。私有网关可设置 `EMBEDDING_BASE_URL`；可用 `EMBEDDING_TIMEOUT_SECONDS` 和 `EMBEDDING_MAX_RETRIES` 调整远程调用边界。不要把 `EMBEDDING_API_KEY` 写入 Git、知识源文件或诊断报告。

## 3. 配置

```powershell
$env:KNOWLEDGE_DATABASE_PATH = "D:\PacketMaster\knowledge\packetmaster-knowledge.sqlite"
$env:RAG_ENABLED = "true"
$env:RAG_MODE = "shadow"
$env:RAG_KEYWORD_TOP_K = "20"
$env:RAG_VECTOR_TOP_K = "20"
$env:RAG_FINAL_TOP_K = "8"
$env:RAG_MAX_CONTEXT_BYTES = "24576"
$env:RAG_TIMEOUT_SECONDS = "2"
```

模式语义：

| 模式 | 检索 | 影响诊断 | 使用场景 |
| --- | --- | --- | --- |
| `off` | 否 | 否 | 基础诊断、故障隔离 |
| `shadow` | 是 | 否 | 知识质量观察、正式评估前运行 |
| `active` | 是 | 仅补充候选与建议 | 50 条以上正式评估通过后 |

请求 `active` 但知识库没有合格评估记录时，PacketMaster 自动降级到 `shadow`。不要修改数据库绕过门禁。

## 4. 知识准备和审核

支持 Markdown、UTF-8 文本和 JSON 历史案例。案例模板见 [knowledge-case.example.json](templates/knowledge-case.example.json)。导入器会脱敏常见 IP、域名、账号、工单、客户标识、密钥和路径，并标记疑似 Prompt 注入，但人工审核仍是发布前必需步骤。

导入草稿：

```powershell
pkm knowledge import ".\knowledge\tcp-window.md" `
  --knowledge-id rfc.tcp-window `
  --title "TCP 窗口机制" `
  --type standard `
  --authority high `
  --source-name "RFC" `
  --source-location "section window"
```

可用类型为 `standard`、`vendor`、`runbook`、`case`。风险内容默认拒绝导入；只有审核原文后才可使用 `--ack-risk`，该参数不等于批准发布。

本文使用短命令 `pkm`；所有示例均可把 `pkm` 替换为兼容入口 `packetmaster`。

查看草稿并人工核对：

```powershell
pkm knowledge show rfc.tcp-window
pkm knowledge list --status draft
```

审核发布会生成缺失 Embedding，然后原子更新正式版本：

```powershell
pkm knowledge approve rfc.tcp-window:v1 --reviewer network-reviewer
```

更新知识时导入 `--version 2`，不要覆盖 V1。发布 V2 后 V1 变为 `superseded`，已生成报告仍保留当时的引用快照。

停用错误或过期知识：

```powershell
pkm knowledge disable rfc.tcp-window:v1 `
  --actor network-reviewer --reason "内容已被新版标准替代"
```

## 5. 索引和健康检查

```powershell
pkm knowledge health
pkm knowledge reindex rfc.tcp-window:v1
pkm knowledge reindex rfc.tcp-window:v1 --force
```

切换模型或维度后，旧向量不会被新配置检索；对每个已发布版本运行强制重建，并重新执行正式评估。DashScope 不可用时 RAG 会降级，基础诊断继续运行。`active` 门禁不会因更换模型自动通过。

强制重建先完整生成新向量，再在一个事务中替换；中途失败保留旧索引。API 和 Worker 按索引代次刷新各自的只读缓存。

常见错误：

| 错误码 | 含义 | 处理 |
| --- | --- | --- |
| `EMBEDDING_AUTH_MISSING` | 未配置 DashScope API Key | 配置 `EMBEDDING_API_KEY` |
| `EMBEDDING_SERVICE_UNAVAILABLE` | DashScope 网络、限流或服务异常 | 检查网络、配额和服务状态后重试 |
| `RAG_DATABASE_LOCKED` | 短时写锁冲突 | 等待其他管理命令结束后重试 |
| `RAG_DATABASE_UNAVAILABLE` | DB 损坏或不可读 | 保持基础诊断，按备份恢复 |
| `RAG_CAPACITY_EXCEEDED` | 正式切片超过 25,000 | 停用冗余知识或评估 Qdrant Server |
| `RAG_RETRIEVAL_TIMEOUT` | 检索超过 2 秒 | 检查磁盘、模型和索引规模 |

## 6. 离线评估与 active 门禁

评估模板见 [rag-evaluation.example.json](templates/rag-evaluation.example.json)。正式数据集至少 50 条，每条需要人工标注相关切片、适用条件、期望原因和禁止结论。模板中的单条示例不能用于生产启用。

```powershell
pkm knowledge evaluate ".\evaluation\rag-production.json" `
  --output ".\evaluation\rag-report.json"
```

生产门槛包括：Recall@5 不低于 0.85、引用准确率和适用条件准确率不低于 0.95、原因覆盖率相对基线提升、禁止结论命中率为 0、P95 检索不超过 2 秒。未全部满足时保持 `shadow`。

## 7. 备份与恢复

知识数据库与 Web 数据库、分析产物、模型缓存具有独立生命周期。备份知识库前停止 `pkm web` 和所有 `pkm knowledge` 写命令。

```powershell
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
Copy-Item $env:KNOWLEDGE_DATABASE_PATH "$env:KNOWLEDGE_DATABASE_PATH.$stamp.bak"
```

如同目录存在 `-wal` 和 `-shm` 文件，说明仍有进程使用数据库；不要进行文件级备份。恢复时先保留损坏文件，再把已验证备份复制回原路径，执行：

```powershell
pkm knowledge health
pkm knowledge reindex <version-id> --force
```

数据库、API Key 和诊断产物不要打包进诊断报告。备份介质权限应至少与内部故障案例的敏感级别一致。

## 8. 容量和 Qdrant 迁移条件

SQLite + FTS5 + 本地向量适用于单机、只读检索为主且正式切片不超过 25,000 的 V1。满足任一条件时评估 Qdrant Server：

- 正式切片需要超过 25,000；
- Web API、Worker 分布到多台主机；
- 25,000 门禁的 P95 持续超过 2 秒；
- 需要高并发写入、在线分片或集中备份；
- 多个 PacketMaster 实例需要共享同一知识索引。

迁移通过 `KnowledgeStore` 和 Retrieval Service 接口实施，不改变 Agent、报告和引用契约。V1 不支持 Qdrant Local，也不应在未达到触发条件时提前服务化。

## 9. 发布前检查

```powershell
python -m pytest -m "not performance" -q
python -m pytest tests\performance\test_rag_capacity.py -v
python -m ruff check .
pkm knowledge health
```

Windows 真机、本地离线模型、中文路径和 Web Worker 检查见 [Windows 发布验收清单](windows-web-release-checklist.md)。
