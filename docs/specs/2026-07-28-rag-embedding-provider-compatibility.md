# RAG Embedding Provider Compatibility Design

日期：2026-07-28

## 1. 目标

PacketMaster 的 RAG 仅支持阿里云百炼 DashScope 的 `text-embedding-v4` 外部模型。

调用方、索引器和检索器只依赖既有 `EmbeddingProvider` 协议。Provider 的选择不改变知识导入、审核、发布、检索或 active 门禁语义。

## 2. 配置契约

新增或调整以下环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `EMBEDDING_PROVIDER` | `dashscope` | 固定为 `dashscope` |
| `EMBEDDING_MODEL` | `text-embedding-v4` | 可显式覆盖为百炼已验证模型 |
| `EMBEDDING_DIMENSION` | `1024` | 用于索引身份和输出校验 |
| `EMBEDDING_API_KEY` | 空 | DashScope API Key，Secret，不出现在日志或 Settings dump 中 |
| `EMBEDDING_BASE_URL` | `https://dashscope.aliyuncs.com/compatible-mode/v1` | DashScope OpenAI 兼容 API 根地址 |
| `EMBEDDING_TIMEOUT_SECONDS` | `15` | 单个远程请求的超时，范围 1-60 秒 |
| `EMBEDDING_MAX_RETRIES` | `2` | 仅网络、429 和 5xx 的额外尝试次数，范围 0-5 |

缺少 `EMBEDDING_API_KEY` 时，Provider 必须抛出 `EMBEDDING_AUTH_MISSING`。发生远程鉴权、网络、限流或服务错误时，RAG 直接降级，基础诊断继续运行。

## 3. Provider 行为

### 3.1 DashScope

DashScope Provider 向 `{EMBEDDING_BASE_URL}/embeddings` 发起 HTTPS `POST`，请求体包含 `model` 和输入文本数组，鉴权使用 `Authorization: Bearer <API Key>`。它不添加 E5 特有前缀，并要求响应按输入顺序返回等量 embedding。

Provider 对每个向量执行有限值、非零范数和预期维度校验。认证/权限错误映射为 `EMBEDDING_AUTH_FAILED`；可恢复的网络、限流和服务端失败映射为 `EMBEDDING_SERVICE_UNAVAILABLE`；协议或输出不合法映射为 `INVALID_EMBEDDING_OUTPUT`。错误详情不得包含 API Key 或完整嵌入文本。

远程 Provider 只接收已通过既有导入脱敏和检索白名单的数据。部署方必须确认允许将这些知识切片和用户查询发送至百炼。

## 4. 索引与迁移语义

知识向量的身份仍是 `(model_name, dimension)`。`SQLiteKnowledgeStore` 仅检索当前 Provider 身份的向量，因此：

1. 变更模型或维度后，应对已批准版本运行 `pkm knowledge reindex <version-id> --force`；
2. 再次执行评估。`active` 门禁不因换模型而自动通过；
3. 外部索引或检索失败时，基础诊断与 Web 启动继续降级运行。

## 5. 构造边界

RAG CLI 的 `approve`、`reindex`、`evaluate` 和 Web/诊断运行时均使用 `build_embedding_provider(settings)`，并以 Provider 报告的模型名和维度初始化 Store。

## 6. 验收标准

- `dashscope` 使用正确 URL、Bearer 鉴权、模型和输入，且保留响应顺序；
- 缺少密钥、HTTP 401/403、429/5xx、超时、畸形 JSON、结果数量不符和维度不符都有稳定错误码；
- CLI 与运行时都通过同一个 Provider 工厂创建 Store；
- API Key、端点以外的敏感配置和知识正文不进入异常详情或序列化 Settings；
- 运维手册说明 DashScope 配置、换模型和重建索引步骤。
