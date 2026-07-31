# 本地多模态 Embedding 与安全切换设计

日期：2026-07-31

状态：已确认，待实施

关联文档：

- `docs/specs/2026-07-27-packetmaster-rag-v1-design.md`
- `docs/specs/2026-07-28-rag-embedding-provider-compatibility.md`
- `docs/rag-operations.md`

## 1. 背景

PacketMaster 当前使用 DashScope `qwen3-vl-embedding` 为文本和 Markdown 图片知识生成向量。Provider 已通过 `EmbeddingProvider` 协议隔离，但配置、知识库和运行时仍假定只有一个活动模型：

- `Settings.embedding_provider` 固定为 `dashscope`；
- `knowledge_embeddings` 以 `chunk_id` 为主键，每个切片只能保留一份向量；
- RAG 运行时在进程启动时创建 Provider 和 Store；
- 发布完整性与 active 评估门禁没有绑定完整的 Embedding 配置身份。

新增本地模型后，如果直接修改模型名或维度并重建，会覆盖现有向量，造成切换期间不可检索、无法快速回滚，并可能错误复用旧评估结果。

## 2. 已确认决策

1. 外部和本地 Embedding 均受支持，由用户选择。
2. 本地基线模型为 `bge-visualized-m3`。
3. 本地模型运行在独立服务进程中，PacketMaster 不在 Web API 或分析 Worker 内加载模型权重。
4. 纯 CPU 是必须支持的正式运行路径；CUDA 和 Apple MPS 属于可选加速路径。
5. 模型切换采用“注册 -> 连接检查 -> 重建 -> 评测 -> 激活”，不得选择后立即影响生产检索。
6. 新旧索引并存；激活是原子操作，失败时旧 Profile 持续服务。
7. 应用不会因用户在 Web 中选择本地模式而自动下载模型权重。

## 3. 目标

- 提供统一的 Embedding Profile，描述外部 DashScope 和本地 HTTP 服务。
- 支持同一知识切片保存多套向量，模型切换期间不覆盖当前活动索引。
- 支持对候选 Profile 全量重建、断点续作、覆盖率检查和独立评测。
- 只有索引完整且正式评测通过的候选 Profile 才能激活。
- 在 Web、CLI、Web API 和分析 Worker 之间一致感知活动 Profile。
- 本地服务支持文本查询、文本知识和图文联合知识输入。
- 缺少 DashScope Key 不影响本地模式；本地服务不可用不影响基础报文诊断。
- 不在日志、API 错误、评测报告或数据库中保存 API Key、完整图片 Data URL 或模型访问令牌。

## 4. 非目标

- 首版不支持多个本地模型同时驻留显存或内存。
- 首版不自动下载、更新或删除模型权重。
- 首版不提供模型微调、量化训练或向量蒸馏。
- 首版不把本地服务暴露到非 loopback 地址。
- 首版不迁移到 Qdrant；仍使用 SQLite、FTS5 和内存向量检索。
- 首版不承诺所有 CPU 上的固定延迟 SLA，必须提供基准结果和可配置超时。
- 首版不允许绕过评测门禁强制激活不完整索引。

## 5. Embedding Profile

### 5.1 Profile 字段

每个 Profile 至少包含：

| 字段 | 说明 |
| --- | --- |
| `profile_id` | 稳定公开 ID，不包含密钥 |
| `display_name` | Web 和 CLI 展示名称 |
| `provider_kind` | `dashscope` 或 `local_http` |
| `model_name` | 服务报告的模型名称 |
| `model_revision` | 锁定的模型 revision；不得仅使用浮动 latest |
| `dimension` | 由远程响应或本地 capabilities 探测并校验 |
| `modalities` | 至少包含 `text`，可包含 `image_text` |
| `normalization` | 当前固定为 `l2` |
| `endpoint` | 外部或 loopback 服务地址，不包含凭据 |
| `credential_ref` | 可选环境变量名称，不保存凭据值 |
| `fingerprint` | 对检索语义有影响字段的确定性哈希 |
| `status` | `candidate`、`active`、`retired` |

`fingerprint` 至少覆盖 provider、model、revision、dimension、modalities、预处理版本、聚合策略和 normalization。只要其中任一项改变，就视为新的向量空间。

### 5.2 默认 Profile

- 外部：`dashscope-qwen3-vl`，沿用当前 DashScope 配置。
- 本地：`local-bge-visualized-m3`，默认端点为 `http://127.0.0.1:8790`。
- 升级已有数据库时，将现有模型和维度注册为 legacy Profile，并保持为活动 Profile，不能自动切到本地。

## 6. 本地服务契约

### 6.1 进程边界

本地服务作为独立可执行入口运行，例如：

```text
packetmaster-embedding-server serve \
  --model BAAI/bge-visualized-m3 \
  --revision <locked-revision> \
  --device cpu \
  --host 127.0.0.1 \
  --port 8790
```

模型目录可显式配置。离线模式下只允许读取本地缓存，缺少权重时启动失败并给出可执行建议。PacketMaster Web 只连接服务，不负责拉取权重。

### 6.2 HTTP API

- `GET /health`：仅说明进程存活和模型是否 ready。
- `GET /v1/capabilities`：返回 model、revision、dimension、modalities、normalization、preprocessing_version、device、dtype、max_batch_size。
- `POST /v1/embeddings`：按输入顺序返回等量向量。

请求示例：

```json
{
  "input_type": "document",
  "inputs": [
    {
      "text": "TCP 零窗口会限制发送端继续发送数据。",
      "images": [
        {
          "mime_type": "image/png",
          "data_base64": "..."
        }
      ]
    }
  ]
}
```

`input_type` 只允许 `query` 或 `document`。查询首版只接受文本；文档可接受文本或图文。服务必须拒绝空输入、未知 MIME、超限图片、超限批量和维度异常。

### 6.3 图文语义

- 纯文本切片使用模型的文本编码路径。
- 带一张图片的切片使用模型官方支持的图文联合编码路径。
- 带多张图片的切片分别生成“正文 + 单图”向量，再做均值和 L2 归一化，保持与当前 DashScope 行为一致。
- 文本查询生成与文档向量位于同一空间的 query 向量。
- 正文拼接、图片缩放、颜色空间和多图聚合规则写入 `preprocessing_version`，规则改变必须产生新 fingerprint。

模型实际输出维度、官方推理包、CPU dtype 和 revision 在实施任务 1 中用真实模型探测后锁定；配置不得预设未经验证的维度。

### 6.4 CPU 基线

- `--device cpu` 必须可启动、预热并完成文本与图文请求。
- CPU 默认使用兼容性优先的 dtype；低精度或量化作为显式可选项，不改变默认结果。
- 服务启动后执行一次文本和一次最小图文预热，再将 ready 置为 true。
- 批量大小、线程数、请求队列长度和超时可配置，并有保守默认值。
- 提供 benchmark 命令，报告模型加载时间、峰值 RSS、文本 warm latency、图文 warm latency和吞吐，不上传样本内容。

## 7. 数据库与索引身份

数据库升级后，`knowledge_embeddings` 的逻辑主键改为 `(chunk_id, profile_id)`。每条向量同时保存：

- `profile_id` 和 `profile_fingerprint`；
- model、revision、dimension；
- vector、content_hash 和 created_at。

新增：

- `embedding_profiles`：Profile 定义与状态；
- `embedding_rebuild_jobs`：重建进度、目标 Profile、总切片、已完成切片、错误和时间；
- 按 Profile 保存的评测报告及门禁结果；
- `active_embedding_profile_id` 和 `embedding_profile_generation` 元数据。

发布知识版本时必须检查“当前活动 Profile”对应的向量完整性，不能把任意旧模型向量视为完整。为候选 Profile 重建时只新增或更新目标 Profile 的向量，不修改活动 Profile。

## 8. 重建、评测与激活

状态流：

```text
注册候选 Profile
  -> capabilities 与最小 embedding 探测
  -> 为全部 approved 切片重建候选索引
  -> 覆盖率 100% 且 content_hash 全部匹配
  -> 使用固定正式评测集评测候选 Profile
  -> 门禁通过
  -> 事务内切换 active Profile 并递增 generation
  -> 各进程刷新 Provider、Store 和向量缓存
```

约束：

1. 重建按知识版本分批提交，进程异常后可从已完成 chunk 继续。
2. 重建失败不会删除候选 Profile 的已完成向量，也不会影响活动索引。
3. 评测报告必须记录 Profile fingerprint、数据集哈希、代码版本、指标和时间。
4. 评测门槛沿用当前正式门禁；报告不属于当前 fingerprint 时无效。
5. 激活操作在单个数据库事务中校验覆盖率和评测门禁，然后更新 active Profile。
6. 回滚本质上是激活此前仍完整且评测有效的 Profile。
7. 删除或清理旧 Profile 不属于自动流程，只能由显式管理操作完成。

## 9. 运行时一致性

现有 RAG Runtime 在进程启动时固定 Provider。新设计增加 `EmbeddingRuntimeManager`：

- 读取 `active_embedding_profile_id` 和 generation；
- 按 fingerprint 缓存轻量 HTTP Provider；
- 每次检索前检查 generation，发生变化时原子替换 Retriever 和 Store 视图；
- Web API 与分析 Worker 通过同一知识数据库感知切换，不要求重启；
- 正在执行的单次检索继续使用开始时的 Profile，下一次检索使用新 Profile；
- 查询向量与知识向量必须来自同一 Profile。

本地服务不可用、超时或输出无效时，向量分支记录结构化降级原因。基础诊断继续运行；BM25 是否单独返回结果沿用 RAG 降级策略，但不能把不完整结果伪装成完整混合检索。

## 10. 配置

保留现有 DashScope 配置，并新增：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `LOCAL_EMBEDDING_BASE_URL` | `http://127.0.0.1:8790` | 本地服务地址 |
| `LOCAL_EMBEDDING_TIMEOUT_SECONDS` | `30` | 本地推理请求超时 |
| `LOCAL_EMBEDDING_MAX_RETRIES` | `1` | 仅连接和 5xx 重试 |
| `LOCAL_EMBEDDING_EXPECTED_MODEL` | `BAAI/bge-visualized-m3` | capabilities 模型校验 |
| `LOCAL_EMBEDDING_EXPECTED_REVISION` | 空 | 正式部署必须显式锁定 |

活动 Profile 和重建状态持久化在知识数据库；API Key 仍只来自 Secret 配置。环境变量不能绕过数据库中的候选、评测和激活流程。

## 11. Web 与 CLI

Web 知识管理新增“Embedding 设置”区域：

- 展示当前活动 Profile、Provider、模型 revision、维度和连接状态；
- 列出外部与本地候选项；
- 本地项支持修改 loopback 端点并测试连接；
- “开始重建”显示进度和错误；
- 重建完成后可发起正式评测；
- 只有门禁通过后显示“激活”命令；
- 切换前明确说明会改变所有后续检索，但不会删除旧索引。

CLI 提供等价命令：

```text
pkm embedding profile list
pkm embedding profile probe <profile-id>
pkm embedding rebuild <profile-id>
pkm embedding rebuild-status <job-id>
pkm embedding evaluate <profile-id> <dataset>
pkm embedding activate <profile-id>
pkm embedding rollback <profile-id>
```

## 12. 安全与隐私

- 本地服务默认且只允许绑定 `127.0.0.1`；非 loopback 绑定首版拒绝。
- endpoint 不允许携带 userinfo、query token 或 fragment。
- 图片和文本只在请求内存中存在，本地服务不记录正文、Data URL 或向量。
- 错误详情只记录输入序号、类型、大小和错误码。
- DashScope Profile 继续遵守外部传输告知；切到本地后知识和查询不离开本机。
- 模型权重目录不通过 Web API 浏览或返回绝对路径。

## 13. 可观测性与错误

稳定错误码至少包括：

- `EMBEDDING_PROFILE_NOT_FOUND`
- `EMBEDDING_PROFILE_INCOMPATIBLE`
- `LOCAL_EMBEDDING_UNAVAILABLE`
- `LOCAL_EMBEDDING_NOT_READY`
- `LOCAL_EMBEDDING_OUTPUT_INVALID`
- `EMBEDDING_REBUILD_INCOMPLETE`
- `EMBEDDING_EVALUATION_REQUIRED`
- `EMBEDDING_EVALUATION_FAILED`
- `EMBEDDING_ACTIVATION_CONFLICT`

健康状态应区分“服务进程可连接”“模型 ready”“活动索引完整”“评测门禁有效”，不能合并成单一绿色状态。

## 14. 验收标准

- DashScope 当前路径保持兼容，升级后默认活动 Profile 不变。
- 本地服务在纯 CPU 环境完成启动、文本、图文、批量、预热和 benchmark。
- capabilities 探测结果与每个响应向量维度一致。
- 同一 chunk 可同时保存外部和本地两套向量。
- 候选索引重建期间，所有查询继续使用旧活动 Profile。
- 缺失任一 approved chunk 向量、content_hash 不匹配或评测未通过时均不能激活。
- 激活后 Web API 与 Worker 无需重启即可在下一次查询使用新 Profile。
- 回滚不需要重新生成仍然完整的旧索引。
- 本地服务停止时返回稳定降级状态，基础报文诊断仍可运行。
- API Key、知识正文、图片 Data URL 和本地模型绝对路径不进入日志或公开 API。
- 同一正式评测集分别产出 DashScope 与本地 Profile 报告，可直接比较 Recall、MRR、Faithfulness、Answer Relevancy 和延迟。

## 15. 风险

- `bge-visualized-m3` 的官方推理代码、CPU 支持和依赖组合必须先做兼容性验证；不能直接假设 Hugging Face 通用 AutoModel 可加载。
- CPU 图文推理可能显著增加知识重建和在线查询延迟，因此需要预热、队列、进度、超时和基准报告。
- 数据库主键迁移影响所有索引读写与发布校验，必须提供旧库迁移夹具和回滚测试。
- 多进程运行时切换若只更新 Web 进程会产生混合向量空间，generation 刷新属于发布阻断项。
- 不同模型的相似度分布不同，现有召回融合参数可能需要基于评测重新校准。
