# 本地多模态 Embedding 实施计划

日期：2026-07-31

关联设计：`docs/specs/2026-07-31-local-multimodal-embedding-design.md`

目标：在保留 DashScope `qwen3-vl-embedding` 的同时，引入独立的 `bge-visualized-m3` 本地服务，支持纯 CPU，并通过双索引重建、正式评测和原子激活实现可回滚切换。

## 全局约束

- 使用测试驱动方式逐任务实施。
- 不在 PacketMaster Web API 或分析 Worker 中加载模型权重。
- 不把 torch、模型推理依赖加入基础安装依赖。
- 不自动下载模型权重。
- 不写死未经真实服务探测确认的维度。
- 不覆盖活动 Profile 的向量。
- 不允许未完成重建或未通过评测的 Profile 激活。
- 每个任务完成后运行对应测试和 Ruff；涉及前端时还需运行 typecheck、Vitest 和生产构建。

## 任务 1：验证并锁定 bge-visualized-m3 运行契约

文件：

- 创建 `docs/research/bge-visualized-m3-compatibility.md`
- 创建 `scripts/probe_bge_visualized_m3.py`
- 修改 `pyproject.toml`，增加隔离的 `rag-local-server` 可选依赖

步骤：

- [ ] 核对官方模型仓库、许可证、revision、推荐推理代码和依赖版本。
- [ ] 在隔离环境使用纯 CPU 加载锁定 revision。
- [ ] 探测文本、图片、图文和批量输入的实际调用方式及输出维度。
- [ ] 验证输出有限、非零、可 L2 归一化，并验证文本查询与图文文档位于兼容空间。
- [ ] 记录 CPU dtype、加载时间、峰值 RSS、单文本和单图文 warm latency。
- [ ] 明确 macOS CPU、Windows CPU 的支持结论；MPS/CUDA 只作为附加结果。
- [ ] 将确认后的版本和维度写入兼容性文档，不写入运行时硬编码。

验收：使用锁定依赖和 revision 可在纯 CPU 生成稳定文本及图文向量，并有可重复探测记录。若模型无法满足，停止后续任务并重新评审模型选择。

## 任务 2：建立 Profile 领域契约和配置

文件：

- 修改 `src/packetmaster/config.py`
- 创建 `src/packetmaster/rag/profiles.py`
- 修改 `src/packetmaster/rag/contracts.py`
- 创建 `tests/unit/test_embedding_profiles.py`
- 修改 `tests/unit/test_rag_contracts.py`

步骤：

- [ ] 先写 Profile 校验、fingerprint 稳定性、Secret 排除和 endpoint 限制失败测试。
- [ ] 实现 `EmbeddingProfile`、ProviderKind、ProfileStatus 和 capability 契约。
- [ ] fingerprint 覆盖所有影响向量空间的配置。
- [ ] 新增本地 endpoint、预期模型、revision、超时和重试配置。
- [ ] 拒绝本地服务使用非 loopback endpoint、URL 凭据、query token 或 fragment。
- [ ] 保持现有 DashScope 配置默认和 config_local Key 行为兼容。

验收：同配置得到相同 fingerprint，任何语义配置变化得到不同 fingerprint，所有 Secret 均不序列化。

## 任务 3：迁移数据库以支持多 Profile 向量

文件：

- 修改 `src/packetmaster/rag/database.py`
- 修改 `tests/unit/test_rag_database.py`
- 增加旧 schema v2 和评测 schema v3 数据库夹具

步骤：

- [ ] 为 schema v4 编写迁移失败测试，并覆盖旧 schema v2/v3 升级。
- [ ] 新增 `embedding_profiles`、多 Profile embeddings、重建 job 和按 Profile 评测记录。
- [ ] 将旧 `knowledge_embeddings` 迁移到 legacy Profile，不丢失向量。
- [ ] 将主键改为 `(chunk_id, profile_id)`，增加 profile、dimension 和 chunk 查询索引。
- [ ] 修改保存、覆盖率、发布完整性、缓存 generation 和向量加载查询。
- [ ] 证明候选 Profile 写入不修改活动 Profile 的向量字节。
- [ ] 证明发布只接受活动 Profile 的完整向量。

验收：已有知识库原地升级后行为不变；同一 chunk 可保存多套向量；迁移事务失败时旧库保持可用。

## 任务 4：实现本地 HTTP Provider Client

文件：

- 修改 `src/packetmaster/rag/embedding.py`
- 创建 `src/packetmaster/rag/local_client.py`
- 修改 `src/packetmaster/rag/base.py`
- 修改 `tests/unit/test_rag_embedding.py`
- 创建 `tests/unit/test_local_embedding_client.py`

步骤：

- [ ] 编写 capabilities、文本、图文、顺序保持、超时和错误映射测试。
- [ ] 实现 loopback HTTP Client 和连接复用。
- [ ] Provider 构造时探测 capabilities，校验 model、revision、modalities、normalization 和 dimension。
- [ ] 将 `KnowledgeImage.data_url` 转为明确的 MIME 与 base64 字段，禁止记录正文。
- [ ] 覆盖连接失败、not ready、4xx、5xx、畸形 JSON、数量不符、非有限值、零向量和维度不符。
- [ ] 扩展 Provider 工厂按 Profile 构造 DashScope 或 Local Provider。

验收：Local Provider 满足既有 EmbeddingProvider 行为，且图文接口能力显式可探测。

## 任务 5：实现独立本地模型服务

文件：

- 创建 `src/packetmaster_embedding_service/__init__.py`
- 创建 `src/packetmaster_embedding_service/api.py`
- 创建 `src/packetmaster_embedding_service/backend.py`
- 创建 `src/packetmaster_embedding_service/runtime.py`
- 修改 `pyproject.toml`，增加 `packetmaster-embedding-server` 入口
- 创建 `tests/unit/test_local_embedding_service.py`
- 创建 `tests/integration/test_local_embedding_service.py`

步骤：

- [ ] 先用 Fake Backend 固定 HTTP 契约测试，避免单元测试下载模型。
- [ ] 实现 health、capabilities 和 embeddings 端点及严格 Pydantic 输入。
- [ ] 实现显式模型目录、revision、device、dtype、batch、线程和队列配置。
- [ ] 限制为 loopback 绑定，限制文本、图片、批量和并发大小。
- [ ] 实现纯文本、单图文和多图聚合，统一 L2 归一化。
- [ ] 启动时完成文本与最小图文预热，成功后才报告 ready。
- [ ] 增加 benchmark 子命令和无正文日志。
- [ ] 增加标记为可选的真实模型 CPU 集成测试，不纳入无模型缓存的默认测试。

验收：独立进程可在 CPU 上提供契约稳定的文本和图文向量；核心 PacketMaster 安装不导入推理依赖。

## 任务 6：实现可恢复的候选索引重建

文件：

- 修改 `src/packetmaster/rag/embedding.py`
- 创建 `src/packetmaster/rag/rebuild.py`
- 修改 `src/packetmaster/rag/cli.py`
- 创建 `tests/unit/test_embedding_rebuild.py`
- 修改 `tests/integration/test_rag_cli.py`

步骤：

- [ ] 编写旧活动索引持续可查询、候选分批写入和失败恢复测试。
- [ ] 实现重建 job 状态机：pending、running、failed、completed、cancelled。
- [ ] 对全部 approved 版本按 chunk 批处理，按 content_hash 跳过已完成项。
- [ ] 记录总数、完成数、失败 chunk、开始时间和最后进度，不记录正文。
- [ ] 进程重启后从数据库状态恢复；重复启动同一 Profile job 保持幂等。
- [ ] CLI 增加 profile list/probe、rebuild 和 rebuild-status。

验收：中途失败后可续作，目标覆盖率最终为 100%，旧活动检索全程不受影响。

## 任务 7：绑定评测门禁与 Profile

文件：

- 修改 `src/packetmaster/rag/evaluation.py`
- 修改 `src/packetmaster/rag/database.py`
- 修改 `src/packetmaster/rag/cli.py`
- 修改 `tests/unit/test_rag_evaluation.py`
- 修改 `tests/integration/test_rag_cli.py`

步骤：

- [ ] 评测命令显式接收目标 Profile，不要求先激活。
- [ ] 报告记录 profile_id、fingerprint、数据集哈希、代码版本和延迟指标。
- [ ] 门禁查询只接受 fingerprint 与数据集哈希匹配的最新正式报告。
- [ ] 模型、revision、预处理或评测集变化后旧门禁自动失效。
- [ ] 使用现有 50 条正式标注分别评估 DashScope 与本地模型，保存可比较报告。
- [ ] 记录 Recall、MRR、Faithfulness、Answer Relevancy、失败率、warm P50/P95。

验收：本地 Profile 未达到当前生产门槛时无法激活；报告能够解释拒绝原因。

## 任务 8：实现原子激活、回滚和多进程刷新

文件：

- 创建 `src/packetmaster/rag/runtime_manager.py`
- 修改 `src/packetmaster/rag/runtime.py`
- 修改 `src/packetmaster/rag/database.py`
- 修改 `src/packetmaster/rag/cli.py`
- 创建 `tests/unit/test_embedding_activation.py`
- 修改 `tests/unit/test_rag_runtime.py`

步骤：

- [ ] 编写覆盖率不足、评测缺失、评测失败和并发激活冲突测试。
- [ ] 在单事务内校验候选并更新 active Profile 与 generation。
- [ ] 实现 Runtime Manager 按 generation 刷新 Provider、Store 和 Retriever。
- [ ] 证明切换中的请求保持旧 Profile，后续请求只使用新 Profile。
- [ ] 证明 Web API 与独立 Worker 都能通过数据库 generation 感知切换。
- [ ] 实现回滚到仍完整且门禁有效的旧 Profile。
- [ ] 清理 Profile 必须是独立显式操作，禁止激活时自动删除旧索引。

验收：激活和回滚无需重启，任一查询不会混用不同 Profile 的 query/document 向量。

## 任务 9：增加 Web 管理与后台任务

文件：

- 修改 `src/packetmaster/web/contracts.py`
- 修改 `src/packetmaster/web/api.py`
- 修改 `webui/src/api.ts`
- 修改 `webui/src/KnowledgeManagement.tsx`
- 修改 `webui/src/styles.css`
- 修改 `tests/unit/test_web_api.py`
- 修改 `webui/src/App.test.tsx`

步骤：

- [ ] 增加 Profile 列表、probe、启动重建、状态、评测和激活 API。
- [ ] 长时间重建使用持久化 job，不保持单个 HTTP 请求直到完成。
- [ ] Web 展示活动 Profile、服务状态、模型、revision、维度、覆盖率和评测门禁。
- [ ] 用户选择本地后先 probe，再允许开始重建。
- [ ] 仅在覆盖率 100% 且门禁通过时启用“激活”。
- [ ] API 和页面错误不得包含 Key、正文、Data URL 或本地绝对路径。
- [ ] 覆盖连接失败、重建失败、评测失败、激活成功和回滚 UI 状态。

验收：用户可以在 Web 完成候选配置到激活的完整流程，且当前活动检索在此之前保持不变。

## 任务 10：文档、发布与跨平台验收

文件：

- 修改 `README.md`
- 修改 `src/packetmaster/config_local.example.py`
- 修改 `docs/rag-operations.md`
- 修改 `docs/windows-web-release-checklist.md`
- 修改 `.github/workflows/test.yml`（若存在）

步骤：

- [ ] 文档说明外部与本地模式、独立服务安装、显式模型准备和离线启动。
- [ ] 提供 Windows CPU 与 macOS CPU 的启动、probe、重建、评测、激活和回滚命令。
- [ ] 记录外部传输与纯本地处理的隐私差异。
- [ ] 执行 Python 单元、集成、RAG 容量和打包测试。
- [ ] 执行前端 lint、typecheck、Vitest、生产构建和 E2E。
- [ ] 在 Windows CPU 与 macOS CPU 各完成真实模型 smoke test。
- [ ] 使用正式 50 条数据集完成 A/B 评测；未达门槛时保留 DashScope 为 active。
- [ ] 检查 wheel 不包含模型权重，基础安装不引入 torch。

验收：两平台 CPU 路径可复现；升级、切换、失败恢复和回滚有完整操作记录；发布包不携带权重或密钥。

## 最终发布门禁

- [ ] 旧数据库 schema v2/v3 升级无数据损失。
- [ ] DashScope 回归评测不低于当前基线。
- [ ] 本地服务 CPU 文本和图文 smoke test 通过。
- [ ] 候选重建期间 active RAG 持续可用。
- [ ] 本地 Profile 正式评测通过才可激活。
- [ ] 激活后下一次 Web 对话和分析 Worker 查询使用本地 Profile。
- [ ] 停止本地服务后基础诊断可继续，并显示明确 RAG 降级状态。
- [ ] 旧 Profile 可原子回滚。
- [ ] 全量测试、Ruff、前端检查、打包测试和 `git diff --check` 通过。
