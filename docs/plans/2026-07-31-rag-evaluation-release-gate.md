# RAG 评测体系与发布门禁实施计划

日期：2026-07-31

关联设计：`docs/specs/2026-07-31-rag-evaluation-release-gate-design.md`

目标：将现有单次 RAG 指标计算升级为可复现的分层评测流水线，支持 BM25、向量、RRF、Reranker 消融，使用真实生成答案和固定 LLM Judge，并通过绑定完整系统身份的发布门禁控制 RAG、知识、Embedding 和 Reranker 激活。

## 全局约束

- 使用测试驱动方式逐任务实施，每个任务保持可独立提交和回滚。
- 确定性指标不得交给 LLM 计算或覆盖。
- 首版 Judge 是受限评分 Provider，不实现自主评测 Agent。
- Judge 和评测任务无权修改知识、标注、配置、基线或活动模型。
- 正式门禁必须绑定 dataset、corpus、chunking、embedding、retrieval、reranker、generation、judge、policy 和 code fingerprint。
- 正式评测失败与评测基础设施异常必须使用不同状态。
- 保留当前 `pkm knowledge evaluate` 兼容行为，迁移期间不破坏已有报告读取。
- 不在数据库、artifact、日志、错误或测试夹具中写入真实 API Key、原始 PCAP、Payload、本地绝对路径或未脱敏数据。
- 外部 Judge 只接收 manifest 允许外发的最小脱敏上下文。
- 涉及数据库的任务必须覆盖旧库升级、事务失败和并发访问。
- 每个后端任务完成后运行定向 Pytest 和 Ruff；涉及 Web 时运行 ESLint、TypeScript、Vitest、生产构建和 Playwright。

## 依赖顺序

```text
冻结 V1 基线
  -> V2 契约与策略
  -> 持久化和 fingerprint
  -> 检索消融
  -> 真实回答评测
  -> Judge 与校准
  -> 比较、归因和门禁
  -> 持久任务与 CLI
  -> Web 工作台
  -> 发布验收
```

本计划任务 1 至 4 是本地 Embedding 计划中“绑定评测门禁与 Profile”的前置条件。候选本地模型可以并行完成兼容性研究，但不能在本计划的正式门禁完成前激活。

## 任务 1：冻结现有 V1 行为和生产基线（已完成）

文件：

- 创建 `docs/research/rag-evaluation-v1-baseline.md`
- 创建 `evaluation/baselines/` 下的正式基线报告或 manifest
- 修改 `tests/unit/test_rag_evaluation.py`
- 修改 `tests/integration/test_rag_cli.py`

步骤：

- [x] 记录当前 50 条数据集 hash、知识 corpus、Embedding、Reranker、检索参数和 Git commit。
- [x] 使用当前生产配置重新运行现有评测，保存原始 JSON 报告和命令。
- [x] 为 Recall@5、MRR、NDCG@5、引用、适用性、原因覆盖、禁止结论和 P95 增加快照测试。
- [x] 记录当前评测无法表达的字段和已知失败样本，不修饰基线结果。
- [x] 验证当前 `active_gate_passed` 在何种配置变化下错误保留，建立迁移回归测试。
- [x] 确认正式数据集不包含密钥、绝对路径、Payload 或未脱敏客户数据。

验收：在改造前形成可重复 V1 基线，后续迁移能够证明兼容指标未被意外改变。

## 任务 2：定义 V2 数据集、Run、Policy 和 Judge 契约（已完成）

文件：

- 修改 `src/packetmaster/rag/evaluation.py`
- 创建 `src/packetmaster/rag/evaluation_contracts.py`
- 创建 `src/packetmaster/rag/evaluation_policy.py`
- 创建 `evaluation/policies/rag-production-v1.json`
- 创建 `docs/templates/rag-evaluation-v2.example.json`
- 修改 `tests/unit/test_rag_evaluation.py`
- 创建 `tests/unit/test_evaluation_contracts.py`
- 创建 `tests/unit/test_evaluation_policy.py`

步骤：

- [x] 先为 V2 manifest、case、Run status、Variant、逐样本结果、Judge 结果和 GateDecision 编写校验失败测试。
- [x] 实现 `passed`、`failed`、`incomplete` 三态，禁止用布尔值合并质量失败和基础设施失败。
- [x] 实现版本化 Policy，迁移当前至少 50 条、Recall@5、引用、适用性、原因覆盖、禁止结论和 P95 门槛。
- [x] 将新增 Recall@8/20、NDCG@8/20、关键样本和 Judge 阈值设为显式策略项；未校准项首版只报告。
- [x] 实现 V1 数据集兼容读取和显式 V1 -> V2 草稿转换。
- [x] 转换过程不得自动填充 `critical`、人工审核人或 Judge ground truth。
- [x] 对规范化 JSON 计算稳定 dataset 和 policy fingerprint。
- [x] 覆盖重复 ID、相关度集合不一致、未知字段、越界分数、敏感字段和内容 hash 变化。

验收：V1 数据仍可运行；V2 数据和 Policy 有严格、稳定、可 hash 的领域契约。

## 任务 3：建立评测持久化与旧门禁迁移（已完成）

文件：

- 修改 `src/packetmaster/rag/database.py`
- 修改 `tests/unit/test_rag_database.py`
- 增加旧知识数据库 schema 夹具

步骤：

- [x] 为 schema 升级编写旧库迁移、事务中断和重复迁移测试。
- [x] 新增 `evaluation_runs`、`evaluation_case_results`、`evaluation_generation_results`、`evaluation_judge_results`、`evaluation_gate_decisions` 和 `evaluation_baselines`。
- [x] 为 Run 状态、fingerprint、case、Variant、基线和时间增加必要索引。
- [x] 将 `last_evaluation` 和 `active_gate_passed` 保存为 legacy 审计记录，不自动授予 V2 门禁。
- [x] 实现 Run 创建、阶段进度、逐样本 upsert、失败恢复、完成和读取 API。
- [x] 大答案和完整轨迹支持受控 artifact；数据库保存相对路径、大小和 SHA-256。
- [x] 阻止删除仍被 baseline 或 gate decision 引用的 Run。
- [x] 验证数据库和 artifact 均不包含 Provider Secret。

验收：旧知识库无损升级，历史 active 状态保持运行兼容，但候选发布必须获得新的 V2 正式门禁。

## 任务 4：实现完整系统 Fingerprint 和快照检查（已完成）

文件：

- 创建 `src/packetmaster/rag/evaluation_identity.py`
- 修改 `src/packetmaster/rag/database.py`
- 修改 `src/packetmaster/rag/runtime.py`
- 创建 `tests/unit/test_evaluation_identity.py`
- 修改 `tests/unit/test_rag_runtime.py`

步骤：

- [x] 为 dataset、corpus、chunking、embedding、retrieval、reranker、generation、judge、policy 和 code 分别实现稳定 fingerprint。
- [x] corpus fingerprint 覆盖 approved version、chunk ID、content hash、图片 hash 和索引 generation。
- [x] retrieval fingerprint 覆盖 BM25、向量、RRF、业务加权、候选 Top K、最终 Top K、超时和上下文预算中影响结果的字段。
- [x] Prompt 只保存 SHA-256 和版本，不把 Secret 或完整系统 Prompt 暴露到公开 API。
- [x] 正式 Run 检查 Git revision 和 dirty 状态；dirty Run 标记 informational。
- [x] 实现评测前知识、FTS5、Embedding 覆盖率、维度、content hash 和 Provider capabilities 检查。
- [x] 证明任一语义字段变化都会产生新 system fingerprint，日志级字段变化不会使门禁无效。
- [x] 新增按当前 system fingerprint 查询有效已批准 GateDecision；运行时切换在任务 8 原子激活阶段启用。

验收：旧 Run 无法为任何不同知识、模型、参数、Prompt、数据集或策略配置放行。

## 任务 5：实现检索消融执行器与逐阶段轨迹（已完成）

文件：

- 修改 `src/packetmaster/rag/retrieval.py`
- 创建 `src/packetmaster/rag/evaluation_retrieval.py`
- 修改 `src/packetmaster/rag/contracts.py`
- 修改 `tests/unit/test_rag_retrieval.py`
- 创建 `tests/unit/test_evaluation_retrieval.py`

步骤：

- [x] 先为 BM25、vector、RRF、reranked 四个 Variant 编写固定候选排名测试。
- [x] 将检索内部阶段暴露为仅供评测使用的结构化 trace，不改变生产 `KnowledgeBundle` 契约。
- [x] trace 保存原始排名、可用分数、业务加权、截断原因、warning 和 Provider 状态；当前 Store 未暴露 BM25 原始分数时明确为 null。
- [x] 同一样本复用一次查询向量和合法中间结果；首版不跨 Run 缓存，避免复用不兼容结果。
- [x] Reranker 关闭、超时和无效输出时明确标记 degraded，不把 RRF 回退伪装为 reranked 成功。
- [x] 保证 Variant 共享相同 corpus snapshot；Run 前后 generation 一致性由持久 Runner 阶段校验。
- [x] 限制 trace 正文，只保存 chunk ID、必要引用快照和受控内容 hash。

验收：任一最终排名都能还原 BM25、向量、融合和重排的来源，并可明确识别相关 chunk 在哪一阶段丢失。

## 任务 6：扩展确定性指标和分组报告（已完成）

文件：

- 修改 `src/packetmaster/rag/evaluation.py`
- 创建 `src/packetmaster/rag/evaluation_metrics.py`
- 创建 `tests/unit/test_evaluation_metrics.py`
- 修改 `tests/unit/test_rag_evaluation.py`

步骤：

- [x] 使用手算样例验证 Recall@5/8/20、MRR@20、NDCG@5/8/20 和 Hit Rate。
- [x] 计算 macro 指标、关键样本 Recall、正确 chunk 平均/最差排名和上下文保留率。
- [x] 计算 Reranker 相对 RRF 的提升、保持和降级样本集合。
- [x] 按知识类型、问题类型、是否含图片输出分组指标，并标明样本数。
- [x] 记录无结果、降级、Provider 错误、P50/P95 latency 和外部调用次数。
- [x] 对空结果、多个相关 chunk、分级相关性、排名和降级建立边界测试。
- [x] 保留现有 V1 `EvaluationReport` 和指标字段，V2 报告使用独立版本化契约。

验收：汇总指标全部可由保存的逐样本 trace 重新计算，报告数字与 trace 一致。

## 任务 7：实现真实回答评测与确定性答案检查

文件：

- 创建 `src/packetmaster/rag/evaluation_generation.py`
- 修改回答生成应用服务的公共契约，避免复制生产 Prompt 流程
- 修改 `src/packetmaster/rag/evaluation.py`
- 创建 `tests/unit/test_evaluation_generation.py`
- 创建 `tests/integration/test_rag_answer_evaluation.py`

步骤：

- [x] 抽取可由线上和离线评测共同调用的回答生成入口，保持相同 Prompt、上下文和引用契约。
- [x] 使用本次 reranked 上下文真实生成答案，不再将数据集中的 `rag_causes` 当作本次结果。
- [x] 保存上下文顺序、引用快照、结构化答案、token、延迟、重试、warning 和 fingerprint；Provider 不暴露 token 时显式记录 unavailable。
- [x] 实现引用存在性、上下文内引用、人工允许集合、expected facts/causes、forbidden conclusions 和必填字段检查。
- [x] 对无 RAG、RAG 降级、上下文截断、模型拒答、无效 Schema 和错误 RAG 状态声明建立测试。
- [ ] 模型或生成失败将完整 Run 标记 incomplete，不以零质量分掩盖服务故障。
- [x] 确保答案 artifact 脱敏且不包含系统 Secret。

验收：每个回答质量指标对应本次真实模型输出，并能重现它使用的上下文和引用。

## 任务 8：实现固定 LLM Judge Provider 与校准流程

文件：

- 创建 `src/packetmaster/rag/judging.py`
- 修改 `src/packetmaster/rag/base.py`
- 修改 `src/packetmaster/config.py`
- 创建 `tests/unit/test_rag_judging.py`
- 创建 `tests/integration/test_rag_judge_provider.py`
- 创建 `evaluation/judge/` 下的版本化 Rubric 和 Prompt

步骤：

- [x] 定义 Judge Provider 协议和严格结果 Schema：五维 0 至 4 分、pass、uncertain、violations、理由和证据引用。
- [x] 实现独立 Judge 配置，不隐式复用回答模型或 Embedding Key。
- [x] 锁定模型、revision、Rubric hash、Prompt hash、温度、最大 token、超时和重试。
- [x] 用清晰数据边界包裹用户问题、知识、报文证据和候选答案，抵抗内容内 Prompt 注入。
- [x] 拒绝越界分数、未知 violation、缺少证据的理由、数量不符和畸形 JSON。
- [ ] Judge 失败、超时或外发策略不允许时将阶段标记 incomplete。
- [x] 实现边界样本固定次数复评和确定性聚合规则，不允许运行时自行改变阈值。
- [ ] 创建人工双人评分校准集，计算通过判断和严重违规一致率。
- [x] 未校准或 fingerprint 变化的 Judge 只报告，不成为阻断项。

验收：Judge 结果可重复、可追溯、受 Schema 和权限约束，且不能修改任何生产状态。

## 任务 9：实现基线比较、失败归因和门禁决策

文件：

- 创建 `src/packetmaster/rag/evaluation_comparison.py`
- 创建 `src/packetmaster/rag/evaluation_gate.py`
- 修改 `src/packetmaster/rag/database.py`
- 创建 `tests/unit/test_evaluation_comparison.py`
- 创建 `tests/unit/test_evaluation_gate.py`

步骤：

- [ ] 拒绝比较 dataset 或 policy 不兼容的 Run，并说明不兼容字段。
- [ ] 输出候选与基线的汇总差值和逐样本新增通过、保持通过、新增失败、保持失败。
- [ ] 实现绝对阈值、最大允许回退、关键样本和严重违规一票否决。
- [ ] 根据逐阶段 trace 生成 DATASET、INGESTION、BM25、VECTOR、FUSION、RERANKER、CONTEXT、GENERATION、CITATION、UNSUPPORTED 和 INFRASTRUCTURE 标签。
- [ ] 同一样本允许多个标签，并给出确定性优先级，不让 Judge 自行覆盖归因。
- [ ] 只有正式、完整、身份匹配、Judge 满足策略、所有阻断项通过的 Run 才能得到 `passed`。
- [ ] GateDecision 保存完整阻断项和报告 hash；人工 approve 追加审核事件。
- [ ] 设置生产 baseline 要求已通过且已人工批准，禁止覆盖历史 baseline 行。
- [ ] 证明总体均值提升不能覆盖关键样本回退或禁止结论。

验收：每个门禁决定可解释、可审计，并能明确指出由哪些样本和规则阻断发布。

## 任务 10：实现可恢复评测任务和 CLI

文件：

- 创建 `src/packetmaster/rag/evaluation_runner.py`
- 修改 `src/packetmaster/rag/cli.py`
- 修改 `tests/integration/test_rag_cli.py`
- 创建 `tests/unit/test_evaluation_runner.py`

步骤：

- [ ] 实现 validation、retrieval、generation、judge、comparison、gate 阶段状态和进度。
- [ ] 逐 case、Variant 持久化结果，进程中断后按 fingerprint 和已完成项恢复。
- [ ] 相同正式身份的并发 Run 去重；不同 Run 不共享不兼容缓存。
- [ ] 提供 dataset validate、run、status、report、compare、approve 和 baseline set 命令。
- [ ] 支持 `--fast` 只运行完整性和检索回归，明确禁止作为正式发布门禁。
- [ ] `--full` 执行真实生成、Judge、比较和 Gate。
- [ ] 保留 `pkm knowledge evaluate` 兼容入口，并在输出中明确 legacy 状态。
- [ ] CLI 退出码区分 passed、failed、incomplete 和命令错误，便于 CI 使用。
- [ ] 输出路径使用用户显式路径或受控 artifact 根，不回显 Secret。

验收：完整 Run 可中断恢复，CLI 和 CI 能可靠区分质量失败、基础设施失败和正式通过。

## 任务 11：增加 Web 评测工作台与审批

文件：

- 修改 `src/packetmaster/web/contracts.py`
- 修改 `src/packetmaster/web/api.py`
- 修改 `webui/src/api.ts`
- 创建或修改 Web 知识管理中的评测视图组件
- 修改 `webui/src/styles.css`
- 修改 `tests/unit/test_web_api.py`
- 修改 `webui/src/App.test.tsx`
- 修改 Playwright E2E 测试

步骤：

- [ ] 增加 Run 列表、创建、状态、报告、比较、逐样本详情和审批 API。
- [ ] 长时间评测只创建持久任务，页面轮询或订阅进度，不保持请求到结束。
- [ ] 展示完整身份、正式/informational 状态和 passed/failed/incomplete 区别。
- [ ] 用紧凑表格展示四路 Recall、NDCG、MRR、延迟和 Reranker 升降数量。
- [ ] 支持按失败标签、知识类型、关键样本和图片样本筛选。
- [ ] 单样本页展示排名变化、上下文、答案、引用检查和 Judge 理由，不展示 Secret 或绝对路径。
- [ ] 人工审批要求 reviewer 和备注；设置 baseline、发布知识、激活模型保持独立操作。
- [ ] 覆盖无权限、Run incomplete、身份过期、Judge 未校准和审批成功状态。
- [ ] 在桌面和窄屏验证表格、筛选、长 chunk ID 和错误信息不重叠。

验收：用户能从 Web 找到具体失败样本并完成受控审批，但页面不会自动发布知识或激活模型。

## 任务 12：RAGAS 适配、文档和发布验收

文件：

- 创建 `src/packetmaster/rag/ragas_adapter.py` 或独立可选脚本
- 修改 `README.md`
- 修改 `docs/rag-operations.md`
- 修改 `docs/windows-web-release-checklist.md`
- 修改 `.github/workflows/test.yml`（若存在）
- 创建评测 Runbook 和故障排查文档

步骤：

- [ ] 提供 question、answer、contexts、reference 的 RAGAS 导入导出，不让 RAGAS 直接写 GateDecision。
- [ ] 将 RAGAS 包作为可选评测依赖并锁定版本；基础运行不强制安装。
- [ ] 文档说明 V1/V2 数据集、fast/full、Judge 外发边界、门禁、审批、基线和失效规则。
- [ ] 记录知识修订、Embedding 切换和 Reranker 切换前后的标准 A/B 流程。
- [ ] 在当前 50 条数据集上生成四路消融、真实回答、Judge 和基线比较报告。
- [ ] 人工复核所有新增失败、Judge uncertain 和规则/Judge 冲突样本。
- [ ] 运行 Python 单元、集成、RAG 容量、数据库迁移和打包测试。
- [ ] 运行 Ruff、前端 lint、typecheck、Vitest、生产构建和 Playwright。
- [ ] 验证 Windows 和 macOS 的路径、编码、断点恢复和报告可读性。
- [ ] 检查 wheel 和前端静态资源不包含数据集、答案 artifact、模型权重或 Secret。

验收：正式 Run 可在两平台复现，文档覆盖操作和故障恢复，发布包不携带评测私有数据或凭据。

## 最终发布门禁

- [ ] 当前 50 条正式数据集完成 V2 人工复核并生成稳定 fingerprint。
- [ ] V1 基线指标迁移无意外回退。
- [ ] 四路检索消融均保存逐样本 trace，汇总指标可从 trace 重算。
- [ ] Recall@5/8/20、MRR、NDCG、关键样本和 Reranker 升降结果可比较。
- [ ] 回答评测使用本次真实生成结果和本次上下文。
- [ ] Judge 完成人工校准，失败或未校准时不能放行。
- [ ] 生产 Policy 同时执行绝对阈值、基线约束和关键样本约束。
- [ ] 任一知识、模型、参数、Prompt、Judge、数据集、策略或代码变化使旧门禁失效。
- [ ] passed Run 仍需人工审批，系统不会自动发布或激活。
- [ ] 评测中断可恢复，基础设施失败不会记录为质量低分。
- [ ] Web 和 CLI 均可查看失败原因、比较报告和审核记录。
- [ ] API Key、原始 PCAP、Payload、本地绝对路径和未脱敏内容不进入持久化和日志。
- [ ] 全量测试、Ruff、前端检查、E2E、打包测试和 `git diff --check` 通过。
