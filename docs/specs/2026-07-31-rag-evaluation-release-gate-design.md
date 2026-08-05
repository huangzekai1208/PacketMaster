# RAG 评测体系与发布门禁设计

日期：2026-07-31

状态：已确认，待实施

关联文档：

- `docs/specs/2026-07-27-packetmaster-rag-v1-design.md`
- `docs/specs/2026-07-31-local-multimodal-embedding-design.md`
- `docs/rag-operations.md`

## 1. 背景

PacketMaster 已具备 50 条人工标注样本、混合检索、RRF、`qwen3-rerank` 和离线评测命令。现有评测能够计算 Recall@5、MRR、NDCG@5、引用准确率、原因覆盖率和延迟，但仍有以下缺口：

- 只评估最终检索结果，无法区分 BM25、向量、RRF 和 Reranker 各阶段贡献；
- 标注集中的回答字段是预先填写的数据，不是本次运行真实生成的答案；
- `active_gate_passed` 是单个布尔值，没有绑定知识、模型、参数、数据集和代码身份；
- 没有保存逐样本检索轨迹、失败阶段和与生产基线的差异；
- 回答忠实度、引用支持度和证据一致性缺少稳定的语义评审；
- 模型、Prompt 或知识变化后，旧评测结果可能仍被误认为有效。

本设计将评测建设为可复现的离线流水线和生产发布门禁。首版增加固定契约的 LLM Judge，但不建设可自主修改知识、切换模型或发布系统的“评测 Agent”。

## 2. 已确认决策

1. 评测分为知识完整性、检索、回答质量、性能稳定性四层。
2. 检索必须对 BM25、向量、RRF、RRF + Reranker 做同数据集消融对比。
3. 可确定计算的指标使用代码，不交给模型评分。
4. LLM Judge 只评价语义质量，使用固定 Prompt、结构化输出和锁定模型版本。
5. Judge 无权修改标注、知识、门槛、运行配置或活动模型。
6. 发布门禁采用“绝对阈值 + 相对生产基线 + 关键样本约束”。
7. 所有门禁结果绑定完整评测身份；任一语义配置变化都会使旧门禁失效。
8. 知识发布和模型激活仍需人工确认；评测通过只是必要条件，不是自动发布授权。
9. 现有 50 条人工修正数据作为首个正式数据集，后续只能通过版本升级修改，不能原地覆盖历史版本。

## 3. 目标

- 准确定位质量变化发生在切片、BM25、Embedding、融合、重排、上下文截断还是答案生成阶段。
- 对同一数据集稳定比较不同知识版本、Embedding Profile、Reranker 和生成配置。
- 让每个汇总指标都能追溯到逐样本结果和原始检索排名。
- 让线上 `active` 模式、候选 Embedding Profile 和候选 Reranker 只接受匹配当前配置的有效门禁。
- 对回答忠实度、相关性、引用支持度、证据一致性和完整性提供校准后的语义评分。
- 生成适合人工审核的失败清单和确定性失败归因。
- 保留 JSON 报告，以便 Git、CI 和外部 RAGAS 分析工具消费。

## 4. 非目标

- 首版不实现会自主规划或调用工具的评测 Agent。
- Judge 不自动生成或修改正式标注答案。
- 评测失败不自动修改切片、Prompt、检索权重或知识正文。
- 评测通过不自动发布知识、切换 Embedding、启用 Reranker 或激活 RAG。
- 首版不把线上用户对话直接加入正式评测集。
- 首版不要求引入独立评测服务或分布式任务队列。
- 首版不以单一 LLM 分数替代人工标注和确定性指标。

## 5. 总体流程

```text
数据集加载与完整性检查
  -> 知识和索引快照检查
  -> 四路检索消融
  -> 逐阶段确定性指标
  -> 使用候选链路生成真实回答
  -> 规则校验引用和禁止结论
  -> 固定 LLM Judge 语义评分
  -> 与生产基线比较
  -> 失败归因和人工审核清单
  -> 门禁决策
  -> 人工决定是否发布或激活
```

评测默认离线运行，不参与正常用户请求。耗时的完整评测使用持久化 Run；CLI 或 Web 请求只创建任务和读取进度，不保持长连接等待全部模型调用结束。

## 6. 评测身份与可复现性

### 6.1 Evaluation Run 身份

每次评测生成不可变 `run_id`，并记录：

| 身份 | 内容 |
| --- | --- |
| `dataset_fingerprint` | 规范化数据集和附件内容的 SHA-256 |
| `corpus_fingerprint` | 所有 approved 知识版本、chunk ID、content hash 和图片 hash |
| `chunking_fingerprint` | 切片器版本及全部语义参数 |
| `embedding_fingerprint` | Provider、模型、revision、维度、预处理和归一化 |
| `retrieval_fingerprint` | BM25、向量、RRF、业务加权、Top K 和上下文预算参数 |
| `reranker_fingerprint` | Provider、模型、revision、文档格式、候选 K 和最大长度 |
| `generation_fingerprint` | 回答模型、revision、系统 Prompt hash、温度和输出契约 |
| `judge_fingerprint` | Judge 模型、revision、Rubric 和 Prompt hash |
| `policy_fingerprint` | 门禁策略版本和阈值 hash |
| `code_revision` | Git commit；脏工作区另记 dirty，不伪造正式结果 |

`system_fingerprint` 是上述影响生产行为字段的确定性组合。旧 Run 只有在目标系统的 fingerprint 完全匹配时才能用于发布门禁。展示层可以比较不匹配的历史 Run，但不得用其放行。

### 6.2 正式运行约束

- 正式 Run 必须使用锁定模型或可验证 revision，禁止浮动 `latest`。
- 正式 Run 必须在干净 Git revision 上执行；开发 Run 可以标记 `informational`。
- 数据集、策略、Prompt 和模型版本变化后必须产生新 Run。
- 每个外部响应保存请求身份、延迟和状态，不保存 API Key。
- 随机生成设置固定；Judge 默认低温度。边界分数可重复评审，重复规则写入策略。

## 7. V2 标注数据集

### 7.1 数据集 Manifest

正式数据集由 manifest 和 cases 组成，至少记录：

- `dataset_id`、`version`、`language`、`domain`；
- 样本数量、创建时间、审核人和变更说明；
- `policy_id` 和允许的知识 corpus 范围；
- 标注规范版本和内容 hash；
- 是否允许将样本内容发送给外部 Judge。

### 7.2 样本字段

每个样本至少包含：

- `case_id`、用户问题和经过脱敏的诊断上下文；
- `relevant_chunk_ids` 和 0 至 3 级相关度；
- `critical`，标记不能漏召回的核心问题；
- `expected_facts`、`expected_causes` 和 `forbidden_conclusions`；
- `applicable_chunk_ids` 和适用条件说明；
- 可选参考答案与人工批准的引用关系；
- 标注人、复核人和最后修订原因。

相关切片集合是多值标注，不能只保留单个“标准 chunk”。知识 V2 导致 chunk ID 变化时，必须显式迁移标注并由人工复核。

### 7.3 兼容与版本管理

- 当前 JSON 数组格式作为 V1 继续可读，但只能运行兼容评测，不能获得完整 V2 门禁。
- 提供显式转换命令生成 V2 草稿，不自动猜测缺失的 `critical`、事实或审核字段。
- 正式数据集只允许创建新版本，不覆盖已用于门禁的文件。
- 数据集不得包含 API Key、原始 Payload、本地绝对路径、未脱敏客户信息或完整 PCAP。

## 8. 知识与索引完整性检查

检索前必须检查：

- 所有目标知识版本处于 approved 状态；
- chunk 内容非空、ID 唯一，图片可解码且 hash 匹配；
- 当前 Embedding Profile 对全部目标 chunk 覆盖完整；
- 向量维度、模型 fingerprint 和 content hash 一致；
- FTS5/BM25 索引代次与知识 corpus 一致；
- 无失效引用、重复正式版本或 superseded 版本误入检索；
- Reranker 和生成服务 capability 与 Run 声明一致。

完整性失败属于基础设施失败，不计算为质量低分，也不能生成“门禁未通过但指标有效”的误导报告。

## 9. 检索消融矩阵

每个样本在同一 corpus snapshot 上执行：

| Variant | 路径 | 用途 |
| --- | --- | --- |
| `bm25` | BM25 | 关键词基线 |
| `vector` | 向量 | Embedding 单路能力 |
| `rrf` | BM25 + 向量 + RRF + 业务加权 | 融合贡献 |
| `reranked` | RRF Top 20 + Reranker | 最终生产候选 |

各 Variant 必须保存候选 chunk、原始排名、BM25 分数、向量相似度、RRF 分数、业务加权、Reranker 分数、截断原因和 warning。消融运行共享已经生成的查询向量和可复用结果，但缓存键必须包含完整 fingerprint。

### 9.1 确定性指标

至少计算：

- Recall@5、Recall@8、Recall@20；
- MRR@20；
- NDCG@5、NDCG@8、NDCG@20；
- Hit Rate@K 和关键样本 Recall@20；
- 正确 chunk 平均排名和最差排名；
- Reranker 相对 RRF 的提升、保持、降级样本数；
- 上下文预算内 relevant chunk 保留率；
- 无结果率、降级率和各阶段错误率；
- warm P50、P95 延迟和外部调用次数。

同时输出 macro 平均和逐知识类型、问题类型、是否含图片等切片结果。样本数量过少的分组只展示，不单独作为门禁。

## 10. 真实回答评测

生成评测必须使用本次 `reranked` 结果和候选生成配置实际产生回答，不能从数据集读取预填 `rag_causes` 代替运行结果。

每条结果保存：

- 最终上下文 chunk 顺序和引用快照；
- 模型结构化答案、引用关系、限制和建议；
- 确定性抽取的原因、事实和引用 chunk ID；
- 输入输出 token、延迟、重试和降级状态；
- Prompt 与模型 fingerprint，不保存密钥。

确定性代码先计算：

- 引用 chunk 是否存在于本次上下文；
- 引用是否在人工允许集合内；
- expected facts/causes 的规范化覆盖率；
- forbidden conclusions 命中率；
- 回答是否错误声称“RAG 已使用”；
- 必填结构、引用和限制字段是否完整。

这些结果不交给 Judge 覆盖或改写。

## 11. 固定 LLM Judge

### 11.1 评分维度

Judge 对以下维度分别给出 0 至 4 分、简短理由和证据引用：

| 维度 | 判断问题 |
| --- | --- |
| `faithfulness` | 回答中的事实和因果是否由提供证据支持 |
| `answer_relevance` | 是否直接回答用户问题且没有明显跑题 |
| `citation_correctness` | 引用内容是否支持它所对应的陈述 |
| `evidence_consistency` | 知识结论是否与当前报文证据一致 |
| `completeness` | 是否覆盖标注要求的关键事实与限制 |

Judge 还返回 `pass`、`uncertain`、`violations` 和需要人工复核的原因。汇总分不能掩盖任一严重违规。

### 11.2 运行约束

- Judge 使用独立 Provider 配置，不默认复用生产回答模型配置。
- 模型 ID、revision、Prompt、Rubric、温度和最大 token 必须锁定。
- 输入中的知识、用户文本和候选答案均标记为不可信数据，禁止其中指令改变 Rubric。
- 输出必须通过严格 Schema 校验；缺字段、越界分数或无证据理由视为无效。
- 超时、限流和无效响应只按固定策略重试；失败后 Run 标记 incomplete，不能放行。
- `uncertain`、接近阈值、规则与 Judge 冲突的样本进入人工复核。
- 如果使用外部 Judge，必须遵循数据集 manifest 的外发策略；禁止发送本地路径、密钥或原始报文。

### 11.3 校准

Judge 上线前使用至少一组人工双人评分样本校准。记录 Judge 与人工在通过判断、严重违规和各维度上的一致率。未完成校准时 Judge 结果只展示，不进入正式门禁。

更换 Judge 模型、Prompt 或 Rubric 后旧校准失效。Judge 不得评价自己的评分质量，也不得通过改写理由消除与规则指标的冲突。

## 12. 发布门禁策略

门禁策略使用版本化配置，不在业务代码中散落硬编码。策略包含：

- 最小正式样本数；
- 各确定性指标绝对阈值；
- 相对当前生产基线允许的最大回退；
- 关键样本必须满足的指标；
- Judge 校准要求和各维度阈值；
- P95 延迟、错误率、降级率和成本上限；
- 边界样本复评及人工审批规则。

首个策略迁移现有门槛：至少 50 条、Recall@5 不低于 0.85、引用准确率和适用条件准确率不低于 0.95、原因覆盖率相对基线提升、禁止结论命中率为 0、P95 检索不超过 2 秒。新增指标先以报告和基线对比运行；完成一次生产基线和 Judge 校准后，再通过策略新版本启用为阻断项。

门禁只有三种结果：

- `passed`：所有阻断项通过，可提交人工激活或发布；
- `failed`：至少一个质量或性能阻断项失败；
- `incomplete`：服务错误、Judge 无效、数据缺失或身份不匹配，指标不得用于发布判断。

任何一个关键样本漏召回、禁止结论出现、正式 Run 身份不匹配或 Judge 严重违规，都可以作为策略中的一票否决项。

## 13. 基线与比较

生产基线是当前活动配置最后一次通过门禁的不可变 Run。候选 Run 必须使用相同数据集版本和策略版本比较；否则只允许并列展示，不能计算发布回退。

报告至少展示：

- 候选与基线的汇总指标差值；
- 每条样本的排名变化和回答评分变化；
- 新增通过、保持通过、新增失败和保持失败四组样本；
- Reranker 将 relevant chunk 排入或排出最终 Top K 的案例；
- 延迟、调用次数和失败率变化。

不能用总体平均提升掩盖关键样本回退。基线 Run 被删除或身份无法验证时，候选不能自动成为新基线。

## 14. 失败归因

首版使用确定性规则生成一个或多个原因标签：

- `DATASET_OR_LABEL`：标注 chunk 不存在、版本不一致或标注冲突；
- `KNOWLEDGE_INGESTION`：正文、图片、切片或索引不完整；
- `BM25_MISS`：相关 chunk 未进入 BM25 Top 20；
- `VECTOR_MISS`：相关 chunk 未进入向量 Top 20；
- `FUSION_DROP`：单路命中但 RRF 后掉出候选池；
- `RERANKER_DROP`：RRF 命中但重排后掉出最终 Top K；
- `CONTEXT_TRUNCATION`：命中结果因字节预算被截断；
- `GENERATION_OMISSION`：上下文具备证据但答案遗漏；
- `CITATION_ERROR`：引用不存在、不适用或不支持陈述；
- `UNSUPPORTED_CONCLUSION`：出现禁止或无证据结论；
- `INFRASTRUCTURE`：超时、鉴权、模型无效或数据库错误。

系统可以根据标签生成修订建议，但建议只进入报告，不能自动执行。后续若引入评测 Agent，只能在该失败包上做辅助聚类和解释，仍不得拥有发布权限。

## 15. 持久化模型

知识数据库新增或等价实现：

- `evaluation_runs`：Run 身份、状态、fingerprint、开始结束时间和门禁结果；
- `evaluation_case_results`：逐样本、Variant、排名、指标、延迟和失败标签；
- `evaluation_generation_results`：答案快照、确定性检查和模型元数据；
- `evaluation_judge_results`：评分、理由、证据、Judge fingerprint 和校准状态；
- `evaluation_gate_decisions`：策略、阻断项、人工审批人和时间；
- `evaluation_baselines`：目标环境到不可变生产 Run 的映射。

大字段可保存到受控 artifact 文件，并在数据库记录相对路径和 hash。数据库不保存 API Key、完整 Prompt Secret、原始 PCAP、Payload 或未脱敏正文。

现有 `last_evaluation` 和 `active_gate_passed` 在迁移时保留为 legacy 记录，但不能自动转换成 V2 正式门禁。

## 16. CLI 与 Web

建议 CLI：

```text
pkm knowledge evaluation dataset validate <dataset>
pkm knowledge evaluation run <dataset> --policy <policy> --full
pkm knowledge evaluation status <run-id>
pkm knowledge evaluation report <run-id> --output <path>
pkm knowledge evaluation compare <baseline-run> <candidate-run>
pkm knowledge evaluation approve <run-id> --reviewer <name>
pkm knowledge evaluation baseline set <run-id> --target production
```

现有 `pkm knowledge evaluate` 保留为兼容入口，并明确输出 legacy 或 V2 Run 类型。

Web 首版提供只读评测工作台和受权限控制的人工审批：

- 显示 Run 状态、完整身份、进度和失败原因；
- 展示四路检索指标、候选与基线差值；
- 按失败标签、知识类型、是否含图片筛选样本；
- 查看单样本排名变化、答案、引用和 Judge 理由；
- 只有完成且通过的正式 Run 可以提交人工批准；
- 激活模型或发布知识仍通过各自管理流程完成。

## 17. RAGAS 兼容

核心门禁使用 PacketMaster 自有稳定契约，避免第三方库升级改变生产判定。可提供 RAGAS 适配器导出 question、answer、contexts、ground truth/reference 和指标结果，用于研究性对照。

RAGAS 版本、模型和 Prompt 必须记录在导出报告中。RAGAS 指标只有在门禁策略明确纳入且完成校准后才成为阻断项。

## 18. 安全、隐私与权限

- 数据集加载继续拒绝密钥、绝对路径、Payload 和未脱敏字段。
- Judge 请求只包含当前样本需要的最小证据，不发送完整知识库。
- 知识中的 Prompt 注入文本作为引用数据转义和分隔，不能成为 Judge 指令。
- 日志只记录 case ID、模型身份、token、延迟、状态和错误码。
- 评测查看、执行、批准、设置基线和模型激活使用不同权限。
- 审批记录不可覆盖；撤销审批必须追加审计事件。
- 评测 artifact 遵循知识库的本地生命周期和备份策略，不进入公开诊断包。

## 19. 可观测性与错误码

稳定错误码至少包括：

- `EVALUATION_DATASET_INVALID`
- `EVALUATION_IDENTITY_INCOMPLETE`
- `EVALUATION_CORPUS_MISMATCH`
- `EVALUATION_INDEX_INCOMPLETE`
- `EVALUATION_PROVIDER_UNAVAILABLE`
- `EVALUATION_JUDGE_INVALID`
- `EVALUATION_JUDGE_UNCALIBRATED`
- `EVALUATION_BASELINE_INCOMPATIBLE`
- `EVALUATION_GATE_FAILED`
- `EVALUATION_APPROVAL_REQUIRED`

进度至少区分 validation、retrieval、generation、judge、comparison 和 gate。失败报告必须区分系统不可用和质量未达标。

## 20. 验收标准

- 同一正式配置和数据集重复运行得到相同检索排名与确定性指标。
- 报告包含 BM25、向量、RRF、Reranker 四路逐样本结果。
- 可计算 Recall@5/8/20、MRR、NDCG、关键样本召回和 Reranker 升降样本。
- 回答评测使用本次真实生成答案，而不是数据集预填结果。
- Judge 输出严格结构化，未校准、失败或身份变化时不能用于放行。
- 任一知识、切片、Embedding、Reranker、检索、Prompt、Judge、数据集或策略变化都会使旧门禁失效。
- 候选必须同时满足绝对阈值、基线约束和关键样本约束。
- 每个失败汇总指标可追溯到具体样本、排名和失败标签。
- 评测通过后仍需要人工批准，系统不会自动发布或激活。
- 现有 V1 数据集和命令保持可读可运行，但不会被误认为 V2 正式门禁。
- API Key、原始报文、Payload、本地绝对路径和未脱敏数据不进入报告、数据库或日志。

## 21. 风险

- 50 条样本只能作为初始生产集，可能无法覆盖所有 TCP 场景，需要持续基于失败类型扩充而不是只增加相似问法。
- LLM Judge 存在模型偏差和随机性，必须以人工校准、规则指标和争议样本复核约束。
- 完整消融和生成评测会增加调用成本与耗时，因此需要结果缓存和 fast/full 两档运行，但 fast Run 不能替代正式门禁。
- 知识版本变化可能使人工相关切片集合失效，必须把标注迁移作为知识发布的一部分。
- 延迟受外部服务和冷启动影响，报告必须区分 warm 指标、服务错误和质量问题。
- 门禁策略过度追求总体平均值会掩盖关键问题，因此必须保留关键样本一票否决和逐样本差异。
