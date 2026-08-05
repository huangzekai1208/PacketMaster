# RAG V1 评测基线记录

日期：2026-07-31

状态：任务 1 基线已冻结

关联计划：`docs/plans/2026-07-31-rag-evaluation-release-gate.md`

## 1. 结论

当前知识库的有效 V1 基线数据集是 `evaluation/rag-csdn-wireshark-tcp.json`，不是旧的 `evaluation/rag-production-network-speed-diagnosis.json`。

使用当前 `qwen3-vl-embedding + qwen3-rerank` 配置重新运行 50 条评测后：

| 指标 | 结果 |
| --- | ---: |
| Recall@5 | 0.98 |
| MRR | 0.89 |
| NDCG@5 | 0.913567 |
| 引用准确率 | 1.0 |
| 适用性准确率 | 1.0 |
| 禁止结论命中率 | 0.0 |
| P95 检索延迟 | 0.867449 秒 |
| 平均上下文字节 | 3011.76 |
| V1 production ready | true |

原始结果冻结在 `evaluation/baselines/rag-csdn-wireshark-tcp-v1-report.json`，运行身份记录在相邻 manifest 中。

## 2. 运行快照

- Git revision：`6a2287e`
- 知识索引代次：6
- 正式知识：2 个版本、39 个 chunk
- 数据集：50 条、19 个唯一相关 chunk
- 数据集 SHA-256：`b6133277058c06e94710d85293645ffdcf09393b760a29b7ab90188651ba5ee8`
- Embedding：DashScope `qwen3-vl-embedding`，2560 维
- Reranker：DashScope `qwen3-rerank`，RRF Top 20 重排
- 最终结果：Top 8，上下文预算 24576 字节

工作区当时存在未提交的评测 spec 和 plan，但没有未提交运行代码。该结果只作为 V1 observed baseline，不能替代后续 V2 fingerprint-bound GateDecision。

## 3. 发现的数据集失配

旧数据集 `evaluation/rag-production-network-speed-diagnosis.json` 包含：

- 50 条样本；
- 32 个唯一相关 chunk；
- 与当前 39 个 approved chunk 的匹配数为 0。

在现有 V1 CLI 中运行该数据集得到 Recall@5、MRR、NDCG@5 全部为 0，并且仍会调用 `record_evaluation`，从而把 `active_gate_passed` 改为 false。该结果属于 `DATASET_OR_LABEL / EVALUATION_CORPUS_MISMATCH`，不是 Embedding 或 Reranker 质量回退。

随后使用当前 corpus 对应的 CSDN 数据集完成复测，门禁恢复为 true。

## 4. V1 已知限制

1. `active_gate_passed` 是全局布尔值，不绑定 corpus、模型、参数或数据集。
2. 评测开始前不检查相关 chunk 是否存在于当前正式知识。
3. 只评估最终 Top 5，无法区分 BM25、向量、RRF 和 Reranker。
4. `rag_causes` 和引用来自数据集预填字段，不是本次真实生成答案。
5. 不保存逐样本排名、阶段分数和失败归因。
6. P95 包含远程服务状态影响，但报告不区分基础设施失败和质量失败。

## 5. 后续约束

- V1 兼容命令必须先执行 corpus 预检，失配时不得写入门禁。
- V2 Run 必须绑定 dataset、corpus、Embedding、Reranker、检索参数、生成配置、Judge、Policy 和代码 revision。
- `rag-production-network-speed-diagnosis.json` 只有在恢复对应知识快照或人工迁移相关 chunk 标注后才能重新作为正式数据集使用。
- 后续候选配置均以本记录为初始比较基线，但只有 V2 正式 Run 可以成为新的生产 GateDecision。
