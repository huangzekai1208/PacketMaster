# DashScope Embedding Integration Plan

日期：2026-07-28

## 实施步骤

1. 扩展 `Settings`：固定 DashScope Provider，并支持模型、维度、端点、密钥、超时和重试；确保机密不序列化。
2. 在 `rag.embedding` 增加 DashScope Provider 和统一 Provider 工厂。远程请求使用标准库 HTTPS，避免增加额外依赖。
3. 将 `rag.runtime` 与 `rag.cli` 改为使用工厂，并使用 Provider 的模型名和维度构造 `SQLiteKnowledgeStore`。
4. 增加单元测试，覆盖 DashScope 请求契约、稳定错误映射、配置默认和工厂选择；保留现有 CLI 注入测试方式。
5. 更新 `config_local.example.py` 和 `docs/rag-operations.md`，给出 DashScope 的最小配置和换模型后的重建流程。
6. 执行 `ruff` 及 RAG 相关单元/集成测试；修复发现的问题后记录结果。

## 非目标

- 本次不引入本地 Embedding 兼容、向量数据库迁移、重排模型或自动模型评测；
- 不自动把历史向量迁移为新模型向量；
- 不在代码或示例中写入真实 DashScope API Key。
