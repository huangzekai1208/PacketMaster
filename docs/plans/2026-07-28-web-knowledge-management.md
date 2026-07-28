# Web Knowledge Management Plan

日期：2026-07-28

1. 抽取可复用的文本导入预览入口，保持 CLI 文件导入兼容。
2. 增加 Web 知识管理 Pydantic 契约和本机 API 路由，复用现有 Store、Indexer、Evaluator 记录。
3. 实现知识管理前端：列表、详情/版本、文本文件预览导入和管理命令。
4. 增加 API 与前端测试，覆盖导入风险、状态操作和评估状态。
5. 构建 Web 静态资源并运行 Python/TypeScript 测试。
6. 将 Web 报文注册改为本地文件选择和受限上传，保留既有路径注册 API 兼容性，并覆盖上传后的会话选择流程。
