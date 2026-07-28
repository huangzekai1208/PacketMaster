# Web Knowledge Management Design

日期：2026-07-28

## 目标

在 PacketMaster 本机 Web 工作台中管理 RAG 知识：列表、文件导入预览、草稿保存、审核发布、版本查看、停用、强制重建索引，以及最后一次评估报告与 active 门禁状态。

## 安全边界

- Web 仅监听 loopback，沿用现有 Host 和 Origin 校验。
- 浏览器通过 File API 读取用户选择的 UTF-8 `.md`、`.markdown`、`.txt`、`.json` 文件，并提交文件名和文本内容；API 不接收或返回本机绝对路径。
- 后端使用现有脱敏、注入风险检测、文件大小、切片和状态迁移规则。
- 导入预览与保存草稿都需要完整元数据；有注入风险时必须在保存草稿时显式确认。
- 发布、停用和重建是明确命令，均要求操作者/审核人和理由（停用）。API Key、完整知识正文和本机路径不写入 Web 错误详情。
- active 门禁仅由评估记录写入；Web 只能展示，不能设置或绕过它。

## API

| 方法 | 路径 | 行为 |
| --- | --- | --- |
| `GET` | `/api/knowledge` | 分页列出知识，支持状态和类型筛选 |
| `GET` | `/api/knowledge/{knowledge_id}` | 返回文档、版本、每版本切片数 |
| `POST` | `/api/knowledge/preview` | 解析内容、脱敏、切片并返回预览与风险标记 |
| `POST` | `/api/knowledge/import` | 保存草稿；风险内容需要 `ack_risk=true` |
| `POST` | `/api/knowledge/versions/{version_id}/approve` | 生成 embedding 后发布版本 |
| `POST` | `/api/knowledge/versions/{version_id}/disable` | 停用版本 |
| `POST` | `/api/knowledge/versions/{version_id}/reindex` | 重建当前 DashScope 模型向量 |
| `GET` | `/api/knowledge/evaluation-status` | 最后一次评估报告、active gate 与当前请求模式 |

## 页面

工作台页头新增“知识库”入口。知识页包含：

- 状态条：已发布/草稿数量、active gate、最近评估的样本数及核心指标；
- 左侧可筛选知识列表；
- 中间详情及版本历史，显示切片数和状态；
- 右侧命令面板：导入预览、保存草稿、审核发布、停用、重建索引；
- 所有破坏性或状态变更操作有确认、处理中和错误状态。

评估状态仅展示。正式评估仍通过 `pkm knowledge evaluate` 产生记录，避免把人工标注工作伪装成自动化按钮。

## 验收

- Web 可完整完成一篇 Markdown 知识的预览、导入、审核、发布、查看版本、停用和重建。
- 风险内容未确认时拒绝导入。
- 详情不泄露本机路径或密钥。
- 页面可显示最新评估报告与 active gate；无评估记录时显示明确状态。
- 后端 API 与前端关键交互有自动化测试。

## Web 报文选择补充

- Web 的“注册报文”使用浏览器文件选择器选择 `.pcap` 或 `.pcapng`，不要求用户输入绝对路径。
- 选择后的文件上传至本机服务受管的 `artifact_root/web-captures` 目录，以随机文件名保存；原始文件名仅作为展示元数据。
- 上传按大小限制流式写入，拒绝空文件、超限文件和非 pcap/pcapng 文件。Web API 不返回浏览器路径或受管文件绝对路径。
- 原有 `POST /api/captures/register` 路径注册接口保留给既有本机调用；Web 界面改用 `POST /api/captures/upload`。
