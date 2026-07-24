# PacketMaster CLI 对话交互实施计划

目标：在保留现有 `packetmaster diagnose` 行为的基础上，新增 `packetmaster chat`。用户可以用一句自由自然语言描述报文路径、标准带宽、实际带宽和方向；系统结构化抽取、补问并确认后执行诊断，随后围绕当前报告和本地证据持续问答。

依据：`docs/superpowers/specs/2026-07-24-packetmaster-cli-chat-design.md`

技术路线：使用“本地路径提取与脱敏 + 模型结构化意图抽取 + 确定性归一化校验 + 用户确认”的混合参数解析；复用现有诊断 LangGraph、FastMCP 工具、Real Adapter、DiagnosisContext 和 DeepSeek 结构化输出兼容层；新增独立的会话管理与有界问答 LangGraph。首次诊断执行全量流式分析，后续问答只复用分析产物和分页证据，不重新扫描完整报文。

## 全局约束

- `packetmaster diagnose` 的参数、输出和报告契约必须保持兼容。
- `packetmaster chat` 默认分析 download，只有用户明确选择时使用 upload 或 both。
- 参数允许从自由自然语言抽取；真实报文路径只在本地解析并以占位符进入模型消息。
- 模型只负责输出结构化意图，单位换算、方向默认值、文件校验和分析启动由确定性代码控制。
- 信息缺失或有歧义时必须追问，参数完整后必须由用户确认才能启动分析。
- 问答只围绕当前 `analysis_id`，不得跨任务混用证据。
- 原始报文、Payload、完整日志、本地绝对路径和 API Key 不得进入模型上下文。
- 每个问题最多两轮额外取证，每轮最多 5 个证据请求。
- 对话历史必须有轮数和字节双重上限。
- 所有用户可见文本使用简体中文，技术缩写和机器字段保持原值。
- 候选原因数量不设固定上下限，尽可能覆盖合理原因并合并同义项。
- 置信度使用 0–100 百分数；有支持证据时选择最高置信度候选作为主因。
- Windows 是正式运行和发布验收平台，macOS 是开发兼容平台。
- 保留所有无关用户修改，不处理或提交 `.DS_Store`、本地报文和分析产物。

## 任务 1：定义对话领域契约和状态边界

涉及文件：

- `src/packetmaster/domain.py`
- `src/packetmaster/chat.py`
- `tests/unit/test_chat.py`
- `tests/unit/test_domain.py`

- [ ] 定义 `ChatSessionState` 所需的稳定领域模型，区分 CLI 本地字段和允许进入模型的字段。
- [ ] 定义 `DiagnosisIntent`、字段解析状态、路径占位符引用、缺失项和歧义项结构。
- [ ] 定义 `ChatQuestion`、`ChatAnswer` 和问答证据引用结构。
- [ ] `ChatAnswer` 包含中文回答、证据依据、限制、后续建议、证据请求和 ready 状态。
- [ ] 为问题长度、回答列表、证据请求数量和会话历史设置合理的单项安全边界，但不限制诊断候选原因总数。
- [ ] 编写失败测试，覆盖空问题、超长问题、非法证据字段、跨 analysis_id 请求和额外字段拒绝。
- [ ] 编写敏感字段测试，证明本地路径、API Key、Payload 和完整日志不能进入模型问答上下文。
- [ ] 运行领域与对话单元测试以及 Ruff。
- [ ] 提交，建议中文提交信息：`feat: 定义CLI问答领域契约`。

验收标准：问答输入输出结构稳定，CLI 本地状态与模型上下文边界明确，非法请求在调用模型或 MCP 前被拒绝。

---

## 任务 2：实现自由自然语言参数抽取

涉及文件：

- `src/packetmaster/intent.py`
- `src/packetmaster/model.py`
- `src/packetmaster/prompts/diagnosis_intent.md`
- `tests/unit/test_intent.py`
- `tests/unit/test_chat_model.py`

- [ ] 实现本地 pcap/pcapng 路径提取器，支持引号、空格、中文、相对路径、Windows 盘符和 macOS 路径。
- [ ] 将真实路径替换为不透明占位符，维护只存在于本地状态的双向映射。
- [ ] 定义结构化意图抽取 Prompt 和模型调用，输出路径引用、标准带宽、实际带宽、单位、方向、缺失项和歧义项。
- [ ] 支持 Mbps、Gbps、M、G、兆、千兆等常见单位，并由确定性代码统一换算为 Mbps。
- [ ] 未出现方向表达时确定性默认为 download；明确上行和双向表达分别归一化为 upload 和 both。
- [ ] 实现多轮字段级合并，支持“实际改成 580M”“不是上行，是双向”等自然语言修正。
- [ ] 多路径、多个无角色带宽、冲突单位和含糊方向必须进入澄清状态，不得猜测。
- [ ] 完整参数生成本地确认摘要，用户确认前不得调用诊断图或 MCP。
- [ ] 模型超时、依赖缺失或结构化输出失败时降级为逐项引导输入。
- [ ] 测试 Prompt 注入文本不能触发工具、改变默认方向或绕过确认。
- [ ] 测试模型消息不包含真实绝对路径、API Key 或报文内容。
- [ ] 运行意图抽取测试和 Ruff。
- [ ] 提交，建议中文提交信息：`feat: 实现自然语言诊断参数抽取`。

验收标准：一句话可以抽取全部诊断参数；不完整、冲突和修正表达可稳定处理；真实路径不进入模型；任何分析都经过确定性校验和用户确认。

---

## 任务 3：实现会话生命周期和内置命令解析

涉及文件：

- `src/packetmaster/chat.py`
- `src/packetmaster/artifacts.py`
- `tests/unit/test_chat.py`
- `tests/unit/test_artifacts.py`

- [ ] 实现会话创建、当前分析绑定、问答轮次追加、历史裁剪和 `/new` 状态重置。
- [ ] 实现 `/new`、`/report`、`/evidence`、`/save`、`/help` 和 `/quit` 的确定性解析。
- [ ] 未知 `/` 命令返回帮助提示，不进入模型。
- [ ] 空输入不进入模型；EOF 和 Ctrl+C 映射为正常退出事件。
- [ ] 会话期间为当前任务维护 active 标记，结束或切换任务时可靠移除。
- [ ] 保留最近 8 个问答轮次，旧轮次进入有界摘要；同时验证序列化字节上限。
- [ ] 测试命令不区分大小写的范围并固定最终规则，避免不同平台行为漂移。
- [ ] 运行会话、产物测试和 Ruff。
- [ ] 提交，建议中文提交信息：`feat: 实现CLI会话状态管理`。

验收标准：命令不依赖模型，会话切换不会串用 analysis_id，退出后无残留 active 状态。

---

## 任务 4：重构可复用的诊断执行入口

涉及文件：

- `src/packetmaster/cli.py`
- `src/packetmaster/chat.py`
- `src/packetmaster/artifacts.py`
- `tests/integration/test_cli.py`

- [ ] 从现有一次性 CLI 中提取可复用诊断服务，供 `diagnose` 和 `chat` 共用。
- [ ] 服务返回诊断报告、analysis_id、报告路径和问答所需的有界上下文引用，不返回原始报文内容。
- [ ] 保持现有中文进度回调、错误映射和相对路径归一化。
- [ ] 保证 `diagnose` 的终端输出、退出码和 JSON 报告路径保持兼容。
- [ ] 证明 chat 首次诊断只调用一次基础分析，后续问答不会再次调用 analyze 工具。
- [ ] 覆盖诊断失败、报告降级和用户取消时的资源清理。
- [ ] 运行 CLI 集成测试、真实流水线回归和 Ruff。
- [ ] 提交，建议中文提交信息：`refactor: 复用诊断执行服务`。

验收标准：两个 CLI 命令共享同一诊断实现，原有 `diagnose` 无行为回归，chat 能获得后续问答所需会话句柄。

---

## 任务 5：实现结构化问答模型和中文 Prompt

涉及文件：

- `src/packetmaster/model.py`
- `src/packetmaster/prompts/chat_answer.md`
- `src/packetmaster/prompts/chat_verify.md`
- `tests/unit/test_context.py`
- `tests/unit/test_chat_model.py`

- [ ] 增加基于 `ChatAnswer` Schema 的问题回答和证据复核方法。
- [ ] 复用 OpenAI 兼容接口、DeepSeek 自动 `json_mode`、JSON Schema 注入和一次结构修复重试。
- [ ] Prompt 明确区分直接证据、间接判断、报文外信息和用户假设。
- [ ] Prompt 要求所有用户可见文本为简体中文，不翻译机器字段和协议标识。
- [ ] Prompt 禁止重复整份报告、编造帧号、伪造证据和输出隐藏推理。
- [ ] 模型只接收当前问题、有界报告上下文、最近问答、摘要和当前问题证据。
- [ ] 使用无网络 Fake Model 测试正常回答、证据请求、Schema 修复、超时和非法输出。
- [ ] 运行模型问答测试和 Ruff。
- [ ] 提交，建议中文提交信息：`feat: 增加证据约束问答模型`。

验收标准：DeepSeek 类模型能够输出合法中文问答结构，结构波动可修复，敏感数据不进入消息。

---

## 任务 6：实现有界问答 LangGraph

涉及文件：

- `src/packetmaster/chat_graph.py`
- `src/packetmaster/chat.py`
- `tests/fakes.py`
- `tests/unit/test_chat_graph.py`

- [ ] 构建 prepare_question、answer_question、inspect_question_evidence、verify_answer 和 finalize_answer 节点。
- [ ] 使用现有 MCP `get_tcp_evidence`，复用字段白名单、分页、analysis_id 一致性和响应大小校验。
- [ ] 每个问题最多两轮取证，每轮最多 5 个请求；达到上限后带限制结束。
- [ ] 无需额外证据的问题直接回答，不调用 MCP。
- [ ] 证据不足、产物过期或查询失败时保留可用回答并说明限制。
- [ ] trace 只记录节点、轮次、状态、错误码和请求数量，不记录问题及回答正文。
- [ ] 编写路由测试，覆盖直接回答、一轮取证、两轮上限、跨任务请求和错误恢复。
- [ ] 证明问答图不会调用基础 analyze 工具。
- [ ] 运行问答图测试和 Ruff。
- [ ] 提交，建议中文提交信息：`feat: 实现有界证据问答图`。

验收标准：问答路由确定、证据可追溯、循环有上限、错误不会破坏当前聊天会话。

---

## 任务 7：实现 chat CLI 自然语言输入和持续提示符

涉及文件：

- `src/packetmaster/cli.py`
- `src/packetmaster/report.py`
- `src/packetmaster/chat.py`
- `tests/integration/test_cli_chat.py`

- [ ] 注册 `packetmaster chat` 命令。
- [ ] 首个提示符接收自由自然语言任务描述，并展示抽取、补问、修正和确认流程。
- [ ] 保留逐项引导作为模型抽取失败时的降级路径。
- [ ] 空方向固定为 download，显式 upload 和 both 原样传递。
- [ ] 诊断完成后进入稳定的 `PacketMaster>` 问答提示符。
- [ ] 实现 `/report` 的完整诊断摘要渲染和 `/evidence` 的有界证据渲染。
- [ ] 实现 `/save`、`/help`、`/new` 和 `/quit` 的中文输出。
- [ ] 问答失败后保持提示符可用，允许用户继续查看报告或开始新任务。
- [ ] 覆盖空格路径、中文路径、相对路径和 Windows 盘符路径。
- [ ] 覆盖 EOF、Ctrl+C、空问题和未知命令。
- [ ] 运行 CLI chat 集成测试和 Ruff。
- [ ] 提交，建议中文提交信息：`feat: 增加CLI持续对话模式`。

验收标准：用户无需记忆 diagnose 参数即可完成分析，并能在同一进程中连续问答和切换任务。

---

## 任务 8：强化问答隐私、持久化和跨平台行为

涉及文件：

- `src/packetmaster/context.py`
- `src/packetmaster/chat.py`
- `src/packetmaster/artifacts.py`
- `src/packetmaster/platform.py`
- `tests/unit/test_chat.py`
- `tests/integration/test_cli_chat.py`

- [ ] 对聊天上下文应用递归敏感字段过滤，覆盖嵌套 Payload、Token、Authorization、日志和路径。
- [ ] 验证自然语言参数抽取消息只包含路径占位符，不包含真实本地路径。
- [ ] 确保聊天历史、trace 和错误详情不包含 API Key 或原始报文内容。
- [ ] 对会话摘要、最近轮次、单个回答和证据页设置字节预算测试。
- [ ] 验证 Windows 控制台中文输入输出、反斜杠路径、Ctrl+C 和子进程清理。
- [ ] 验证 macOS UTF-8 终端、空格路径、EOF 和信号处理。
- [ ] 验证产物 TTL 清理不会删除 active 会话，退出后可按策略正常清理。
- [ ] 增加失败注入测试，覆盖模型超时、MCP 超时、证据数据库缺失和报告文件不可写。
- [ ] 运行安全、跨平台和集成测试。
- [ ] 提交，建议中文提交信息：`test: 强化CLI问答安全与跨平台验证`。

验收标准：问答功能不扩大现有数据泄露面，Windows 和 macOS 的输入、退出和清理行为一致。

---

## 任务 9：真实模型验收、文档和发布门禁

涉及文件：

- `README.md`
- `.github/workflows/test.yml`
- `tests/integration/test_cli_chat.py`
- `docs/superpowers/specs/2026-07-24-packetmaster-cli-chat-design.md`

- [ ] 更新 README，说明 `packetmaster chat`、内置命令、默认下载方向和本地模型配置。
- [ ] 使用确定性虚拟报文完成真实 DeepSeek 端到端问答验收。
- [ ] 使用一句话输入完整参数，并验证缺失参数追问、字段修正和确认拒绝流程。
- [ ] 连续询问主因依据、具体异常位置、其他候选和排查建议。
- [ ] 检查回答为中文、证据可定位、候选置信度为百分数且主因选择正确。
- [ ] 检查模型输入、终端输出、trace 和报告中不存在 API Key 与 Payload。
- [ ] 在 Windows 发布门禁和 macOS 兼容门禁中加入无网络 CLI chat 测试。
- [ ] 运行全部非性能测试、Ruff 和打包测试。
- [ ] 保留并记录 Python 3.12/psutil 既有子进程回收测试问题，不混入功能修复。
- [ ] 提交，建议中文提交信息：`docs: 完善CLI问答使用与验收说明`。

验收标准：`packetmaster chat` 在真实 DeepSeek 和测试替身两条路径均可使用，现有 diagnose 回归通过，Windows 发布门禁和 macOS 兼容门禁稳定。

## 完成定义

- `packetmaster chat` 能引导完成 download、upload 和 both 诊断。
- 一句自由自然语言可以抽取完整诊断参数，缺失、歧义和修正可继续多轮处理。
- 真实报文路径在模型输入中始终使用本地占位符，用户确认前不启动分析。
- 用户可围绕当前报告持续问答，并使用全部内置命令。
- 问答需要额外证据时通过 FastMCP 分页查询，不重新扫描完整报文。
- 每个问题的取证循环和上下文大小均有明确上限。
- 回答严格区分报文事实、间接判断和报文外限制。
- 原始报文、Payload、完整日志、本地路径和 API Key 不进入模型或 trace。
- DeepSeek 结构化输出兼容，用户可见文本为简体中文。
- Windows 和 macOS 验收通过，现有 `packetmaster diagnose` 行为不回归。
