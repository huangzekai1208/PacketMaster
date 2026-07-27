# PacketMaster 现阶段功能与工作流程

更新日期：2026-07-27

## 1. 项目定位

PacketMaster 是一个用于分析 TCP 测速速率不达标原因的单 Agent 智能体。它在本机对 pcap/pcapng 报文执行全量流式统计，通过 LangGraph 编排诊断步骤，通过 FastMCP 获取基础分析结果和局部证据，再由大模型生成并复核开放式候选原因。

PacketMaster 不是对 speed-analyze 的简单调用包装。speed-analyze 负责确定性的报文筛选、字段提取、指标聚合和证据索引；PacketMaster 在此基础上增加参数理解、任务编排、候选原因推理、主动取证、证据复核、报告生成和持续问答。

当前版本同时提供 CLI 和本机 Web 工作台。RAG 知识库、多 Agent 协作和批量任务平台尚未接入。

## 2. 已实现功能

### 2.1 TCP 测速诊断

- 输入 pcap 或 pcapng 报文、标准带宽、实际带宽和可选分析方向。
- 默认只分析下载方向；只有用户明确指定时才分析上行或双向。
- 支持 Mbps、Gbps、M、G、兆和千兆等常见单位。
- 未填写带宽单位时按 Mbps 解释。
- 计算带宽达标率，并结合报文中的 TCP 指标分析速率不达标原因。
- 候选原因不受固定清单限制，可以根据实际统计和证据生成新的数据驱动假设。
- 输出主因、候选原因、支持证据、反向证据、缺失证据、置信度、限制、排查步骤和优化建议。

### 2.2 CLI 持续对话

- 支持普通问候、能力咨询和 TCP 概念问答。
- 支持用一句自然语言提交完整诊断任务。
- 支持分多轮补充报文路径、标准带宽、实际带宽和方向。
- 使用本地确定性规则优先抽取路径和明确带宽，减少模型结构化输出波动造成的失败。
- 参数不完整时逐项追问；参数完整后必须由用户确认才启动分析。
- 诊断完成后可以围绕当前报告继续追问，Agent 可按需查询局部证据。
- 保留最近 8 轮对话，超出部分进入有界摘要。

当前内置命令：

| 命令 | 功能 |
| --- | --- |
| `/new` | 清空当前任务并开始新会话 |
| `/report` | 查看当前完整中文报告 |
| `/evidence` | 查看当前报告中的关键证据 |
| `/save` | 查看 JSON 报告位置 |
| `/help` | 查看命令帮助 |
| `/quit` | 退出 PacketMaster |

### 2.3 Web 对话与可视化工作台

- 使用 `packetmaster web` 同时启动 FastAPI、独立单 Worker 和 React 静态页面。
- 默认且仅监听 `127.0.0.1`，MVP 不提供公网监听和登录系统。
- 使用 SQLite WAL 持久化会话、消息、报文引用、任务、SSE 事件和诊断后问答。
- 页面刷新或关闭不会终止后台分析，重新打开后可恢复会话和任务状态。
- 支持普通对话、分轮参数补充、参数确认、默认下载方向和方向修正。
- 支持运行进度、取消确认、失败或中断任务重试。
- 支持报告、候选原因、吞吐、RTT、TCP 事件、完整 TCP 流分页和证据分页。
- 诊断后问答绑定当前 `analysis_id`，复用有界 LangGraph 取证流程，不重复执行基础分析。
- 浏览器只保存会话 ID、布局和非敏感草稿，不保存 API Key、绝对路径、完整报告或证据。

### 2.4 大报文处理

- 面向几百 MB 到数 GB 的报文设计。
- 原始报文由本地脚本和 TShark 流式处理，不经过 LangGraph 状态或模型上下文。
- 对全部目标测速流执行聚合，不以开头若干报文代替完整测速过程。
- 先形成全局、每流和时间区间摘要，再围绕异常区间分页取证。
- 运行前检查输入文件和可用磁盘空间。
- 支持动态分析超时、进度消息、子进程取消和过期产物清理。

### 2.5 平台兼容

- Windows 是正式运行和发布验收平台。
- macOS 是当前开发和兼容验证平台。
- 支持 Windows 盘符、反斜杠、空格和中文路径。
- 支持 macOS 绝对路径、相对路径和常见 Wireshark/TShark 安装位置。
- 子进程通过参数数组启动，文本产物统一使用 UTF-8。
- Web Worker 使用 `spawn` 启动方式，不依赖 Unix `fork`。

## 3. 使用入口

### 3.1 一次性诊断

```bash
packetmaster diagnose <报文路径> --standard 1000 --actual 600
```

省略 `--target` 时使用 `download`。显式分析上行或双向时使用：

```bash
packetmaster diagnose <报文路径> --standard 1000 --actual 600 --target upload
packetmaster diagnose <报文路径> --standard 1000 --actual 600 --target both
```

### 3.2 对话诊断

```bash
packetmaster chat
```

完整输入示例：

```text
分析 test.pcapng，标准带宽 1G，实际带宽 600M
```

分轮输入示例：

```text
用户：帮我分析测速不达标原因
PacketMaster：请提供要分析的 pcap 或 pcapng 报文文件路径。
用户：test.pcapng
PacketMaster：请告诉我标准带宽，例如 1000 Mbps。
用户：1000
PacketMaster：请告诉我实际测速带宽，例如 600 Mbps。
用户：600
```

只提供文件名时，PacketMaster 会在当前工作目录和当前工作目录的 `samples` 目录中定位文件。生产使用建议提供绝对路径，避免文件同名或工作目录变化。

### 3.3 Web 工作台

```bash
packetmaster web
```

启动后浏览器访问本机 URL。Web 首版不上传大报文，而是注册本机绝对路径；后端完成允许目录、文件类型和可读性校验后，前端仅使用 `capture_id`。

Web 操作流程：

```text
新建或恢复会话
  -> 普通对话或诊断意图识别
  -> 注册本机报文
  -> 补充并确认带宽和方向
  -> SQLite 创建 queued 任务
  -> 独立 Worker 执行共享诊断服务
  -> SSE 展示并恢复进度
  -> 报告、指标、流和证据可视化
  -> 围绕当前 analysis_id 持续问答
```

## 4. 从输入到报告的总体流程

```text
用户输入
  |
  v
CLI 参数校验或 Web/CLI 对话意图路由
  |
  +-- 普通问题 ----------------------> 通用对话模型 -> 中文回答
  |
  +-- 诊断任务
        |
        v
    本地路径提取、带宽归一化、方向默认
        |
        v
    缺失参数逐项追问 -> 用户确认
        |
        v
    LangGraph 诊断图
        |
        v
    FastMCP Client -> FastMCP Server
        |
        v
    RealAnalyzerAdapter -> speed-analyze + TShark
        |
        v
    全量聚合摘要 + 本地 SQLite 证据索引
        |
        v
    候选原因生成 -> 局部取证 -> 证据复核
        |
        v
    共享 DiagnosticReport + report.json + trace.jsonl
        |
        v
    CLI 中文输出或 Web 报告/图表/证据
        |
        v
    基于当前 analysis_id 的持续证据问答
```

## 5. 诊断 LangGraph 工作流程

一次诊断由六个节点组成：

1. `validate`：校验报文路径、带宽、分析方向、磁盘预算和请求结构。
2. `analyze`：通过 MCP 调用 `analyze_speed_capture`，执行 speed-analyze 全量基础分析。
3. `reason`：Context Builder 将聚合结果压缩为有界上下文，大模型生成开放式候选原因和证据请求。
4. `inspect_evidence`：通过 MCP 调用 `get_tcp_evidence`，查询指定流、时间区间或 TCP 字段的分页证据。
5. `verify`：大模型根据新增证据调整候选原因、置信度、反向证据和限制，并判断是否继续取证。
6. `report`：确定性生成最终诊断报告并结束任务。

诊断取证循环最多执行 3 轮，每轮最多处理 10 个证据请求。循环由 LangGraph 控制，大模型不能无限调用工具。即使部分模型调用或证据查询失败，只要已有基础分析结果，系统也会尽量输出带限制说明的降级报告。

## 6. 对话问答工作流程

诊断完成后的每个问题使用独立的有界问答图：

1. `prepare_question`：校验问题，并绑定当前 `analysis_id`。
2. `answer_question`：先根据当前报告、诊断上下文和最近对话尝试回答。
3. `inspect_question_evidence`：上下文不足时，通过 MCP 查询额外证据。
4. `verify_answer`：使用新证据复核回答，判断是否还需继续取证。
5. `finalize_answer`：形成最终中文回答或带限制的降级回答。

单个问题最多取证 2 轮，每轮最多 5 个请求。所有证据请求必须与当前 `analysis_id` 一致，防止不同任务之间混用证据。

## 7. 各组件职责

| 组件 | 当前职责 |
| --- | --- |
| CLI | 收集输入、对话路由、参数补全、用户确认、进度展示和报告输出 |
| React 工作台 | 会话、对话、确认、进度、报告、指标、流、证据和问答交互 |
| FastAPI | 本机安全 API、稳定错误、SSE 和生产静态资源托管 |
| Web Worker | 从 SQLite 领取任务并调用共享诊断服务，处理心跳、取消和终止状态 |
| SQLite Web Store | 保存会话、报文引用、任务、有序事件和问答，不保存报文二进制 |
| LangGraph 诊断图 | 控制校验、分析、推理、取证、复核和结束条件 |
| LangGraph 问答图 | 控制报告问答、额外证据查询和问答循环上限 |
| FastMCP Server | 暴露基础分析和证据查询工具，并校验请求与输出 |
| RealAnalyzerAdapter | 将 MCP 请求连接到 speed-analyze，并读取本地产物和证据索引 |
| speed-analyze | 筛选目标方向 TCP 流、提取字段、全量聚合指标并建立 SQLite 证据索引 |
| Context Builder | 从全量统计中生成有界、分层、允许进入模型的上下文 |
| 大模型 | 理解模糊参数、生成候选原因、提出证据需求、复核原因和回答追问 |
| Artifact Store | 保存覆盖率、统计、证据索引、筛选报文、报告和运行轨迹 |

## 8. 模型上下文与隐私边界

原始报文保留在本机。以下内容不得进入模型上下文：

- pcap/pcapng 二进制内容；
- TCP Payload；
- 完整逐包数据；
- 完整日志；
- API Key、Authorization 和密码；
- 本地绝对路径。

模型可以接收的内容包括：

- 报文覆盖率和是否完整、截断；
- 全局 TCP 指标摘要；
- 有界的每流指标；
- 有界的时间区间指标和异常区间；
- 经字段白名单过滤的分页证据；
- 当前报告、当前问题和有界对话历史。

路径在进入模型前会替换为 `capture_XXXXXXXX` 形式的不透明引用。MCP Server 和 Context Builder 对字段、条数、大小和字符串长度进行约束。

## 9. 本地产物

每次分析使用独立 `analysis_id`，默认在 artifact 根目录下产生：

```text
<analysis_id>/
  coverage.json
  speed_stats.json
  tcp_analysis.json
  analysis.sqlite
  filtered/
  logs/
  report.json
  trace.jsonl
```

- `coverage.json`：输入覆盖率和完整性信息。
- `speed_stats.json`：测速方向、流和时间区间统计。
- `tcp_analysis.json`：TCP 事件和协议指标摘要。
- `analysis.sqlite`：供分页证据查询使用的本地索引。
- `filtered/`：按目标方向筛选后的本地报文。
- `report.json`：最终结构化诊断报告。
- `trace.jsonl`：LangGraph 节点、轮次、状态和错误码轨迹，不记录原始问题、回答正文或报文 Payload。

未标记保留且超过配置有效期的任务产物会被清理；活动任务使用 `.active` 标记避免被误删。

## 10. 当前边界与后续空间

当前版本尚未实现：

- RAG 故障案例和网络知识库；
- 多 Agent 分工协作；
- 多报文批量任务和多 Worker 并发队列；
- CLI 会话退出后的历史恢复；
- 基于 analysis_id 的 `/resume`、`/status` 和 `/cancel` 命令；
- 自动修改操作系统或网络设备配置。

现阶段已经形成单 Agent、全量流式报文分析、证据驱动推理、CLI 和 Web 持续问答闭环。macOS 本地自动化、真实 TShark 和浏览器门禁已完成；Windows 真机启动、真实 TShark、取消后进程树清理和大报文门禁需要按发布清单完成最终验收。RAG 等能力应在积累经过确认的诊断案例、术语定义和处置规则后接入，作为证据解释和经验检索的补充，而不是替代报文直接证据。
