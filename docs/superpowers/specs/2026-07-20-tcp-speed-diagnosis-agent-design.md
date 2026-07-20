# TCP 测速速率不达标诊断 Agent 设计

日期：2026-07-20

## 1. 背景

项目已有 speed-analyze skill。它接收 pcapng 报文和分析方向，通过 speed_filter_strip.py 筛选测速流，再通过 tcp_extract.py 提取 TCP 字段并计算吞吐量、RTT、重传、窗口和 TCP 选项等指标。现有 SKILL.md 最后由大模型读取 JSON 并生成诊断结果。

本项目的目标不是再包装一次 skill，而是在其确定性报文处理能力之上构建一个可控、可追溯、能主动补充证据的交互式 Agent。

## 2. 第一版目标

第一版提供 CLI 交互式诊断能力，用户输入：

- pcap 或 pcapng 文件路径
- 标准带宽，单位 Mbps
- 实际带宽，单位 Mbps
- 分析方向：download、upload 或 both

Agent 应完成：

1. 校验输入并计算达标率等确定性指标。
2. 通过 FastMCP 调用报文分析工具。
3. 根据紧凑指标摘要形成候选原因。
4. 在证据不足时主动查询指定流、时间段或字段的详细证据。
5. 对候选原因进行证据复核。
6. 输出主因、候选原因、证据、置信度、限制、排查步骤和优化建议。
7. 保存结构化报告、分析产物和运行轨迹。

## 3. 非目标

第一版不包含：

- Web 页面
- 批量任务平台
- 告警和外部监控系统集成
- 向量数据库
- RAG 知识库
- 多 Agent 协作
- 自动执行网络配置变更

第一版完整实现 Mock Adapter，保证 CLI、LangGraph、FastMCP、模型调用和报告生成可以端到端运行。真实 Adapter 使用相同接口，并预留接入现有 speed-analyze 的边界。真实 Adapter 的完整跨平台适配属于后续里程碑。

## 4. 技术决策

### 4.1 交互形式

第一版使用 CLI。这样可以优先验证诊断流程和工具编排，避免引入前端范围。

### 4.2 Agent 编排

使用单 Agent 和 LangGraph 显式状态图。LangGraph 负责规定节点、条件分支、循环次数、错误恢复和最终结束条件；大模型只负责需要语义判断的候选原因生成、证据需求判断和报告表达。

### 4.3 工具协议

使用 FastMCP 提供本地 MCP Server。Agent 通过 MCP Client 调用两个工具：

- analyze_speed_capture：执行一次基础报文分析并返回紧凑摘要
- get_tcp_evidence：按需返回分页后的详细证据

MCP Tool 只提供数据和证据，不直接生成最终诊断原因。

### 4.4 模型接口

使用 OpenAI 兼容接口，并通过环境配置以下参数：

- MODEL_BASE_URL
- MODEL_API_KEY
- MODEL_NAME
- MODEL_TIMEOUT_SECONDS

Agent 不绑定单一模型厂商。

### 4.5 数据模型

使用 Pydantic 定义：

- CLI 输入
- AgentState
- MCP Tool 输入输出
- 候选原因
- 证据记录
- 错误对象
- 最终诊断报告

模型产生的结构化结果必须通过 Schema 校验。

## 5. 总体架构

    CLI
      |
      v
    LangGraph Agent
      |
      v
    FastMCP Client
      |
      v
    FastMCP Server
      |
      +-- MockSpeedAnalyzerAdapter
      |
      +-- RealSpeedAnalyzerAdapter
              |
              v
         speed-analyze

主要组件如下。

### 5.1 CLI

CLI 负责收集参数、显示状态进度、进行必要的用户追问，并输出人类可读报告。CLI 同时将最终 JSON 报告写入任务目录。

建议命令形式：

    speed-agent diagnose <pcap_path> \
      --standard 1000 \
      --actual 300 \
      --target download

### 5.2 LangGraph Agent

Agent 维护单次任务的共享状态，并执行确定的诊断流程。它不能绕过输入校验、证据复核或循环上限。

### 5.3 FastMCP Server

FastMCP Server 隔离 Agent 与底层脚本。Agent 只依赖 MCP Schema，不依赖 speed-analyze 的文件名和内部实现。

### 5.4 Adapter

第一版实现 Mock Adapter，并定义 Real Adapter 必须遵循的相同内部协议：

- analyze
- get_evidence

运行模式通过 SPEED_ANALYZER_MODE=mock 或 real 选择。

### 5.5 Artifact Store

每次分析创建独立目录：

    output/<analysis_id>/
      speed_stats.json
      tcp_analysis.json
      report.json
      trace.jsonl
      logs/

不同任务不得复用同名中间文件。

## 6. Agent 状态

AgentState 至少包含：

- messages：CLI 多轮交互消息
- pcap_path：输入报文路径
- standard_bandwidth_mbps：标准带宽
- actual_bandwidth_mbps：实际带宽
- target：分析方向
- achievement_ratio_pct：达标率
- analysis_id：分析任务标识
- flow_summary：测速流摘要
- tcp_summary：TCP 核心指标
- syn_options：TCP 握手选项
- candidate_causes：候选原因
- collected_evidence：已经获取的证据
- missing_evidence：仍需查询的证据
- inspection_count：详细查询次数
- warnings：非致命警告
- final_report：最终报告
- error：结构化错误

状态中只保存结构化候选结论和证据需求，不保存或展示模型的内部思维过程。

## 7. LangGraph 节点

### 7.1 collect

从 CLI 收集或补充报文路径、带宽和分析方向。如果信息缺失，停留在交互流程，不调用模型或 MCP。

### 7.2 validate

通过确定性代码完成：

- 文件存在性和可读性检查
- 文件扩展名检查
- 带宽参数正数检查
- 分析方向检查
- 达标率计算
- 是否确实属于不达标场景的判断

### 7.3 analyze

调用 analyze_speed_capture，写入 analysis_id、流摘要、TCP 摘要、TCP 选项、可用证据类型、产物路径和警告。

### 7.4 reason

调用模型，根据带宽信息和紧凑摘要输出：

- 候选原因
- 已支持该原因的指标
- 仍需查询的证据
- 初始置信度等级

reason 节点不直接输出最终报告。

### 7.5 inspect_evidence

根据 missing_evidence 调用 get_tcp_evidence。每次请求必须指定证据类型，并可指定流、时间范围、字段、偏移量和数量。

详细证据查询最多三轮。

### 7.6 verify

复核以下内容：

- 每个原因是否有具体证据
- 原因与证据是否矛盾
- 是否将相关性错误描述为确定因果
- 置信度是否与证据强度匹配
- 是否还需要获取详细证据

证据不足且查询次数未达到上限时，返回 inspect_evidence。达到上限后进入 report，并在限制中说明证据不足。

### 7.7 report

生成符合固定 Schema 的分层诊断报告，并同时输出终端文本和 report.json。

## 8. 状态转移

主路径：

    collect
      -> validate
      -> analyze
      -> reason
      -> verify
      -> report

需要详细证据时：

    reason
      -> inspect_evidence
      -> verify
      -> inspect_evidence
      -> verify
      -> report

缺少用户参数时：

    collect
      -> validate
      -> collect

工具或模型发生不可恢复错误时，进入统一错误结束状态。存在部分指标时，允许生成明确标注未完成智能诊断的降级报告。

## 9. MCP Tool 契约

### 9.1 analyze_speed_capture

输入：

    {
      "request_id": "20260720-a13f",
      "pcap_path": "/data/test.pcapng",
      "target": "download",
      "max_packets": 5000
    }

标准带宽和实际带宽不传给该工具。它们不影响报文提取，由 Agent 的确定性逻辑用于达标率、BDP 和报告上下文计算。

request_id 由 Agent 在调用前生成。MCP Server 将它作为 analysis_id 使用；重试相同 request_id 时复用已有任务和产物。

输出包含：

- analysis_id
- status
- flow_summary
- tcp_summary
- syn_options
- available_evidence
- warnings
- artifact_paths

输出只包含适合进入模型上下文的紧凑摘要，不包含完整 per_packet_fields。

### 9.2 get_tcp_evidence

输入包含：

- analysis_id
- evidence_type
- flow_id，可选
- time_start，可选
- time_end，可选
- fields，可选
- offset
- limit

支持的 evidence_type 至少包括：

- retransmissions
- duplicate_acks
- out_of_order
- window_changes
- zero_window
- io_timeline
- syn_options
- packet_fields

输出包含：

- analysis_id
- evidence_type
- summary
- items
- total
- next_offset
- truncated
- warnings

每一项逐包证据必须包含可追溯的报文编号、相对时间和流标识。

### 9.3 Tool 约束

- 强制分页
- 限制最大返回条数
- 限制字段白名单
- analysis_id 必须属于当前 Artifact Store
- 相同 request_id 的重复调用必须幂等
- 工具不得直接生成原因概率
- 不将原始 pcap 内容返回给模型

## 10. 完整数据流

1. CLI 收集输入。
2. validate 检查参数并计算达标率。
3. analyze 调用 analyze_speed_capture。
4. MCP Server 根据配置选择 Mock 或 Real Adapter。
5. Adapter 生成或读取统计产物。
6. MCP Server 返回紧凑摘要。
7. reason 形成候选原因和证据需求。
8. inspect_evidence 按需查询详细证据。
9. verify 复核结论与证据。
10. report 生成最终报告。
11. Artifact Store 保存报告和轨迹。

## 11. 最终报告

最终报告至少包含：

- standard_bandwidth_mbps
- actual_bandwidth_mbps
- achievement_ratio_pct
- target
- primary_cause
- candidate_causes
- key_evidence
- confidence
- limitations
- troubleshooting_steps
- optimization_suggestions
- analysis_metadata

候选原因包含：

- cause
- confidence
- evidence
- affected_flows
- explanation
- suggestion

confidence 使用 high、medium、low 等级。它表示基于当前证据的诊断置信度，不宣称为经过统计校准的概率。

## 12. 异常处理

统一错误结构包含：

- code
- message
- recoverable
- suggested_action
- details

### 12.1 输入错误

在 validate 节点处理，不调用模型或 MCP。包括文件不存在、格式不支持、带宽参数非法和方向非法。

### 12.2 环境依赖错误

真实 Adapter 检查 Python、Scapy、TShark 和输出目录。

TShark 查找顺序：

1. TSHARK_PATH 环境变量
2. 系统 PATH
3. Windows 和 macOS 常见安装路径

当前 speed-analyze/scripts/tcp_extract.py 固定了 Windows 路径，真实 Adapter 接入时必须通过配置或自动发现消除该限制。

### 12.3 报文分析错误

定义以下错误码：

- INVALID_CAPTURE
- NO_TCP_PACKETS
- NO_SPEED_FLOW
- ANALYSIS_TIMEOUT
- ANALYSIS_FAILED
- INVALID_ANALYSIS_OUTPUT
- EVIDENCE_NOT_FOUND

部分方向分析成功时返回部分结果，并通过 warnings 说明。

### 12.4 MCP 错误

临时连接错误最多重试两次，采用短暂退避。失败后保存当前 LangGraph 状态。

### 12.5 模型错误

限流或超时最多重试两次。结构化结果校验失败时，允许一次 Schema 修复请求。模型最终不可用时，输出基础指标摘要，不重新运行报文分析。

### 12.6 证据不足

证据不足不是系统错误。Agent 必须降低置信度、列出缺失证据，并区分已证实、较可能和无法判断。

## 13. 安全与隐私

- pcap 和完整逐包数据只在本机处理
- 只向模型发送必要的指标和少量证据
- API Key 不写入日志
- MCP 限制可访问文件路径
- 每个任务使用独立目录
- 报告记录模型、工具版本和证据引用
- 日志不得包含原始 TCP payload

## 14. 现有 speed-analyze 接入注意事项

真实 Adapter 后续接入时需要处理：

1. tcp_extract.py 的 TShark 路径固定为 Windows 路径。
2. run_pipeline.py 每个方向只采用第一个成功端口，可能遗漏并行测速流。
3. per_packet_fields 最多包含 5000 个报文，必须在 MCP 层摘要和分页。
4. 当前吞吐量和服务端、客户端推断偏下载场景，上行需要专项验证。
5. 筛选脚本支持 IPv6 流识别，但 tcp_extract.py 使用 ip.src 和 ip.dst，IPv6 字段完整性需要验证。
6. skill 文档描述为自包含，但真实运行仍依赖 Scapy 和 TShark。

这些问题不改变 MCP 契约，修复可以限制在 Real Adapter 或 speed-analyze 内部。

## 15. 测试策略

### 15.1 单元测试

覆盖输入校验、达标率、BDP、方向、置信度映射和错误对象。

### 15.2 MCP 契约测试

覆盖：

- Schema 校验
- 幂等性
- 独立任务目录
- 分页
- 字段白名单
- 时间范围过滤
- 无效 analysis_id
- Mock 与 Real Adapter 接口一致性

### 15.3 LangGraph 路由测试

使用固定模型响应验证：

- 缺失输入返回 collect
- 证据充分直接 verify 和 report
- 证据不足进入 inspect_evidence
- 最多三次详细查询
- MCP 失败进入错误状态
- 模型失败执行重试或降级
- 证据不足时不会输出高置信度结论

### 15.4 CLI 端到端测试

在 Mock 模式验证：

- CLI 显示进度
- MCP Tool 调用符合预期
- 详细证据按需查询
- 终端和 JSON 报告均生成
- 轨迹文件生成
- API Key 不进入日志

### 15.5 诊断质量评测

固定案例覆盖：

- 高重传和重复 ACK
- 高 RTT 或 RTT 波动
- 窗口过小或零窗口
- MSS、WScale、SACK 异常
- 严重乱序
- 多原因并存
- 数据不足
- TCP 指标正常但速度不达标

评测不要求自然语言完全一致，但要求原因有证据、置信度与证据匹配、报告符合 Schema，并能区分直接证据和推测。

## 16. 第一版验收标准

第一版被视为完成时：

1. 用户可以通过一条 CLI 命令启动诊断。
2. Mock FastMCP Server 能端到端运行。
3. OpenAI 兼容模型能生成符合 Schema 的诊断。
4. Agent 能主动决定是否查询详细证据。
5. 详细证据查询最多三轮。
6. 最终报告包含主因、候选原因、证据、置信度、限制、排查步骤和建议。
7. MCP 或模型失败时提供可执行的错误提示。
8. 分析状态、工具调用和证据引用可以追溯。
9. Real Adapter 接口已经预留，可在后续里程碑接入现有 speed-analyze。
10. RAG 不在第一版范围内，但图结构允许后续插入知识检索节点。

## 17. 后续演进

### 17.1 真实 Adapter

实现跨平台 TShark 发现、调用现有流水线、解析产物，并补充上行、多流和 IPv6 验证。

### 17.2 RAG

在 reason 与 verify 之间插入 retrieve_knowledge 节点，知识源可包含 RFC、Linux TCP 文档、内部故障案例和历史诊断报告。RAG 只补充机制解释与案例证据，不替代报文证据。

### 17.3 诊断质量提升

- 引入确定性规则评分
- 建立带标签的回归案例集
- 校准置信度
- 对不同模型进行离线评测

### 17.4 产品化

- HTTP API
- Web 聊天界面
- 批量分析
- 监控平台集成
