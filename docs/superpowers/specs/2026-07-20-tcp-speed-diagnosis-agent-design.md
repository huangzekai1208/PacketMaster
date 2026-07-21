# TCP 测速速率不达标诊断 Agent 设计

日期：2026-07-20

修订日期：2026-07-21

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
8. 第一版直接通过 Real Adapter 接入现有 speed-analyze。
9. 支持几百 MB 到数 GB 的 pcapng，报文处理过程不得将完整文件载入内存。
10. 对完整测速过程执行全量流式聚合，再根据异常区间进行局部取证。
11. 候选原因集合保持开放，常见原因只作为基础排查清单，不作为原因白名单。

## 3. 非目标

第一版不包含：

- Web 页面
- 批量任务平台
- 告警和外部监控系统集成
- 向量数据库
- RAG 知识库
- 多 Agent 协作
- 自动执行网络配置变更

第一版以 Real Adapter 为正式运行路径，直接接入并加固现有 speed-analyze。Mock Adapter 仅用于单元测试、契约测试和无需真实报文的演示。

## 4. 技术决策

### 4.1 交互形式

第一版使用 CLI。这样可以优先验证诊断流程和工具编排，避免引入前端范围。

### 4.2 Agent 编排

使用单 Agent 和 LangGraph 显式状态图。LangGraph 负责规定节点、条件分支、循环次数、错误恢复和最终结束条件；大模型只负责需要语义判断的候选原因生成、证据需求判断和报告表达。

reason、inspect_evidence、verify 构成“基于证据的有界 ReAct”循环：

- reason 对应 Reason：生成候选原因和下一步证据需求
- inspect_evidence 对应 Action：调用 MCP Tool 获取证据
- MCP 返回值对应 Observation
- verify 判断证据是否充分，以及继续循环还是结束

它不是允许模型无限自主调用工具的纯 ReAct。工具范围、最大三轮取证和结束条件均由 LangGraph 控制。

候选原因采用开放式假设生成。Agent 先执行常见模式基线排查，再从全量统计的异常、变化和指标关联中生成数据驱动假设。模型可以提出清单之外的原因，但必须说明证据、反向证据、缺失证据和报文可观测性。

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

### 4.6 大报文处理原则

几百 MB 到数 GB 的报文只在本地磁盘流水线中处理。CLI、LangGraph 和 MCP 调用之间只传递文件路径、analysis_id、覆盖率、聚合摘要和分页证据，不传递 pcapng 二进制内容。

采用“全量统计、局部取证”：

1. 对全部测速流执行流式聚合。
2. 生成全局、每流和时间区间指标。
3. 将异常事件和时间区间写入本地证据索引。
4. 只把紧凑摘要和覆盖率发送给模型。
5. 模型需要进一步判断时，通过 get_tcp_evidence 查询局部证据。

不得使用“前若干个报文”代表完整测速过程。返回给模型的条数限制只适用于证据响应，不适用于基础统计覆盖范围。

### 4.7 模型上下文构建

只向模型发送局部信息并不等于只分析局部报文。上下文由确定性的 Context Builder 从全量聚合结果中分层生成：

1. 覆盖层：文件大小、报文数、字节数、测速持续时间、流数量、complete 和 truncated。
2. 全局层：总吞吐量、RTT 分布、重传率、窗口统计、TCP 选项和总体异常计数。
3. 每流层：各测速流的吞吐量、RTT、重传、窗口和异常排名。
4. 时间层：固定时间粒度统计、分位数、突变点和异常时间区间。
5. 证据层：与候选原因相关的少量逐包证据。

如果流数量或时间区间过多，Context Builder 可以压缩正常区间，但必须保留所有异常区间、被省略数量、聚合方法和覆盖范围。模型可以通过 get_tcp_evidence 查询未展开的流或区间。

模型不负责决定基础统计是否完整。verify 节点必须先检查 coverage_summary，再判断诊断置信度。

Context Builder 不预先将异常映射为固定原因。它输出客观事实，例如“第 3 条流吞吐量周期性下降但没有同步重传”或“各 TCP 指标正常但所有流都稳定在固定平台”，由 reason 节点据此形成可验证的开放式假设。

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
      +-- RealSpeedAnalyzerAdapter（正式路径）
              |
              v
         speed-analyze
      |
      +-- MockSpeedAnalyzerAdapter（测试路径）

主要组件如下。

### 5.1 CLI

CLI 负责收集参数、显示当前阶段、已处理报文数或字节数、进行必要的用户追问，并输出人类可读报告。CLI 同时将最终 JSON 报告写入任务目录。

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

第一版实现 Real Adapter 和 Mock Adapter。Real Adapter 是正式运行路径，Mock Adapter 只服务于测试。两者遵循相同的内部协议：

- analyze
- get_evidence

运行模式通过 SPEED_ANALYZER_MODE=real 或 mock 选择，默认值为 real。

### 5.5 Artifact Store

每次分析创建独立目录：

    output/<analysis_id>/
      coverage.json
      speed_stats.json
      tcp_analysis.json
      analysis.sqlite
      filtered/
      report.json
      trace.jsonl
      logs/

不同任务不得复用同名中间文件。

analysis.sqlite 至少保存流摘要、固定时间粒度统计、异常事件、SYN 选项和证据定位信息。它不要求保存每一个正常报文的全部字段。需要额外逐包证据时，可对筛选后的本地 pcapng 执行带过滤条件和数量上限的定向提取。

分析完成后，产物按照 ARTIFACT_TTL_HOURS 保留，默认 24 小时，以支持同一会话继续追问。CLI 可通过 keep-artifacts 配置延长保留时间。

## 6. Agent 状态

AgentState 至少包含：

- messages：CLI 多轮交互消息
- pcap_path：输入报文路径
- standard_bandwidth_mbps：标准带宽
- actual_bandwidth_mbps：实际带宽
- target：分析方向
- achievement_ratio_pct：达标率
- analysis_id：分析任务标识
- input_size_bytes：输入文件大小
- coverage_summary：覆盖报文数、字节数、时间范围、流数、是否完整和是否截断
- processing_progress：当前处理阶段与进度
- resource_usage：耗时、磁盘产物大小和警告
- flow_summary：测速流摘要
- tcp_summary：TCP 核心指标
- syn_options：TCP 握手选项
- anomaly_facts：由全量统计发现的异常、变化和指标关联
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

调用 analyze_speed_capture，对完整测速过程执行流式聚合，并写入 analysis_id、覆盖率、流摘要、TCP 摘要、TCP 选项、可用证据类型、产物路径、资源使用和警告。

### 7.4 reason

调用模型，根据带宽信息、完整性信息和紧凑摘要输出：

- 常见模式基线排查结果
- 从实际异常中发现的开放式候选原因
- 已支持该原因的指标
- 与该原因矛盾的指标
- 仍需查询的证据
- 初始置信度等级
- 对覆盖率是否足以支持当前判断的评价
- 原因在报文中的可观测性：direct、indirect 或 outside_capture

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
- coverage_summary 是否表明分析覆盖完整测速过程
- 局部证据是否与全局聚合结果一致
- 开放式新原因是否提出了可执行的验证方法
- outside_capture 原因是否明确标注需要外部数据，而没有写成报文已证实

覆盖不完整时不得产生高置信度结论。证据不足且查询次数未达到上限时，返回 inspect_evidence。达到上限后进入 report，并在限制中说明证据不足。

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

需要详细证据时，以下部分构成受约束的 ReAct 循环：

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
      "aggregation_interval_seconds": 1,
      "build_evidence_index": true
    }

标准带宽和实际带宽不传给该工具。它们不影响报文提取，由 Agent 的确定性逻辑用于达标率、BDP 和报告上下文计算。

request_id 由 Agent 在调用前生成。MCP Server 将它作为 analysis_id 使用；重试相同 request_id 时复用已有任务和产物。

输出包含：

- analysis_id
- status
- coverage_summary
- flow_summary
- tcp_summary
- interval_summary
- syn_options
- available_evidence
- resource_usage
- warnings
- artifact_paths

coverage_summary 至少包含：

- input_size_bytes
- total_packets_seen
- tcp_packets_seen
- speed_packets_analyzed
- analyzed_bytes
- analysis_start_time
- analysis_end_time
- analyzed_duration_seconds
- complete
- truncated
- truncation_reason

基础统计必须覆盖全部已识别测速报文，不设置 max_packets 或 tshark 的 -c 前缀限制。输出只包含适合进入模型上下文的紧凑摘要，不包含完整 per_packet_fields。

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
- flow_summary
- rtt_distribution
- throughput_distribution
- syn_options
- packet_fields
- custom_packet_query

custom_packet_query 用于验证预定义证据类型之外的新假设。它采用受控查询 DSL，例如：

    {
      "analysis_id": "20260721-a13f",
      "evidence_type": "custom_packet_query",
      "query": {
        "flow_ids": ["flow-3"],
        "time_start": 8,
        "time_end": 12,
        "predicates": [
          {
            "field": "tcp.window_size",
            "operator": "lt",
            "value": 65536
          }
        ],
        "fields": [
          "frame.number",
          "frame.time_relative",
          "tcp.seq",
          "tcp.window_size"
        ]
      },
      "offset": 0,
      "limit": 100
    }

允许的 operator 为 eq、ne、gt、gte、lt、lte、in 和 exists。服务端将 DSL 编译为 analysis.sqlite 查询或安全的 TShark 参数数组。模型不得提交原始 shell、任意 TShark display filter 或命令字符串。

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

证据查询优先读取 analysis.sqlite 中的流摘要、时间区间和异常事件。只有索引信息不足时，才对本地筛选 pcapng 执行带流、时间和字段过滤条件的定向 TShark 提取。定向提取必须设置返回上限，但不改变基础统计的全量覆盖。

### 9.3 Tool 约束

- 强制分页
- 限制最大返回条数
- 限制字段白名单
- analysis_id 必须属于当前 Artifact Store
- 相同 request_id 的重复调用必须幂等
- 工具不得直接生成原因概率
- 不将原始 pcap 内容返回给模型
- 全量聚合与局部证据查询必须分离
- 每次证据响应必须附带数据来源、覆盖区间和是否截断
- 模型上下文不得仅依赖文件开头的连续样本
- cause 不使用封闭枚举；evidence_type 使用预定义类型加 custom_packet_query 扩展
- custom_packet_query 只能使用字段白名单、操作符白名单和参数化值
- 禁止将查询 DSL 拼接到 shell 字符串中执行

## 10. 完整数据流

1. CLI 收集输入，只传递本地文件路径。
2. validate 检查参数、文件大小、可读性和剩余磁盘，并计算达标率。
3. Agent 生成 request_id，analyze 调用 analyze_speed_capture。
4. Real Adapter 调用加固后的 speed-analyze。
5. speed-analyze 流式筛选测速流，并对完整测速过程执行全量聚合。
6. 全局、每流、固定时间粒度和异常事件统计写入 JSON 与 analysis.sqlite。
7. MCP Server 返回覆盖率和紧凑摘要。
8. reason 先执行常见模式基线排查，再根据实际异常形成开放式候选原因和证据需求。
9. inspect_evidence 从索引或筛选 pcapng 中按需查询预定义证据或执行 custom_packet_query。
10. verify 检查局部证据、全局统计和覆盖率是否一致。
11. report 生成最终报告。
12. Artifact Store 保存报告和轨迹，并按保留策略清理大文件。

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
- coverage_summary
- evidence_quality
- analysis_metadata

候选原因包含：

- cause
- hypothesis_type：known_pattern、data_discovered 或 external_factor
- observability：direct、indirect 或 outside_capture
- confidence
- supporting_evidence
- contradicting_evidence
- missing_evidence
- affected_flows
- explanation
- suggestion

cause 为自由文本，不使用固定原因枚举。known_pattern 表示来自常见模式基线，data_discovered 表示由实际数据异常发现，external_factor 表示可能位于报文可观测范围之外。

如果现有证据不能合理支持任何原因，报告必须允许 primary_cause 为 unresolved，并说明当前报文无法解释、仍需哪些外部数据，而不是强行从常见原因中选择一个。

confidence 使用 high、medium、low 等级。它表示基于当前证据的诊断置信度，不宣称为经过统计校准的概率。

evidence_quality 至少说明：

- 全量聚合是否完成
- 诊断引用了哪些全局、每流和时间区间数据
- 局部证据是否截断
- 当前结论仍缺少哪些报文外信息

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

当前 speed-analyze/scripts/tcp_extract.py 固定了 Windows 路径，第一版 Real Adapter 接入时必须通过配置或自动发现消除该限制。

### 12.3 报文分析错误

定义以下错误码：

- INVALID_CAPTURE
- NO_TCP_PACKETS
- NO_SPEED_FLOW
- ANALYSIS_TIMEOUT
- ANALYSIS_FAILED
- INVALID_ANALYSIS_OUTPUT
- EVIDENCE_NOT_FOUND
- INSUFFICIENT_DISK_SPACE
- RESOURCE_LIMIT_EXCEEDED
- ANALYSIS_CANCELLED
- INCOMPLETE_COVERAGE

部分方向分析成功时返回部分结果，并通过 warnings 说明。

对于大报文，分析前根据输入大小和目标方向检查磁盘预算。默认要求可用空间至少为输入文件大小的 1.5 倍加固定安全余量；该比例允许配置。运行时间限制根据文件大小和历史处理速度动态计算，并保留管理员可配置的硬上限。

### 12.4 MCP 错误

临时连接错误最多重试两次，采用短暂退避。失败后保存当前 LangGraph 状态。

### 12.5 模型错误

限流或超时最多重试两次。结构化结果校验失败时，允许一次 Schema 修复请求。模型最终不可用时，输出基础指标摘要，不重新运行报文分析。

### 12.6 证据不足

证据不足不是系统错误。Agent 必须降低置信度、列出缺失证据，并区分已证实、较可能和无法判断。

## 13. 安全与隐私

- pcap 和完整逐包数据只在本机处理
- 只向模型发送必要的指标和少量证据
- CLI、Agent 和 MCP 之间只传路径、任务 ID、摘要和分页证据
- API Key 不写入日志
- MCP 限制可访问文件路径
- 每个任务使用独立目录
- 报告记录模型、工具版本和证据引用
- 日志不得包含原始 TCP payload
- 模型请求记录发送字段清单和估算 Token 数，但不得记录敏感 payload

## 14. 第一版 speed-analyze 接入与加固

Real Adapter 在第一版直接调用 speed-analyze/scripts/run_pipeline.py。接入前必须完成：

1. pcapng 直接进入流水线；pcap 使用本地 TShark 或 editcap 转换为任务目录中的 pcapng，转换产物计入磁盘预算。
2. 将 TShark 路径改为 TSHARK_PATH、系统 PATH 和常见安装路径的跨平台发现。
3. 处理同一方向的全部测速流，不再只采用第一个成功端口。
4. 删除基础统计中的 max_packets=5000 和 tshark -c 5000 限制。
5. 将可能随报文数增长的 TShark 输出改成 subprocess.Popen 流式读取和在线聚合，避免 capture_output 持有完整结果。
6. 对全部测速报文生成每流指标、固定时间粒度指标、分布统计和异常事件索引。
7. 不再把所有逐包字段写入一个大型 JSON；使用 analysis.sqlite 保存聚合结果和异常事件。
8. 保留筛选后的 pcapng，用于按需执行局部定向证据提取。
9. 增加文件大小、磁盘空间、处理进度、动态超时、取消和清理机制。
10. 验证下载、上行、both、多流和 IPv6 场景。
11. 明确 Scapy、TShark 和可选 editcap 是外部运行依赖，并在启动时进行预检。

当前 speed_filter_strip.py 已逐包读取报文，并通过两遍扫描完成统计与筛选，因此不会一次性把几 GB 文件放入内存。但它的运行时间与文件大小线性增长，流字典占用与流数量相关，并且会产生筛选后的 pcapng。第一版保留两遍扫描结构，同时加入资源预检和进度反馈；减少扫描遍数属于后续性能优化。

上述改造不改变 MCP 契约，Agent 只依赖结构化结果。

## 15. 测试策略

### 15.1 单元测试

覆盖输入校验、达标率、BDP、方向、置信度映射、覆盖率判断、资源预算和错误对象。

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
- coverage_summary 完整性
- 全量聚合与证据响应条数限制相互独立
- analysis.sqlite 查询结果与摘要一致
- 证据响应附带覆盖区间和截断标记
- custom_packet_query 正确编译字段、操作符、时间和流条件
- 原始 shell、任意 TShark filter、未知字段和非法操作符被拒绝

### 15.3 LangGraph 路由测试

使用固定模型响应验证：

- 缺失输入返回 collect
- 证据充分直接 verify 和 report
- 证据不足进入 inspect_evidence
- 最多三次详细查询
- MCP 失败进入错误状态
- 模型失败执行重试或降级
- 证据不足时不会输出高置信度结论
- coverage_summary 不完整时不会输出高置信度结论
- 受约束 ReAct 循环不会超过三轮
- 数据异常不匹配常见模式时仍可生成 data_discovered 假设
- 无假设得到充分支持时输出 unresolved，而不是强行选择原因

### 15.4 CLI 端到端测试

Mock 模式用于稳定验证 Agent 和 MCP 契约。Real 模式使用小型真实 pcapng 验证 speed-analyze 端到端接入：

- CLI 显示进度
- MCP Tool 调用符合预期
- 详细证据按需查询
- 终端和 JSON 报告均生成
- 轨迹文件生成
- API Key 不进入日志
- Real Adapter 能生成覆盖率、聚合摘要、证据索引和最终报告

### 15.5 大报文与性能测试

准备或生成不同规模的测试报文，至少覆盖约 500 MB 和约 2 GB：

- 分析过程中不读取完整文件到内存
- 基础统计覆盖完整测速过程
- 报告中的 complete、truncated 和处理时间正确
- 异常发生在文件后半段时仍能被统计和取证
- 峰值内存保持在配置预算内，不随文件字节数线性增长
- 磁盘不足时在处理前失败
- 取消任务后子进程停止，临时产物可清理
- 超时与进度信息可追溯

### 15.6 诊断质量评测

固定案例覆盖：

- 高重传和重复 ACK
- 高 RTT 或 RTT 波动
- 窗口过小或零窗口
- MSS、WScale、SACK 异常
- 严重乱序
- 多原因并存
- 数据不足
- TCP 指标正常但速度不达标
- 异常只出现在测速中段或末段
- 不属于预定义清单的新型异常
- 所有候选原因均被反向证据否定

评测不要求自然语言完全一致，也不要求原因来自固定清单，但要求原因有证据、置信度与证据匹配、报告符合 Schema，并能区分直接证据、间接推测和报文外因素。相同完整报文的诊断不得因只查看文件开头而遗漏后半段异常。

## 16. 第一版验收标准

第一版被视为完成时：

1. 用户可以通过一条 CLI 命令启动诊断。
2. Real FastMCP Server 能调用 speed-analyze 完成真实 pcapng 的端到端分析。
3. OpenAI 兼容模型能生成符合 Schema 的诊断。
4. Agent 能主动决定是否查询详细证据。
5. 详细证据查询最多三轮。
6. 最终报告包含主因、候选原因、证据、置信度、限制、排查步骤和建议。
7. MCP 或模型失败时提供可执行的错误提示。
8. 分析状态、工具调用和证据引用可以追溯。
9. 基础统计覆盖完整测速过程，不再使用前 5000 个报文代表全局。
10. 约 2 GB 的测试报文能够在配置资源预算内完成或给出明确资源错误，不发生内存溢出。
11. 模型只接收覆盖率、全局摘要和按需局部证据，不接收原始报文或完整逐包数据。
12. Mock Adapter 能完成自动化测试，并与 Real Adapter 保持契约一致。
13. RAG 不在第一版范围内，但图结构允许后续插入知识检索节点。
14. 候选原因不受固定枚举限制，新假设可以通过 custom_packet_query 验证。
15. 数据无法支持明确原因时，最终报告可以返回 unresolved。

## 17. 后续演进

### 17.1 流水线性能优化

在第一版稳定后评估：

- 将测速流筛选和指标聚合合并为更少的扫描阶段
- 避免不必要的筛选报文复制
- 对多流指标进行受控并行处理
- 使用更高性能的报文解析方案替换部分 Scapy 热路径
- 基于历史处理速度改进完成时间估算

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
