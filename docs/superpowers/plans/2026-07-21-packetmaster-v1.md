# PacketMaster TCP 测速诊断 Agent 第一版实施计划

> 面向执行智能体：逐任务实施并使用复选框跟踪。推荐使用 superpowers:subagent-driven-development，也可以使用 superpowers:executing-plans。

目标：构建名为 PacketMaster 的 CLI 形式 TCP 测速诊断 Agent。默认分析下载速率不达标原因；仅当用户明确要求时分析上行或双向。PacketMaster 通过 FastMCP 调用真实 speed-analyze，对完整报文做全量流式聚合，并在 LangGraph 中执行最多三轮的证据驱动诊断。

架构：原始 pcap/pcapng 始终留在本机，由 speed-analyze 和 TShark 流式处理。聚合摘要与异常证据写入 JSON 和 SQLite，模型只接收覆盖范围、紧凑指标和分页证据。Windows 是正式运行与发布平台，macOS 是当前开发与兼容平台。

项目标识：Python 分发包和导入包使用 packetmaster，CLI 命令使用 packetmaster，FastMCP Server 名称使用 packetmaster；speed-analyze 保持为底层 skill 名称。

技术栈：Python 3.11-3.13、Pydantic 2、FastMCP 2、LangGraph 1、langchain-openai 1、Typer、SQLite、Scapy、TShark、pytest、pytest-asyncio、Ruff。

## 全局约束

- 默认分析方向为 download。
- 用户明确要求上行时使用 upload，明确要求上行和下载、双向或同时分析时使用 both。
- 不得因为报文中同时存在上行和下载流而自动切换为 both。
- CLI 输入方向可以省略；进入 LangGraph 和 MCP 前必须归一化为 download、upload 或 both。
- Windows 是正式运行、测试和发布验收平台；macOS 是开发和兼容验证平台。
- 路径必须支持 Windows 盘符、反斜杠、空格和非 ASCII 字符，同时兼容 macOS 路径。
- 子进程必须使用参数数组调用，禁止 shell=True、os.system 和命令字符串拼接。
- TShark 按 TSHARK_PATH、系统 PATH、当前操作系统常见安装目录的顺序发现。
- 原始报文和完整逐包数据不得进入模型上下文。
- 基础统计必须覆盖全部已识别测速报文，不允许只分析前 N 个报文。
- 大报文处理不得将完整文件、完整 TShark 输出或全部异常事件载入内存。
- 证据响应必须分页，并包含来源、覆盖范围和截断信息。
- 候选原因使用开放式文本；常见 TCP 原因只是基础检查清单，不是原因白名单。
- 每个假设必须包含支持证据、反向证据、缺失证据、影响流和可观测性。
- ReAct 取证循环最多三轮。
- 证据不足时返回 unresolved，不得强行给出原因。
- Real Adapter 是默认运行路径；Mock Adapter 仅用于测试和演示。
- RAG、Web UI、批量调度、监控集成和多 Agent 编排不属于第一版。
- 保留所有无关的用户修改，包括当前未提交的 .DS_Store。

## 文件结构

### PacketMaster 包

- pyproject.toml：依赖、CLI 入口、pytest 和 Ruff 配置。
- src/packetmaster/config.py：环境配置和默认值。
- src/packetmaster/domain.py：Pydantic 领域模型。
- src/packetmaster/errors.py：结构化错误。
- src/packetmaster/platform.py：Windows/macOS 路径、进程和编码辅助能力。
- src/packetmaster/artifacts.py：任务目录、磁盘预检、保留策略和轨迹。
- src/packetmaster/analyzer/base.py：Analyzer Adapter 协议。
- src/packetmaster/analyzer/mock.py：测试 Adapter。
- src/packetmaster/analyzer/real.py：真实 speed-analyze 子进程 Adapter。
- src/packetmaster/mcp/server.py：名为 packetmaster 的 FastMCP 工具服务。
- src/packetmaster/mcp/client.py：FastMCP stdio Client。
- src/packetmaster/context.py：模型上下文构建。
- src/packetmaster/model.py：结构化模型调用。
- src/packetmaster/graph.py：LangGraph 状态、节点和路由。
- src/packetmaster/report.py：报告生成和保存。
- src/packetmaster/cli.py：命令行入口和进度输出。
- src/packetmaster/prompts/：假设生成与证据复核 Prompt。

### speed-analyze 加固

- speed-analyze/scripts/lib/tshark.py：跨平台 TShark 发现、格式转换和流式字段提取。
- speed-analyze/scripts/lib/aggregate.py：全量 TCP 聚合。
- speed-analyze/scripts/lib/store.py：SQLite 证据索引和安全查询。
- speed-analyze/scripts/lib/progress.py：JSONL 进度事件。
- speed-analyze/scripts/speed_filter_strip.py：方向筛选、文件指纹和任务隔离。
- speed-analyze/scripts/tcp_extract.py：全流流式提取和聚合。
- speed-analyze/scripts/run_pipeline.py：任务级流水线入口。
- speed-analyze/SKILL.md：新参数、方向规则和输出说明。

### 测试与文档

- tests/unit/：领域模型、平台兼容、产物、TShark、聚合、证据库、上下文和 Graph 测试。
- tests/contract/：FastMCP 工具契约测试。
- tests/integration/：Real Pipeline 和 CLI 端到端测试。
- tests/performance/：大报文性能门禁。
- tests/fixtures/：Mock 分析结果和小型报文夹具。
- scripts/generate_test_capture.py：确定性测试报文生成器。
- .github/workflows/test.yml：Windows 与 macOS 测试矩阵。
- README.md：安装、配置、运行和排障说明。

---

### 任务 1：初始化项目和领域契约

文件：

- 创建 pyproject.toml
- 创建 src/packetmaster/__init__.py
- 创建 src/packetmaster/config.py
- 创建 src/packetmaster/domain.py
- 创建 src/packetmaster/errors.py
- 创建 tests/unit/test_domain.py

接口：

- Settings.load() 读取模型、Adapter、TShark、产物和超时配置。
- AnalyzeRequest、AnalyzeResponse、EvidenceRequest、EvidenceResponse 定义 MCP 契约。
- Hypothesis、VerificationResult、DiagnosticReport 定义诊断结果。
- Target 只允许 download、upload 和 both。
- AppError 提供错误码、可恢复性和建议操作。

- [ ] 步骤 1：编写领域模型失败测试，覆盖未指定方向时默认为 download、显式 upload、显式 both、相对路径拒绝、非法方向拒绝和开放式原因文本。
- [ ] 步骤 2：运行 python -m pytest tests/unit/test_domain.py -v，确认因项目包尚不存在而失败。
- [ ] 步骤 3：创建项目配置和共享模型，确保 AnalyzeRequest 在缺少 target 时得到 download。
- [ ] 步骤 4：实现 Settings 和 AppError，默认 SPEED_ANALYZER_MODE 为 real，最大取证轮数固定不超过 3。
- [ ] 步骤 5：运行领域测试和 python -m ruff check src tests/unit/test_domain.py。
- [ ] 步骤 6：确认测试证明报文中存在双向流不会改变用户选择的 target。
- [ ] 步骤 7：提交，建议提交信息为 feat: add agent domain contracts。

验收标准：方向默认值和显式覆盖规则固定，后续所有组件共享同一套模型。

---

### 任务 2：实现平台兼容、产物管理和资源预检

文件：

- 创建 src/packetmaster/platform.py
- 创建 src/packetmaster/artifacts.py
- 创建 tests/unit/test_platform.py
- 创建 tests/unit/test_artifacts.py

接口：

- PlatformSupport 负责当前操作系统识别、UTF-8 子进程配置和子进程终止。
- ArtifactManager 创建隔离目录、执行磁盘预检、记录轨迹并清理过期产物。
- ResourceBudget 返回输入大小、所需空间和可用空间。

- [ ] 步骤 1：编写失败测试，覆盖 Windows 盘符路径、空格路径、中文路径、macOS 路径和绝对路径校验。
- [ ] 步骤 2：编写失败测试，覆盖磁盘不足、任务目录隔离、keep 标记和过期清理。
- [ ] 步骤 3：实现平台辅助能力，禁止依赖 POSIX 专属路径和 Signal。
- [ ] 步骤 4：实现产物目录与输入文件大小 1.5 倍加固定余量的磁盘预检。
- [ ] 步骤 5：验证 Windows 和 macOS 的超时、terminate、等待和 kill 降级路径都可由单元测试模拟。
- [ ] 步骤 6：运行 python -m pytest tests/unit/test_platform.py tests/unit/test_artifacts.py -v 和 Ruff。
- [ ] 步骤 7：提交，建议提交信息为 feat: add cross-platform artifact management。

验收标准：相同接口可在 Windows 和 macOS 使用，路径、编码和任务清理不存在平台硬编码。

---

### 任务 3：实现跨平台 TShark 发现和全量流式读取

文件：

- 创建 speed-analyze/scripts/lib/__init__.py
- 创建 speed-analyze/scripts/lib/tshark.py
- 创建 speed-analyze/scripts/lib/progress.py
- 创建 tests/helpers.py
- 创建 tests/unit/test_tshark.py

接口：

- find_tshark() 返回可执行 TShark 路径。
- normalize_capture() 将 pcap 转为任务目录中的 pcapng，pcapng 直接复用。
- stream_tshark_fields() 逐行返回字段，不设置报文数量上限。
- ProgressWriter 追加 JSONL 进度事件。

- [ ] 步骤 1：编写 TShark 查找顺序测试，覆盖 TSHARK_PATH、PATH、Windows Wireshark 默认目录、macOS App Bundle 和 Homebrew。
- [ ] 步骤 2：编写流式读取测试，证明第 5000 个报文后的记录仍被读取。
- [ ] 步骤 3：实现基于参数数组的 TShark 调用，路径包含空格时不得依赖 Shell 转义。
- [ ] 步骤 4：统一以 UTF-8 读取输出，对异常字符进行替换并写入 warning。
- [ ] 步骤 5：实现 pcap 格式转换、错误截断和 JSONL 进度输出。
- [ ] 步骤 6：运行 python -m pytest tests/unit/test_tshark.py -v，并检查代码中不存在 TShark -c 限制。
- [ ] 步骤 7：提交，建议提交信息为 feat: add cross-platform streaming tshark。

验收标准：Windows 和 macOS 都能发现 TShark；流式读取覆盖完整输入且内存不随输出总行数线性增长。

---

### 任务 4：实现全量 TCP 聚合和 SQLite 证据库

文件：

- 创建 speed-analyze/scripts/lib/aggregate.py
- 创建 speed-analyze/scripts/lib/store.py
- 创建 tests/unit/test_aggregate.py
- 创建 tests/unit/test_store.py
- 创建 tests/fixtures/packet_rows.jsonl

接口：

- TcpAccumulator 按全局、方向、流和时间区间累计指标。
- AnalysisStore 保存摘要、时间区间、异常事件和证据定位信息。
- query_custom() 只接受字段白名单、操作符白名单和参数化值。

- [ ] 步骤 1：编写回归测试，证明第 5000 个报文之后的重传、重复 ACK、零窗口和乱序不会遗漏。
- [ ] 步骤 2：编写多流与双向测试，证明 download、upload 和 both 只聚合各自目标方向。
- [ ] 步骤 3：实现固定大小计数器、每流统计、时间桶、RTT 直方图、窗口统计和 SYN 选项。
- [ ] 步骤 4：异常事件通过批量写入 SQLite，禁止在内存中长期保留全部异常行。
- [ ] 步骤 5：实现安全查询 DSL，并测试未知字段、非法操作符和注入值被拒绝。
- [ ] 步骤 6：运行 python -m pytest tests/unit/test_aggregate.py tests/unit/test_store.py -v 和 Ruff。
- [ ] 步骤 7：提交，建议提交信息为 feat: add full-capture aggregation and evidence store。

验收标准：基础统计完整、方向隔离正确、事件索引可追溯，自定义查询不能执行任意 Shell 或 SQL。

---

### 任务 5：将全量聚合集成到 speed-analyze

文件：

- 修改 speed-analyze/scripts/speed_filter_strip.py
- 修改 speed-analyze/scripts/tcp_extract.py
- 修改 speed-analyze/scripts/run_pipeline.py
- 修改 speed-analyze/SKILL.md
- 创建 tests/integration/test_real_pipeline.py

接口：

- run_pipeline.py 接收绝对报文路径、明确 target、analysis_id、时间粒度和是否建立证据索引。
- 流水线生成 manifest.json、coverage.json、speed_stats.json、tcp_analysis.json 和 analysis.sqlite。
- target 在流水线内部必须明确，不由报文内容自动推断。

- [ ] 步骤 1：建立小型真实报文夹具，覆盖默认下载对应的 download、显式 upload、显式 both、多流和 IPv6。
- [ ] 步骤 2：移除 max_packets、TShark -c 和仅分析第一个端口的逻辑。
- [ ] 步骤 3：让下载和上行筛选结果写入任务独立目录，both 模式不得互相覆盖文件。
- [ ] 步骤 4：在第一次全量扫描中计算文件指纹和覆盖范围，并默认保留本地 Payload、不把 Payload 写入摘要。
- [ ] 步骤 5：接入 TcpAccumulator 和 AnalysisStore，失败时写入结构化 manifest 错误。
- [ ] 步骤 6：更新 SKILL.md，说明 Agent 默认传入 download，只有用户明确要求才传 upload 或 both。
- [ ] 步骤 7：在 Windows 和 macOS 分别验证 TShark 路径、空格路径、中文路径和任务取消。
- [ ] 步骤 8：运行真实流水线集成测试和帮助命令。
- [ ] 步骤 9：提交，建议提交信息为 feat: harden speed analysis for full captures。

验收标准：真实 speed-analyze 能在两个平台处理完整测速过程，方向行为与用户意图一致。

---

### 任务 6：实现 Analyzer Adapter 和 FastMCP 工具

文件：

- 创建 src/packetmaster/analyzer/base.py
- 创建 src/packetmaster/analyzer/mock.py
- 创建 src/packetmaster/analyzer/real.py
- 创建 src/packetmaster/mcp/server.py
- 创建 src/packetmaster/mcp/client.py
- 创建 tests/contract/test_mcp_tools.py
- 创建 tests/fixtures/mock_analysis.json

接口：

- AnalyzerAdapter 提供 analyze() 和 get_evidence()。
- FastMCP 暴露 analyze_speed_capture 和 get_tcp_evidence。
- SpeedMCPClient 负责 stdio 生命周期、结构化校验和进度回调。

- [ ] 步骤 1：编写契约失败测试，覆盖结构化输入输出、默认 download、显式 upload/both、分页和不安全查询拒绝。
- [ ] 步骤 2：实现 Mock Adapter，保证结果确定且与 Real Adapter 使用相同 Schema。
- [ ] 步骤 3：实现 Real Adapter，以参数数组启动流水线，将日志写入文件而不是内存。
- [ ] 步骤 4：实现动态超时、RSS 峰值采样和 Windows/macOS 子进程取消。
- [ ] 步骤 5：校验 manifest；将失败、超时、取消和无效输出映射为 AppError。
- [ ] 步骤 6：实现 FastMCP Server 和 Client，模型与 MCP 之间只传路径、摘要和分页证据。
- [ ] 步骤 7：运行 python -m pytest tests/contract/test_mcp_tools.py -v 和 Ruff。
- [ ] 步骤 8：提交，建议提交信息为 feat: expose speed analysis through fastmcp。

验收标准：MCP 契约稳定、安全，Real Adapter 在 Windows 和 macOS 都能可靠启动、监控和终止流水线。

---

### 任务 7：构建模型上下文和开放式诊断

文件：

- 创建 src/packetmaster/context.py
- 创建 src/packetmaster/model.py
- 创建 src/packetmaster/prompts/hypothesis.md
- 创建 src/packetmaster/prompts/verification.md
- 创建 tests/unit/test_context.py

接口：

- ContextBuilder 从 AnalyzeResponse 和 EvidenceResponse 生成 DiagnosisContext。
- DiagnosisModel 生成开放式假设并对证据进行复核。

- [ ] 步骤 1：编写上下文失败测试，覆盖后段异常保留、正常区间压缩、覆盖信息和原始 Payload 排除。
- [ ] 步骤 2：实现带宽、覆盖范围、全局指标、每流指标、异常区间、SYN 选项和证据分层。
- [ ] 步骤 3：保证上下文携带 target，使模型不会混淆下载、上行和双向指标。
- [ ] 步骤 4：编写假设 Prompt，明确原因不是封闭枚举，每个原因必须提供正反证据和缺失证据。
- [ ] 步骤 5：编写复核 Prompt，明确报文外原因不能被描述为已由报文证实。
- [ ] 步骤 6：实现 OpenAI 兼容结构化输出封装，不记录隐藏推理和 API Key。
- [ ] 步骤 7：运行 python -m pytest tests/unit/test_context.py -v；该测试不得调用外部模型。
- [ ] 步骤 8：提交，建议提交信息为 feat: add open-ended evidence diagnosis model。

验收标准：模型只看到全量聚合后的必要信息，能提出清单外假设，并能在证据不足时保留 unresolved。

---

### 任务 8：实现有界 LangGraph 工作流

文件：

- 创建 src/packetmaster/graph.py
- 创建 tests/fakes.py
- 创建 tests/unit/test_graph.py

接口：

- AgentState 保存输入、归一化 target、分析结果、假设、证据、轮数、报告和错误。
- build_graph() 构建 validate、analyze、reason、inspect_evidence、verify 和 report 节点。

- [ ] 步骤 1：编写路由失败测试，覆盖默认 download、显式 upload/both、证据查询、三轮上限、错误和 unresolved。
- [ ] 步骤 2：实现 validate，对缺失 target 进行防御性归一化为 download，并拒绝未知值。
- [ ] 步骤 3：实现 analyze 和 reason，确保 target 原样传入 MCP 并进入模型上下文。
- [ ] 步骤 4：实现 inspect_evidence 和 verify，证据请求必须分页并受字段白名单约束。
- [ ] 步骤 5：实现最多三轮的条件路由，达到上限后必须进入 report。
- [ ] 步骤 6：每个节点写入可追溯轨迹，但不写 API Key、原始 Payload、完整逐包记录或隐藏推理。
- [ ] 步骤 7：运行 python -m pytest tests/unit/test_graph.py -v 和 Ruff。
- [ ] 步骤 8：提交，建议提交信息为 feat: add bounded evidence diagnosis graph。

验收标准：Graph 行为确定、方向不漂移、循环有上限、错误可降级、结论可追溯。

---

### 任务 9：实现 CLI 和报告

文件：

- 创建 src/packetmaster/report.py
- 创建 src/packetmaster/cli.py
- 创建 tests/integration/test_cli.py
- 创建 README.md

接口：

- packetmaster diagnose PATH --standard FLOAT --actual FLOAT 启动默认下载诊断。
- --target upload 和 --target both 用于用户明确要求的上行或双向诊断。
- report.json 保存结构化 DiagnosticReport。

- [ ] 步骤 1：编写 CLI 失败测试，确认省略 --target 时输出 target=download。
- [ ] 步骤 2：增加显式 upload 和 both 测试，确认参数完整传到 Graph 和 MCP。
- [ ] 步骤 3：增加 Windows 盘符、空格和中文路径测试，以及 macOS 绝对路径测试。
- [ ] 步骤 4：实现 Typer CLI、实时进度、错误退出码和 keep-artifacts。
- [ ] 步骤 5：实现终端报告和 JSON 报告，报告必须明确分析方向、覆盖范围、证据和限制。
- [ ] 步骤 6：编写 README，首先展示不带 --target 的默认下载命令，再展示上行和双向命令。
- [ ] 步骤 7：记录 Windows 的 TShark 安装与 TSHARK_PATH 配置，同时记录 macOS 开发环境配置。
- [ ] 步骤 8：运行 python -m pytest tests/integration/test_cli.py -v 和 python -m packetmaster.cli --help。
- [ ] 步骤 9：提交，建议提交信息为 feat: add diagnosis cli and reports。

验收标准：用户无需说明方向即可分析下载；只有明确指定时才改变方向；两个平台的路径均可使用。

---

### 任务 10：增加端到端、安全和发布门禁

文件：

- 创建 scripts/generate_test_capture.py
- 创建 tests/performance/test_large_capture.py
- 修改 tests/integration/test_real_pipeline.py
- 修改 tests/integration/test_cli.py
- 创建 .github/workflows/test.yml
- 修改 README.md

接口：

- 测试报文生成器可生成多流、后段重传、重复 ACK 和可选零窗口场景。
- PERF_PCAP_PATH 指向发布性能测试使用的大报文。
- CI 在 Windows 和 macOS 运行核心测试，Windows 是发布门禁。

- [ ] 步骤 1：实现确定性报文生成器，异常必须可配置在第 5000 个报文之后。
- [ ] 步骤 2：增加端到端回归测试，覆盖默认下载、显式上行、显式 both、多流、后段异常和证据引用。
- [ ] 步骤 3：增加安全测试，确认日志无 API Key、模型上下文无原始 Payload、命令无 Shell 拼接。
- [ ] 步骤 4：增加 Windows 与 macOS CI 矩阵；Windows 运行真实 TShark 集成门禁，macOS 运行兼容门禁。
- [ ] 步骤 5：增加约 2 GB 的可选性能测试，检查完整覆盖、无截断、无内存溢出和 RSS 预算。
- [ ] 步骤 6：在 Windows 真实环境执行 CLI 冒烟诊断，验证 TShark、取消、SQLite 和报告产物。
- [ ] 步骤 7：在 macOS 开发环境执行相同核心流程的兼容冒烟诊断。
- [ ] 步骤 8：运行 python -m pytest -m "not performance" -v 和 python -m ruff check src speed-analyze/scripts tests scripts。
- [ ] 步骤 9：在具备大报文夹具的 Windows 机器上运行性能门禁。
- [ ] 步骤 10：提交，建议提交信息为 test: add cross-platform release gates。

验收标准：Windows 能完成真实端到端分析和大报文发布门禁，macOS 能持续完成开发兼容验证。

---

## 最终验证

- [ ] 运行所有默认测试：python -m pytest -m "not performance" -v。
- [ ] 运行代码检查：python -m ruff check src speed-analyze/scripts tests scripts。
- [ ] 检查方向测试同时覆盖默认 download、显式 upload 和显式 both。
- [ ] 检查不存在根据报文内容自动把 target 改为 both 的逻辑。
- [ ] 检查基础分析不存在 max_packets、TShark -c 或完整 per_packet_fields 输出。
- [ ] 检查不存在 shell=True、os.system 或将查询 DSL 拼入命令字符串的代码。
- [ ] 在 Windows 验证盘符、空格、中文路径、TShark、取消和 SQLite 产物。
- [ ] 在 macOS 验证相同核心流程和 Wireshark/Homebrew TShark 路径。
- [ ] 检查模型请求不包含原始报文、完整逐包数据、API Key 或隐藏推理。
- [ ] 检查 git status，确保只提交实施产生的文件并保留用户自己的 .DS_Store 修改。

## 实施顺序

任务 1 至任务 6 建立确定性报文处理和工具边界；任务 7 至任务 9 建立诊断与交互能力；任务 10 完成双平台和大报文发布门禁。每个任务完成后独立运行对应测试并提交，不跨任务累计未验证修改。
