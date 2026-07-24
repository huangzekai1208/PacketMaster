# PacketMaster

PacketMaster 是 TCP 测速不达标原因分析 Agent。原始报文留在本机，模型只接收全量聚合后的有界摘要和分页证据。

## 默认分析下载

```powershell
packetmaster diagnose "C:\captures\测速 报文.pcapng" --standard 1000 --actual 600
```

省略 `--target` 时固定使用 `download`，不会因为报文含双向流自动切换。

## 显式分析上行或双向

```powershell
packetmaster diagnose "C:\captures\test.pcapng" --standard 1000 --actual 600 --target upload
packetmaster diagnose "C:\captures\test.pcapng" --standard 1000 --actual 600 --target both
```

可用 `--keep-artifacts` 保留本次本地产物。结构化结果写入 `report.json`。
packetmaster diagnose \
  artifacts/synthetic-model-test/capture.pcapng \
  --standard 1000 \
  --actual 600 \
  --output-dir artifacts/my-first-report \
  --keep-artifacts

## Windows

安装 Wireshark 并勾选 TShark。若不在 PATH，设置：

```powershell
$env:TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"
```

支持盘符、反斜杠、空格和中文路径。

## macOS 开发环境

```bash
brew install wireshark
export TSHARK_PATH=/opt/homebrew/bin/tshark
packetmaster diagnose "/Users/me/captures/test capture.pcapng" --standard 1000 --actual 600
```

诊断需要兼容 OpenAI API 的模型配置。Payload、完整逐包字段、完整日志和 API Key 不进入模型上下文。

推荐复制本地配置模板并填写模型配置：

```powershell
Copy-Item src\packetmaster\config_local.example.py src\packetmaster\config_local.py
```

`config_local.py` 会被 Git 忽略，PacketMaster 启动时自动读取，无需每次设置
环境变量。环境变量的优先级更高，仍可用于临时覆盖。Windows PowerShell：

```powershell
$env:MODEL_API_KEY = "..."
$env:MODEL_BASE_URL = "https://api.deepseek.com"
$env:MODEL_NAME = "deepseek-v4-flash"
$env:MODEL_STRUCTURED_OUTPUT_METHOD = "auto"
```

macOS/Linux：

```bash
export MODEL_API_KEY="..."
export MODEL_BASE_URL="https://api.deepseek.com"
export MODEL_NAME="deepseek-v4-flash"
export MODEL_STRUCTURED_OUTPUT_METHOD="auto"
```

`auto` 会对模型名或接口地址中包含 `deepseek` 的服务使用 `json_mode`，
其他模型默认使用 `json_schema`。兼容服务也可以显式设置为
`json_mode`、`json_schema` 或 `function_calling`。

## CLI 对话模式

```bash
conda activate agent
packetmaster chat
```

首次输入自然语言任务，例如：

```text
请分析 /Users/me/captures/test.pcapng，标准带宽 1Gbps，实际 600M
```

PacketMaster 会抽取参数、补问缺失项并等待确认；未明确方向时默认分析下载。
确认完成后进入 `PacketMaster>` 提示符，可继续询问当前报告和证据。

内置命令：`/new` 新建任务，`/report` 查看完整中文报告，`/evidence` 查看有界证据，
`/save` 查看 JSON 报告路径，`/help` 查看帮助，`/quit` 退出。

## 开发与测试

```bash
python -m pip install -e ".[dev]"
python -m pytest -m "not performance" -v
python -m ruff check src speed-analyze/scripts tests scripts
```

可生成确定性的多流测试报文，重传、重复 ACK 和可选零窗口将出现在第 5000 个报文之后：

```bash
python scripts/generate_test_capture.py \
  --output "artifacts/test captures/late-evidence.pcapng" \
  --flows 2 \
  --data-packets-per-flow 2500 \
  --anomaly-after 5000 \
  --zero-window
```

## 发布门禁

GitHub Actions 在 Windows 和 macOS 上安装真实 TShark 并运行所有非性能测试。Windows job 是正式发布门禁，macOS job 是开发兼容门禁。

约 2 GB 的大报文性能门禁需在带有 `packetmaster-performance` 标签的 Windows 自托管 runner 上手动运行，并配置仓库变量 `PERF_PCAP_PATH` 和 `PERF_METADATA_PATH`。也可在实机本地执行：

```powershell
$env:PERF_PCAP_PATH = "D:\captures\release-2gb.pcapng"
$env:PERF_METADATA_PATH = "D:\captures\release-2gb.pcapng.metadata.json"
$env:PERF_MAX_RSS_BYTES = "1073741824"
python -m pytest tests/performance/test_large_capture.py -v
```

元数据 JSON 必须由发布夹具的独立生成流程提供 `input_size_bytes`、`total_packets_seen`、`tcp_packets_seen` 和 `speed_packets_analyzed` 四个正整数。门禁要求分析结果与这些期望值完全相等、无截断，且子进程树的采样 RSS 峰值大于零并不超过预算。RSS 约每 250 ms 采样一次，不是操作系统级精确峰值，因此发布预算应保留安全余量。
