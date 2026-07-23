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

约 2 GB 的大报文性能门禁需在带有 `packetmaster-performance` 标签的 Windows 自托管 runner 上手动运行，并配置仓库变量 `PERF_PCAP_PATH`。也可在实机本地执行：

```powershell
$env:PERF_PCAP_PATH = "D:\captures\release-2gb.pcapng"
$env:PERF_MAX_RSS_BYTES = "1073741824"
python -m pytest tests/performance/test_large_capture.py -v
```

该门禁要求分析覆盖完整、无截断、包数大于零，且子进程 RSS 峰值不超过预算。
