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
