# PacketMaster Windows Web 发布验收清单

日期：2026-07-27

用途：在 Windows 真机验证 PacketMaster Web、真实 TShark、取消清理和大报文性能。请在项目根目录执行，记录每一步结果和失败日志中的错误码，但不要记录 API Key 或报文绝对路径。

## 1. 环境准备

```powershell
conda activate agent
python --version
tshark --version
python -m pip install -r requirements.txt
python -m pip install -e ".[rag]"
```

要求：Python 3.11 至 3.13，TShark 可执行。若 TShark 不在 PATH：

```powershell
$env:TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"
```

配置模型和允许读取的报文目录：

```powershell
$env:MODEL_API_KEY = "..."
$env:MODEL_BASE_URL = "https://api.deepseek.com"
$env:MODEL_NAME = "deepseek-v4-flash"
$env:MODEL_STRUCTURED_OUTPUT_METHOD = "auto"
$env:WEB_ALLOWED_CAPTURE_ROOTS = '["D:\\captures"]'
$env:WEB_DATABASE_PATH = "D:\PacketMaster\packetmaster-web.sqlite"
$env:KNOWLEDGE_DATABASE_PATH = "D:\PacketMaster\knowledge\packetmaster-knowledge.sqlite"
$env:EMBEDDING_MODEL_PATH = "D:\PacketMaster\models\multilingual-e5-small"
$env:RAG_ENABLED = "true"
$env:RAG_MODE = "shadow"
```

## 2. 自动化门禁

```powershell
$env:PACKETMASTER_REQUIRE_TSHARK = "1"
python -m pytest -m "not performance" -q
python -m ruff check .
```

预期：全部通过。Windows 专用取消测试不得跳过，结束后执行：

```powershell
Get-Process tshark -ErrorAction SilentlyContinue
```

预期：没有由 PacketMaster 遗留的 TShark 进程。

## 3. Web 启动与退出

```powershell
packetmaster web --no-browser
```

检查：

- 终端输出 `http://127.0.0.1:<端口>`；
- 浏览器可打开该地址；
- 健康状态显示本机服务已连接；
- 只能从本机访问；
- 按 `Ctrl+C` 后 API、Worker 和 TShark 均退出。

退出后检查：

```powershell
Get-Process python,tshark -ErrorAction SilentlyContinue
```

确认没有本次启动遗留的 PacketMaster Worker 或 TShark。

## 4. 三方向真实诊断

在 Web 中注册同一份合法测试报文，并分别创建三个会话：

1. 不说明方向，确认右栏显示“下载”；
2. 明确输入“分析上行”，确认显示“上行”；
3. 明确输入“分析上行和下载”，确认显示“上行 + 下载”。

每个任务检查：

- 确认前没有进入队列；
- 确认后页面持续显示进度；
- 刷新浏览器后任务仍存在；
- 完成后报告方向正确；
- 报告、指标、TCP 流和证据均可打开；
- 围绕报告追问一次，回答引用当前任务证据。

## 5. 取消与重试

使用处理时间足够长的报文启动任务：

1. 点击取消按钮并确认；
2. 等待状态变为“已取消”；
3. 检查没有遗留 TShark；
4. 点击“重试任务”；
5. 确认产生新的任务 ID，原取消任务和历史仍保留。

```powershell
Get-Process tshark -ErrorAction SilentlyContinue
```

## 6. 大报文门禁

准备约 2 GB 的真实 pcap/pcapng 和独立元数据：

```powershell
$env:PERF_PCAP_PATH = "D:\captures\release-2gb.pcapng"
$env:PERF_METADATA_PATH = "D:\captures\release-2gb.pcapng.metadata.json"
$env:PERF_MAX_RSS_BYTES = "1073741824"
python -m pytest tests/performance/test_large_capture.py -v
python -m pytest tests/performance/test_web_large_capture.py -v
```

预期：覆盖计数完全一致、无截断、RSS 不超过预算，Web 包装不复制报文到 SQLite 或 Python 内存。

## 7. RAG 真机门禁

使用包含空格和中文的离线模型及知识目录，依次执行：

```powershell
pkm knowledge health
pkm knowledge import ".\fixtures\窗口 案例.json" `
  --knowledge-id case.windows-window --title "Windows 窗口案例" `
  --type case --authority medium_high --source-name "验收案例"
pkm knowledge approve case.windows-window:v1 --reviewer windows-reviewer
pkm knowledge reindex case.windows-window:v1 --force
python -m pytest tests\performance\test_rag_capacity.py -v
```

检查：

- 中文路径和离线模型目录可用，运行时不访问公网；
- 导入预览、审核、重建和检索均不输出绝对路径或密钥；
- Web 报告与机制类追问显示独立“知识经验引用”；
- 询问具体帧或流时仍优先使用报文证据；
- 暂停访问知识 DB 或临时移走模型后，Web 仍能启动，基础诊断和问答可用；
- `RAG_MODE=active` 在没有 50 条合格评估记录时自动降为 `shadow`；
- `Get-Process python,tshark` 未出现异常残留进程。

正式 `active` 验收还需使用不少于 50 条经过脱敏和人工标注的评估集：

```powershell
pkm knowledge evaluate ".\evaluation\rag-production.json" `
  --output ".\evaluation\rag-report.json"
```

报告的 `production_ready` 必须为 `true`，否则保持 `shadow`。

## 8. 验收记录

| 项目 | 结果 | 备注 |
| --- | --- | --- |
| 非性能自动化 | 待执行 | |
| Web 启动与 Ctrl+C 退出 | 待执行 | |
| 默认下载 | 待执行 | |
| 显式上行 | 待执行 | |
| 显式双向 | 待执行 | |
| 刷新恢复 | 待执行 | |
| 取消无残留进程 | 待执行 | |
| 失败或取消后重试 | 待执行 | |
| 2 GB 性能门禁 | 待执行 | |
| RAG 离线模型与中文路径 | 待执行 | |
| 知识导入、审核与重建 | 待执行 | |
| 25,000 切片 P95 门禁 | 待执行 | |
| RAG 故障降级 | 待执行 | |
| 50 条正式评估与 active 门禁 | 待执行 | |

全部通过后，将结果和 Windows 版本、Python 版本、TShark 版本、Embedding 模型哈希及评估报告摘要反馈回来。不要反馈 API Key、知识正文或报文路径。
