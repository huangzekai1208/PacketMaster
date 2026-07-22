---
name: speed-analyze
description: Use when a user provides a pcap/pcapng capture and bandwidth information and wants to diagnose why a TCP speed test is below expectation.
---

# 测速报文速率不达标原因分析

对 pcap/pcapng 中用户指定方向的全部测速 TCP 流做全量聚合，输出覆盖度、流/时序摘要和本地 SQLite 证据索引，再据此诊断速率不达标原因。

## 输入约束

- 收集原始报文的绝对路径、标准带宽和实际带宽。
- `target` 默认为 `download`。只有用户明确要求时才使用 `upload` 或 `both`，不得从报文内容自行改成 `both`。
- 为每次分析生成只含字母、数字、点、下划线和连字符的独立 `analysis-id`。
- 为该 `analysis-id` 使用独立的绝对输出目录，不复用全局中间文件。

## 运行流水线

只调用一次 `scripts/run_pipeline.py`，使用参数数组并传入绝对路径：

```text
python <skill绝对路径>/scripts/run_pipeline.py \
  --input <pcap或pcapng绝对路径> \
  --target <download|upload|both> \
  --output <单任务绝对输出目录> \
  --analysis-id <analysis-id>
```

可选参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--target` | `download` | 明确的分析方向 |
| `--interval` | `1` | 聚合区间秒数，范围 1..60 |
| `--build-evidence-index` / `--no-build-evidence-index` | 开启 | 是否生成本地 SQLite 证据索引 |
| `--tshark-path` | 自动发现 | 显式 TShark 可执行文件 |
| `--min-ratio` | `0.70` | 测速流单向流量占比阈值 |
| `--min-bytes` | `102400` | 测速流最小字节数 |

流水线会规范化 pcap、按请求方向筛选全部测速流，并通过 TShark 逐行提取字段进行全量聚合。它不设置报文数量上限，也不会只分析第一个端口或第一条流。

## 输出文件

固定入口为 `<output>/manifest.json`。成功或失败都先读取 manifest，并根据其中的绝对 `artifact_paths` 访问其他产物：

- `manifest.json`：状态、目标方向、覆盖度、告警、结构化错误和所有产物路径。
- `coverage.json`：原始总包数、TCP 包数、实际分析的测速包数、完整性和截断状态。
- `speed_stats.json`：输入指纹、流分类、方向文件及写出计数。
- `tcp_analysis.json`：TCP、流、区间和 SYN 选项的聚合摘要。
- `analysis.sqlite`：开启证据索引时生成，保存局部异常事件，供受限分页查询。
- `progress.jsonl`、`logs/`、`filtered/`：进度、子进程日志和本地筛选报文。

`both` 只识别到一个方向时，manifest 状态为 `partial` 并列出告警；不得伪造缺失方向。失败时使用 manifest 的 `error.code`、`message`、`recoverable`、`suggested_action` 和 `details` 判断后续动作。

## 诊断边界

- PacketMaster 模型只读取 `manifest.json`、`coverage.json` 和 `tcp_analysis.json` 的聚合摘要。
- 原始 pcap/pcapng、筛选 pcapng 和 Payload 始终保留在本地，不进入模型上下文。
- 需要验证某个异常假设时，通过 PacketMaster 的证据查询接口分页读取 `analysis.sqlite` 中的局部事件；不要直接读取完整数据库或逐包字段。
- 先确认 `coverage.complete=true`、`coverage.truncated=false`，再基于重传、重复 ACK、乱序、窗口、RTT、吞吐时序和 SYN 选项形成结论。
- 每个原因必须给出捕获内证据、受影响流、置信度与排查建议。数据不足或因素位于捕获外时明确说明，不猜测。

## 安全原则

- 使用参数数组调用脚本，不使用 shell 拼接。
- 不在诊断阶段直接运行 TShark 或解析原始报文。
- 不把 Payload、完整逐包字段或原始会话文本写入 JSON/模型摘要。
- 保留用户的原始报文和任务产物，不覆盖其他分析目录。
