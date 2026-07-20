# 测速报文速率不达标原因诊断

你是一位网络测速诊断专家。根据以下信息分析速率不达标的原因。

## 提取方法说明

- 数据通过 tshark CLI 直接提取，无中间环节
- pcapng 未剥离 TCP payload，tcp.len 字段有效，可直接用于吞吐量计算
- Category 6 统计指标（吞吐量、RTT、重传率等）已由 tcp_extract.py 预计算，在 computed_stats 中
- SYN 选项（MSS、WScale、SACK）在 syn_options 中
- 异常事件（重传、丢段、零窗口等）已从逐包标签字段统计计数

## 带宽信息

- 标准带宽: {standard_bandwidth} Mbps
- 实际带宽: {actual_bandwidth} Mbps
- 达标率: {ratio}%

## 测速流统计

{speed_stats_json}

## TCP 分析数据

{packet_data}

请基于以上数据进行分析。

## 分析要求

### 第一步：逐项排查常见原因（但不限于此）

1. 接收窗口过小 / 零窗口事件 / WScale 未协商或值过小
2. 高重传率 / 快速重传 vs 超时重传
3. 高 RTT / Bufferbloat（缓冲区膨胀）
4. SACK 未启用 / SACK 块过多（说明乱序/丢包严重）
5. 乱序报文严重
6. MSS 过小 / Path MTU Discovery 失败
7. TCP 选项缺失（Timestamps、WScale、SACK-Permitted）
8. 拥塞窗口不足（飞行字节数远小于 BDP）

### 第二步：自由探索

基于报文数据自由分析，找出上述清单之外的可能原因，例如但不限于：
- NIC 接收端丢包（ring buffer 溢出）
- 服务端限速 / QoS 策略
- TCP Offload 异常
- 链路层重传（无线环境）
- 其他任何报文头部可观测的异常

### 第三步：综合输出

1. 汇总所有发现（常见原因 + 自由探索发现）
2. 给出每个原因对速率不达标的贡献概率
3. 按概率从高到低排列
4. 给出综合诊断结论和建议
5. 如果数据不足以判断某个原因，明确说明而非猜测

## 输出格式

```json
{
  "standard_bandwidth": "{standard_bandwidth} Mbps",
  "actual_bandwidth": "{actual_bandwidth} Mbps",
  "achievement_ratio": "{ratio}%",
  "diagnosis": [
    {
      "cause": "原因名称",
      "probability": "概率%",
      "evidence": "报文数据中的具体证据",
      "affected_flows": ["受影响的流"],
      "suggestion": "排查建议"
    }
  ],
  "summary": "综合诊断结论"
}
```
