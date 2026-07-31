# 使用 Wireshark 抓包分析 TCP 协议

> 来源：CSDN 博主“大草原的小灰灰”（账号：new9232）
>
> 原文：https://blog.csdn.net/new9232/article/details/124225524
>
> 首次发布：2022-04-17
>
> 许可：[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)
>
> 改编说明：本文由原网页清理为 Markdown，移除了广告、评论和推荐内容，补充了图片替代文本及协议适用边界。正文和配图沿用原许可。

本文以 Wireshark 抓包截图介绍 TCP/IP 分层、TCP 三次握手、数据传输中的序列号与确认应答，以及连接终止过程。

## 阅读说明

- 截图中显示的 `seq=0`、`ack=1` 等通常是 Wireshark 默认启用“相对序列号”后的结果，并不代表线上 TCP 初始序列号固定为 0。
- TCP 确认号表示接收方下一步期望收到的序列号。SYN 和 FIN 各占用一个序列号空间。
- TCP 连接终止不保证每次都能在抓包中看到四个彼此独立的数据包。ACK 与 FIN 可以合并发送，但协议状态转换仍需结合端点行为判断。
- 本文是入门教程和抓包示例，不替代 RFC 9293 等 TCP 标准，也不应单独作为现网吞吐故障的根因证据。

## 1. 协议分层介绍

Wireshark 的数据包详细信息栏会按协议层次展示各字段。

![Wireshark 数据包详细栏中的协议分层](images/4c33d334ffb6bc112bea10bf58ce7881.png)

### 1.1 数据链路层

展开数据链路层字段，可以看到当前链路上相邻设备使用的源 MAC 地址和目的 MAC 地址。

![Wireshark 以太网帧中的源和目的 MAC 地址](images/1c5d9ad974512edfebe0a403cdb6a1d6.png)

### 1.2 网络层

网络层负责提供源 IP 地址、目的 IP 地址等网络层信息，并承载传输层报文。

![Wireshark IPv4 网络层字段](images/9aee2bf5081b6cf74b5f1186cbf0310a.png)

### 1.3 传输层

该示例的传输层使用 TCP 协议。TCP 首部包含源端口、目的端口、序列号、确认号、标志位、窗口等字段。

![TCP 首部字段结构示意图](images/aa94efdf790db32b13e00bef4a0cea4b.png)

Wireshark 会把捕获到的 TCP 字段解析到对应的首部结构中。

![Wireshark TCP 字段与 TCP 首部的对应关系](images/1c22fc4cca0e2ec79a17bea8cd39083b.png)

## 2. TCP 三次握手

![TCP 三次握手示意图](images/9d1f4a3c93722c743f3c50aa9df2ec56.png)

1. 第一次握手：客户端向服务器发送 SYN 段，发起连接请求并携带客户端初始序列号。
2. 第二次握手：服务端返回 SYN+ACK，确认客户端的 SYN，同时携带服务端初始序列号。
3. 第三次握手：客户端返回 ACK，确认服务端的 SYN，连接建立。

原文示例使用 Wireshark 相对序列号显示，因此客户端和服务端的初始序列号都显示为 `seq=0`，对 SYN 的确认显示为 `ack=1`。

### 2.1 Wireshark 握手概览

发起连接后，可以在数据包列表中定位三次握手报文。

![Wireshark 中三次握手的数据包列表](images/91121cc3119b9be454513f5aec34d7e6.png)

### 2.2 第一次握手：SYN

客户端发起 SYN 请求，Wireshark 的相对初始序列号显示为 0。

![第一次握手 SYN 报文摘要](images/01acb87b1ef1b853227e8365a7789f70.png)

![第一次握手 SYN 报文详细字段](images/eab5c9670bfaed1b6a4f97e882f3f62b.png)

### 2.3 第二次握手：SYN+ACK

服务端返回 SYN+ACK。示例中服务端相对序列号为 `seq=0`，确认号为 `ack=1`。

![第二次握手 SYN ACK 报文摘要](images/3a2c79ec33a898779a9333970faac9a2.png)

![第二次握手 SYN ACK 报文详细字段](images/918df318f75bd5dcc146879296843e40.png)

### 2.4 第三次握手：ACK

客户端返回 ACK。示例中相对确认号为 `ack=1`，客户端相对序列号更新为 `seq=1`。至此客户端与服务端建立连接。

![第三次握手 ACK 报文摘要](images/1effeb601f70631f1e8bddbcc71ae524.png)

![第三次握手 ACK 报文详细字段](images/9e742007ec8de512063f617876217661.png)

## 3. TCP 数据传输

TCP 使用序列号、确认应答、重传等机制提供可靠的字节流传输。确认号通常表示接收方下一步期望收到的字节序列号。

示例中客户端分两次向服务端发送字符串：第一次发送 `hello`，第二次发送原文所写的 `word`。示意图展示了发送方序列号与接收方确认号之间的关系。

![TCP 数据传输中序列号和确认号变化示意图](images/d67b43eb6948c0595837a83e80a80897.png)

Wireshark 数据包列表中可以看到两次数据发送以及服务端的确认应答。

![Wireshark 中两次 TCP 数据传输的数据包列表](images/20de30652b88e695f8c6bfdb033a6e3b.png)

### 3.1 第一次发送

客户端第一次发送字符串 `hello`。原文截图显示该段 TCP 载荷长度为 6 字节，可能包含字符串结束符或其他额外字节，实际应以 TCP payload 长度字段为准。

![第一次发送 hello 的数据内容和长度](images/1547e367bf72e4bc2bad028dc1016f38.png)

该段的相对序列号为 `seq=1`。

![第一次发送数据时的相对序列号](images/7960e389aa4c360b14b9e3a7668e81d6.png)

服务端返回 `ack=7`，表示已经确认此前的字节，并期望下一字节从相对序列号 7 开始。

![服务端对第一次发送返回确认号 7](images/570a6cebaa4dbc3c5eac2cfc197f1c97.png)

### 3.2 第二次发送

第二次发送字符串 `word` 时，客户端相对序列号使用前一次服务端返回的确认号，即 `seq=7`。

![第二次发送数据时相对序列号更新为 7](images/e0cd765d4d4dc17d1f22333f72d734de.png)

服务端对第二次数据返回的相对确认号为 `ack=12`。

![服务端对第二次发送返回确认号 12](images/385d1bf28639b1e55b7e98ebe2b133f2.png)

## 4. TCP 连接终止

![TCP 四次挥手状态示意图](images/8e4aa6184a967b64e1a3a11ed4843f6c.png)

典型的主动关闭过程可表述为：

1. 主动关闭方发送 FIN，表示该方向不再发送数据。
2. 对端返回 ACK，确认收到 FIN。
3. 对端准备关闭其发送方向时发送 FIN。
4. 主动关闭方返回 ACK，确认对端的 FIN。

原文抓包只显示三个报文，因为第二步 ACK 和第三步 FIN 被合并为一个 FIN+ACK 报文。

![Wireshark 中三个报文完成连接终止的列表](images/33c7785ef2cfa4010094cc9f47e97dd7.png)

### 4.1 第一次挥手：FIN

客户端发送 FIN 请求。示例使用相对序列号，显示 `seq=12`、`ack=23`；这里的确认号延续此前数据通信状态。

![客户端第一次挥手 FIN 报文详细字段](images/ac4a6cba38c5cf0ff0fc6cd73265cd38.png)

### 4.2 第二、三次挥手：FIN+ACK

服务端用同一个报文发送 ACK 和 FIN，既确认客户端的 FIN，又关闭服务端的发送方向。示例显示 `ack=13`、`seq=23`。

![服务端合并发送 FIN ACK 报文详细字段](images/52fd6499dd053839bcc204fee9b11d01.png)

### 4.3 第四次挥手：ACK

客户端返回 ACK，确认服务端的 FIN。示例显示 `ack=24`、`seq=13`。

![客户端最后一次 ACK 报文详细字段](images/9cde0e76056f8adc1ebd858529774121.png)

## 参考

- 原文：[使用Wireshark抓包分析TCP协议](https://blog.csdn.net/new9232/article/details/124225524)
- 许可：[Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/)
- TCP 标准：[RFC 9293 - Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc9293)
