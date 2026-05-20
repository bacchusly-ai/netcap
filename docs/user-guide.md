# Netcap 使用手册

Netcap 是一个高性能网络流量采集与协议解析代理，通过 AF_PACKET 零拷贝抓包、多级流水线处理、TCP 流重组，将解析后的应用层协议事件以 JSON 格式推送到 Kafka，供下游安全分析、审计和监控系统消费。

---

## 目录

1. [快速开始](#1-快速开始)
2. [架构说明](#2-架构说明)
3. [命令行参数](#3-命令行参数)
4. [支持的协议](#4-支持的协议)
5. [输出数据格式](#5-输出数据格式)
6. [配置调优指南](#6-配置调优指南)
7. [监控指标参考](#7-监控指标参考)
8. [消费端对接](#8-消费端对接)
9. [运维操作](#9-运维操作)
10. [FAQ](#10-faq)

---

## 1. 快速开始

### 三步启动

**第一步：下载二进制**

```bash
# 从 release 页面下载对应平台的二进制
wget https://github.com/netcap/netcap/releases/latest/download/netcap-amd64 -O netcap
chmod +x netcap
sudo mv netcap /usr/local/bin/
```

**第二步：修改配置**

复制默认配置并修改关键字段：

```bash
sudo mkdir -p /etc/netcap
cp configs/netcap.yaml /etc/netcap/netcap.yaml
```

编辑 `/etc/netcap/netcap.yaml`，修改以下两个必填项：

```yaml
capture:
  interface: "eth0"        # 改为你的网卡名称，如 ens192、bond0

kafka:
  brokers:
    - "kafka1:9092"        # 改为你的 Kafka broker 地址
    - "kafka2:9092"
```

**最小配置示例**（只需修改 `interface` 和 `brokers`，其余使用默认值）：

```yaml
capture:
  interface: "ens192"

kafka:
  brokers:
    - "10.0.1.10:9092"
    - "10.0.1.11:9092"
  topic: "netcap-events"
```

**第三步：启动**

```bash
sudo netcap --config /etc/netcap/netcap.yaml
```

> 注意：抓包需要 root 权限或 `CAP_NET_RAW`、`CAP_NET_ADMIN` 能力。推荐使用 capability 方式：
> ```bash
> sudo setcap 'cap_net_raw,cap_net_admin,cap_bpf+ep' /usr/local/bin/netcap
> ```

### 验证运行

默认 metrics 端口为 `:9090`，路径 `/metrics`：

```bash
# 检查进程是否存活
curl -s http://localhost:9090/metrics | head -20

# 检查抓包计数是否在增长
curl -s http://localhost:9090/metrics | grep netcap_packets_captured_total

# 检查 Kafka 是否发送成功
curl -s http://localhost:9090/metrics | grep netcap_kafka_messages_sent_total
```

---

## 2. 架构说明

### 数据流图

```
                          netcap 内部流水线
 ┌─────┐    ┌─────────┐    ┌────────┐    ┌───────────┐
 │ NIC │───>│ Capture  │───>│ Decode │───>│ Splitter  │
 └─────┘    │(AF_PACKET│    │(N workers)  │(TCP/UDP)  │
            │ 零拷贝)  │    └────────┘    └─────┬─────┘
            └─────────┘                         │
                                    ┌───────────┴───────────┐
                                    │                       │
                              ┌─────▼──────┐          ┌─────▼─────┐
                              │    TCP     │          │    UDP    │
                              │ Reassembly │          │  (直接)   │
                              └─────┬──────┘          └─────┬─────┘
                                    │                       │
                                    └───────────┬───────────┘
                                                │
                                          ┌─────▼──────┐
                                          │ Dispatcher │
                                          │(协议识别+  │
                                          │  解析)     │
                                          └─────┬──────┘
                                                │
                                          ┌─────▼──────┐
                                          │   Kafka    │
                                          │  Producer  │
                                          │(多worker   │
                                          │  批量发送) │
                                          └─────┬──────┘
                                                │
                                          ┌─────▼──────┐
                                          │   Kafka    │
                                          │  Cluster   │
                                          └────────────┘
```

### 各阶段功能简述

| 阶段 | 组件 | 说明 |
|------|------|------|
| **Capture** | `afpacket.Capturer` | 使用 AF_PACKET mmap 环形缓冲区从网卡零拷贝收包，支持多队列和 fanout |
| **Decode** | `decode.Decoder` | 多 worker 并行解码以太网/IP/TCP/UDP 包头，提取五元组信息 |
| **Splitter** | `packetSplitter` | 按传输层协议号分流：TCP(6) 进重组、UDP(17) 直接进调度 |
| **TCP Reassembly** | `reassembly.Reassembler` | TCP 流重组，处理乱序、重传、分片，还原完整应用层数据 |
| **Dispatcher** | `dispatch.Dispatcher` | 通过端口匹配 + DPI 探测识别协议，调用对应 Parser 解析 |
| **Kafka Producer** | `output.Producer` | 多 worker 异步批量写入 Kafka，按流哈希分区保证同一会话有序 |

### 背压机制说明

各阶段之间通过带缓冲的 Go channel 连接（默认缓冲大小 `channel_buffer: 4096`）。当下游处理速度跟不上时：

1. **Channel 满** -- 上游 goroutine 阻塞在 channel 写入操作，自动降速
2. **Capture 环缓冲区满** -- AF_PACKET 内核环缓冲区溢出，内核丢包，`packets_dropped_total` 指标增长
3. **Kafka 写入慢** -- Producer 的 input channel 满，Dispatcher 阻塞，进而逐级向上传导

监控 `netcap_channel_utilization_ratio` 指标可以及时发现瓶颈所在阶段。

---

## 3. 命令行参数

### --config

指定配置文件路径，默认为 `configs/netcap.yaml`。

```bash
netcap --config /etc/netcap/netcap.yaml
netcap --config ./my-config.yaml
netcap  # 使用默认路径 configs/netcap.yaml
```

### 环境变量覆盖配置

Netcap 使用 [Viper](https://github.com/spf13/viper) 加载配置，支持通过环境变量覆盖 YAML 中的配置项。环境变量命名规则：

- 前缀：`NETCAP_`
- 层级分隔：使用 `_`（下划线）
- 全大写

**对照表：**

| YAML 路径 | 环境变量 | 示例值 |
|-----------|---------|--------|
| `capture.interface` | `NETCAP_CAPTURE_INTERFACE` | `eth0` |
| `capture.num_queues` | `NETCAP_CAPTURE_NUM_QUEUES` | `4` |
| `capture.bpf_filter` | `NETCAP_CAPTURE_BPF_FILTER` | `tcp port 80` |
| `decode.workers` | `NETCAP_DECODE_WORKERS` | `8` |
| `decode.channel_buffer` | `NETCAP_DECODE_CHANNEL_BUFFER` | `8192` |
| `kafka.topic` | `NETCAP_KAFKA_TOPIC` | `netcap-prod` |
| `kafka.compression` | `NETCAP_KAFKA_COMPRESSION` | `lz4` |
| `metrics.listen` | `NETCAP_METRICS_LISTEN` | `:9090` |
| `logging.level` | `NETCAP_LOGGING_LEVEL` | `debug` |

**使用示例：**

```bash
# 通过环境变量指定网卡和日志级别
NETCAP_CAPTURE_INTERFACE=ens192 \
NETCAP_LOGGING_LEVEL=debug \
netcap --config /etc/netcap/netcap.yaml
```

---

## 4. 支持的协议

### 协议列表

| 协议 | 类型 | 默认端口 | 提取的关键字段 |
|------|------|---------|---------------|
| HTTP | TCP | 80, 8080, 8000, 8888, 3000 | method, url, host, status_code, headers, content_type, body, body_length, body_truncated |
| DNS | TCP/UDP | 53, 5353 | transaction_id, op_code, response_code, questions, answers |
| TLS | TCP | 443, 8443, 993, 995, 465, 636 | version, server_name(SNI), ja3, alpn_protocols, handshake_type, certificate_chain |
| MySQL | TCP | 3306, 33060 | system, operation(COM_QUERY等), statement, error_code, error_msg |
| PostgreSQL | TCP | 5432 | system, operation(SimpleQuery/Parse/ErrorResponse), statement, error_msg |
| Redis | TCP | 6379, 6380 | system, operation(命令名), statement(完整命令), error_msg |
| MongoDB | TCP | 27017, 27018, 27019 | system, operation(命令名), table(集合名) |
| SMTP | TCP | 25, 587 | command, line(完整命令行), code(响应码), message |
| FTP | TCP | 21 | command, line, code, message |
| IMAP | TCP | 143, 993 | tag, command, line(响应行) |
| POP3 | TCP | 110, 995 | command, status(OK/ERR), line |
| MQTT | TCP | 1883, 8883 | packet_type, topic, client_id |
| WebSocket | TCP | 80, 443, 8080 | type(upgrade/frame), opcode, ws_key, ws_protocol, payload_len |
| SSH | TCP | 22 | version_string, protocol_version, software |
| Unknown | TCP/UDP | (无) | raw_hex(前128字节十六进制), total_size |

### 各协议详细说明

#### HTTP

解析 HTTP/1.x 请求和响应。通过标准库 `net/http` 解析，提取：

- **请求方向**：method、url（RequestURI）、host、headers（全部头字段）、content_type、body、body_length、body_truncated
- **响应方向**：status_code、headers、content_type、body、body_length、body_truncated
- **DPI 探测**：检测数据是否以 `GET `、`POST `、`PUT `、`DELETE `、`HEAD `、`PATCH `、`OPTIONS `、`HTTP/` 开头，置信度 90
- **Body 抓取**：受 `protocols.http.max_body_capture` 控制，0 表示不抓 body，>0 表示按字节截断。超过上限时 `body_truncated=true`，`body_length` 仍反映原始 Content-Length，便于消费端判断是否被截断
- **Keep-alive / Pipelining**：单次 reassembly buffer 内可能含多条请求或响应，parser 会逐条解析并发出多条事件
- **请求-响应配对**：每条事件附带 `uid` 字段（详见第 5 节），下游消费者匹配相同 uid 即可配对一次往返

#### DNS

手写的 DNS 协议解析器（无外部依赖），支持完整的 DNS 消息解码：

- **查询**：transaction_id、op_code、questions（name/type/class）
- **响应**：response_code、answers（name/type/class/ttl/data）
- 支持域名压缩指针解析
- 支持的 RR 类型：A、NS、CNAME、SOA、PTR、MX、TXT、AAAA、SRV、HTTPS

#### TLS

解析 TLS ClientHello 握手消息，不解密加密内容：

- **SNI**（Server Name Indication）：目标域名
- **JA3 指纹**：基于 TLS 版本、密码套件、扩展、椭圆曲线、EC 点格式计算的 MD5 哈希
- **ALPN**：应用层协议协商列表（如 h2、http/1.1）
- **版本**：SSL 3.0 / TLS 1.0 / TLS 1.1 / TLS 1.2 / TLS 1.3
- **证书链**：可选提取（`tls.extract_certificates: true`，开销较大）
- JA3 原始字符串也存储在 `metadata.ja3_raw` 中

#### MySQL

解析 MySQL 线协议：

- **请求**：`COM_QUERY`（SQL 查询）、`COM_STMT_PREPARE`（预处理语句）
- **响应**：`OK` 包、`ERR` 包（含错误码和错误消息）
- SQL 语句长度可通过 `protocols.db.max_query_length` 配置截断

#### PostgreSQL

解析 PostgreSQL v3 线协议：

- **SimpleQuery**（'Q' 消息）：完整 SQL 语句
- **Parse**（'P' 消息）：扩展查询/预处理语句的 SQL
- **ErrorResponse**（'E' 消息）：severity + SQLSTATE code + 错误消息

#### Redis

解析 Redis RESP 序列化协议：

- **命令**：命令名（如 GET、SET、HGET）+ 完整命令文本
- **错误**：RESP 错误行的错误消息
- 支持嵌套数组解析

#### MongoDB

解析 MongoDB 线协议：

- **OP_MSG**（3.6+ 主流格式）：提取命令名（如 find、insert、update）和目标集合名
- **OP_QUERY**（旧版）：提取集合全名
- 通过简化的 BSON 解析提取首个键值

#### SMTP

解析 SMTP 命令/响应交互：

- **客户端命令**：EHLO、HELO、MAIL FROM、RCPT TO、DATA、QUIT、AUTH 等
- **服务器响应**：三位数字响应码 + 消息文本

#### FTP

解析 FTP 控制通道：

- **客户端命令**：USER、PASS、LIST、RETR、STOR、CWD、PWD、QUIT 等
- **服务器响应**：三位数字响应码 + 消息文本

#### IMAP

解析 IMAP 命令/响应：

- **客户端命令**：LOGIN、SELECT、FETCH、LIST、LOGOUT、CAPABILITY、SEARCH 等，附带 tag
- **服务器响应**：完整响应行（截断至 256 字符）

#### POP3

解析 POP3 命令/响应：

- **客户端命令**：USER、PASS、RETR、LIST、QUIT 等
- **服务器响应**：+OK / -ERR 状态

#### MQTT

解析 MQTT v3.1.1/v5 协议：

- **包类型**：CONNECT、CONNACK、PUBLISH、SUBSCRIBE、UNSUBSCRIBE、PINGREQ/RESP、DISCONNECT 等
- **CONNECT**：提取 client_id
- **PUBLISH**：提取 topic 名称

#### WebSocket

解析 WebSocket 升级握手和帧头：

- **升级阶段**：检测 HTTP Upgrade 头，提取 Sec-WebSocket-Key、Sec-WebSocket-Protocol
- **帧阶段**：提取 opcode（text/binary/close/ping/pong）、fin 标志、masked 标志、payload 长度

#### SSH

解析 SSH 版本交换字符串：

- **版本字符串**：如 `SSH-2.0-OpenSSH_8.9`
- **协议版本**：如 `SSH-2.0`
- **软件标识**：如 `OpenSSH_8.9`

---

## 5. 输出数据格式

### Kafka 消息结构

- **Topic**：配置项 `kafka.topic`，默认为 `netcap-events`
- **Key**：8 字节 FNV-1a 哈希值，基于四元组（src_ip + dst_ip + src_port + dst_port）计算，保证同一流的消息落入同一分区
- **Value**：JSON 编码的 `ProtocolEvent` 对象
- **分区策略**：使用 `kafka-go` 的 `ReferenceHash` Balancer，按 Key 哈希选分区

### ProtocolEvent 完整字段说明

| 字段 | JSON Key | 类型 | 说明 |
|------|----------|------|------|
| 时间戳 | `timestamp_ns` | int64 | Unix 纳秒时间戳 |
| 关联ID | `uid` | string | 请求-响应配对标识，格式 `"<16位hex(conn_id)>-<seq>"`。同一对 HTTP 请求/响应共享同一 uid，下游消费者据此配对；未参与配对的协议（如 DNS、TLS 单条事件）此字段为空 |
| 源IP | `src_ip` | []byte | 源 IP 地址（4字节 IPv4 / 16字节 IPv6） |
| 目标IP | `dst_ip` | []byte | 目标 IP 地址 |
| 源端口 | `src_port` | uint32 | 源端口号 |
| 目标端口 | `dst_port` | uint32 | 目标端口号 |
| 协议 | `protocol` | string | 协议名称（http/dns/tls/mysql/postgres/redis/mongodb/smtp/ftp/imap/pop3/mqtt/websocket/ssh/unknown） |
| 方向 | `direction` | int | 0=未知, 1=请求, 2=响应 |
| 元数据 | `metadata` | map[string]string | 协议特定的键值对元数据（可选） |
| 原始摘要 | `raw_excerpt` | []byte | 原始载荷前 N 字节（可选，主要用于 unknown 协议） |
| HTTP详情 | `http_detail` | object | HTTP 协议详情（可选） |
| DNS详情 | `dns_detail` | object | DNS 协议详情（可选） |
| TLS详情 | `tls_detail` | object | TLS 协议详情（可选） |
| DB详情 | `db_detail` | object | 数据库协议详情（可选） |

### HTTPDetail 子结构

| 字段 | JSON Key | 类型 | 说明 |
|------|----------|------|------|
| 方法 | `method` | string | HTTP 方法（GET/POST/PUT 等） |
| URL | `url` | string | 请求 URI |
| 主机 | `host` | string | Host 头 |
| 状态码 | `status_code` | int32 | HTTP 响应状态码 |
| 头字段 | `headers` | map[string]string | HTTP 头字段键值对 |
| 内容类型 | `content_type` | string | Content-Type 头 |
| 正文 | `body` | []byte | 报文 Body 内容，JSON 序列化为 Base64；长度受 `protocols.http.max_body_capture` 限制 |
| 正文长度 | `body_length` | int64 | 原始声明的 Content-Length；chunked 传输或长度未知时可能为 -1。可能大于 `len(body)`（被截断时） |
| 正文截断 | `body_truncated` | bool | true 表示原始 body 超过 `max_body_capture`，`body` 字段只是前 N 字节 |

### DNSDetail 子结构

| 字段 | JSON Key | 类型 | 说明 |
|------|----------|------|------|
| 事务ID | `transaction_id` | uint16 | DNS 事务标识符 |
| 操作码 | `op_code` | int32 | DNS 操作码（0=标准查询） |
| 响应码 | `response_code` | int32 | DNS 响应码（0=NOERROR, 3=NXDOMAIN 等） |
| 查询 | `questions` | []DNSQuestion | 查询记录列表 |
| 应答 | `answers` | []DNSAnswer | 应答记录列表 |

**DNSQuestion**：`name`(string) + `type`(string, 如 A/AAAA/CNAME) + `class`(string, 如 IN)

**DNSAnswer**：`name`(string) + `type`(string) + `class`(string) + `ttl`(uint32) + `data`(string)

### TLSDetail 子结构

| 字段 | JSON Key | 类型 | 说明 |
|------|----------|------|------|
| 版本 | `version` | string | TLS 版本（如 "TLS 1.2"） |
| 密码套件 | `cipher_suite` | string | 协商的密码套件名称或 JA3 指纹哈希（具体取决于握手阶段） |
| 服务器名 | `server_name` | string | SNI 域名 |
| 握手类型 | `handshake_type` | int32 | 握手消息类型（1=ClientHello） |
| 证书链 | `certificate_chain` | []string | 证书链信息（需开启配置） |
| ALPN | `alpn_protocols` | []string | ALPN 协议列表 |

> `metadata` 中还包含 `ja3`（JA3 哈希）和 `ja3_raw`（JA3 原始字符串）。

### DBDetail 子结构

| 字段 | JSON Key | 类型 | 说明 |
|------|----------|------|------|
| 系统 | `system` | string | 数据库类型（mysql/postgres/redis/mongodb） |
| 操作 | `operation` | string | 操作类型（如 COM_QUERY/SimpleQuery/GET/find） |
| 语句 | `statement` | string | SQL/命令全文 |
| 数据库 | `database` | string | 数据库名 |
| 表 | `table` | string | 表名/集合名 |
| 错误码 | `error_code` | int32 | 数据库错误码 |
| 错误消息 | `error_msg` | string | 错误消息文本 |
| 延迟 | `latency` | int64 | 请求延迟（纳秒） |
| 行数 | `row_count` | int64 | 影响/返回的行数 |

### 示例 JSON 输出

#### HTTP 请求示例

```json
{
  "timestamp_ns": 1712150400000000000,
  "uid": "a3f1c9e72b8d4501-0",
  "src_ip": "kgqLAQ==",
  "dst_ip": "rBIAAQ==",
  "src_port": 52431,
  "dst_port": 80,
  "protocol": "http",
  "direction": 1,
  "http_detail": {
    "method": "POST",
    "url": "/api/v1/login",
    "host": "api.example.com",
    "headers": {
      "Accept": "application/json",
      "Content-Type": "application/json",
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"
    },
    "content_type": "application/json",
    "body": "eyJ1c2VybmFtZSI6ImFsaWNlIiwicGFzc3dvcmQiOiIqKioqIn0=",
    "body_length": 50
  }
}
```

> 说明：`body` 是 Base64 编码的 `{"username":"alice","password":"****"}`；`body_length` 与解码后字节数一致，表示未被截断。

#### HTTP 响应示例（与上面请求配对）

```json
{
  "timestamp_ns": 1712150400123456000,
  "uid": "a3f1c9e72b8d4501-0",
  "src_ip": "rBIAAQ==",
  "dst_ip": "kgqLAQ==",
  "src_port": 80,
  "dst_port": 52431,
  "protocol": "http",
  "direction": 2,
  "http_detail": {
    "status_code": 200,
    "headers": {
      "Content-Type": "application/json",
      "Content-Length": "42"
    },
    "content_type": "application/json",
    "body": "eyJ0b2tlbiI6ImV5SmhiR2NpT2lKSVV6STFOaUo5In0=",
    "body_length": 42
  }
}
```

> 配对规则：消费者匹配相同 `uid` 即可把请求和响应关联起来。本例中两条事件的 uid 都是 `"a3f1c9e72b8d4501-0"`，表示这是该 TCP 连接（conn_id=a3f1c9e72b8d4501）上的第 0 对请求/响应。Keep-alive 后续的第 1 对、第 2 对会依次得到 uid `…-1`、`…-2`。

#### DNS 查询示例

```json
{
  "timestamp_ns": 1712150400100000000,
  "src_ip": "kgqLAQ==",
  "dst_ip": "CAgICA==",
  "src_port": 41923,
  "dst_port": 53,
  "protocol": "dns",
  "direction": 1,
  "dns_detail": {
    "transaction_id": 43521,
    "op_code": 0,
    "response_code": 0,
    "questions": [
      {
        "name": "api.example.com",
        "type": "A",
        "class": "IN"
      }
    ],
    "answers": [
      {
        "name": "api.example.com",
        "type": "A",
        "class": "IN",
        "ttl": 300,
        "data": "172.18.0.1"
      }
    ]
  }
}
```

#### TLS ClientHello 示例

```json
{
  "timestamp_ns": 1712150400200000000,
  "src_ip": "kgqLAQ==",
  "dst_ip": "rBIAAQ==",
  "src_port": 52432,
  "dst_port": 443,
  "protocol": "tls",
  "direction": 1,
  "metadata": {
    "ja3": "e7d705a3286e19ea42f587b344ee6865",
    "ja3_raw": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-16-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2"
  },
  "tls_detail": {
    "version": "TLS 1.2",
    "cipher_suite": "e7d705a3286e19ea42f587b344ee6865",
    "server_name": "api.example.com",
    "handshake_type": 1,
    "alpn_protocols": [
      "h2",
      "http/1.1"
    ]
  }
}
```

#### MySQL 查询示例

```json
{
  "timestamp_ns": 1712150400300000000,
  "src_ip": "kgqLAQ==",
  "dst_ip": "kgqMAQ==",
  "src_port": 49210,
  "dst_port": 3306,
  "protocol": "mysql",
  "direction": 1,
  "db_detail": {
    "system": "mysql",
    "operation": "COM_QUERY",
    "statement": "SELECT id, username, email FROM users WHERE status = 'active' ORDER BY created_at DESC LIMIT 100"
  }
}
```

---

## 6. 配置调优指南

### 低流量场景（< 1 Gbps）

适用于开发测试环境或小型办公网络，使用默认配置即可。

```yaml
capture:
  interface: "eth0"
  num_queues: 1
  buffer_size: 4194304       # 4 MiB

decode:
  workers: 4
  channel_buffer: 4096

reassembly:
  max_buffered_pages_per_conn: 256
  max_buffered_pages_total: 65536

kafka:
  batch_size: 100
  batch_timeout: "500ms"
  num_workers: 2
  compression: "lz4"
```

**硬件建议**：2 核 CPU、4 GB 内存

### 中流量场景（1-5 Gbps）

适用于中等规模数据中心或核心交换镜像。

```yaml
capture:
  interface: "eth0"
  num_queues: 4
  buffer_size: 16777216      # 16 MiB
  fanout:
    enabled: true
    type: "hash"
    size: 4
    group_id: 1

decode:
  workers: 8
  channel_buffer: 8192

reassembly:
  max_buffered_pages_per_conn: 512
  max_buffered_pages_total: 131072
  connection_timeout: "1m"

kafka:
  batch_size: 500
  batch_timeout: "200ms"
  num_workers: 4
  compression: "lz4"
  max_message_bytes: 1048576

runtime:
  gomaxprocs: 8
```

**硬件建议**：8 核 CPU、16 GB 内存、万兆网卡

### 高流量场景（5-10 Gbps）

适用于大规模数据中心出口镜像流量。

```yaml
capture:
  interface: "eth0"
  num_queues: 8
  buffer_size: 33554432      # 32 MiB
  snap_length: 1500           # 不需要巨帧时降低 snap_length 可提升性能
  fanout:
    enabled: true
    type: "cpu"               # CPU 亲和分发，减少跨核缓存失效
    size: 8
    group_id: 1

decode:
  workers: 16
  channel_buffer: 16384

reassembly:
  max_buffered_pages_per_conn: 256    # 适当降低防止单连接占用过多内存
  max_buffered_pages_total: 262144
  connection_timeout: "30s"           # 缩短超时，更积极地释放资源
  max_connection_age: "5m"
  flush_interval: "15s"

kafka:
  batch_size: 1000
  batch_timeout: "100ms"
  num_workers: 8
  compression: "lz4"
  required_acks: 1            # leader-only ack 降低延迟
  max_message_bytes: 1048576

protocols:
  http:
    max_body_capture: 0       # 高流量下不采集 body
    capture_headers: false    # 减少数据量
  tls:
    extract_ja3: true
    extract_certificates: false
  db:
    max_query_length: 2048    # 截断过长 SQL

runtime:
  gomaxprocs: 16
```

**硬件建议**：16+ 核 CPU、32 GB 内存、支持 RSS 多队列的万兆网卡

### 关键参数对性能的影响

| 参数 | 影响 | 调优建议 |
|------|------|---------|
| `capture.num_queues` | 收包并行度。增加队列可利用多核，但过多会增加上下文切换 | 设为 CPU 核数的 1/2 到与核数相等 |
| `capture.buffer_size` | AF_PACKET 环缓冲区大小。过小会导致内核丢包 | 流量越大应越大，建议 4MB-32MB |
| `capture.snap_length` | 每包最大捕获字节数。9000 支持巨帧但浪费内存 | 无巨帧环境设为 1500 |
| `capture.fanout.type` | `hash`=按流哈希分发，`cpu`=按 CPU 亲和分发，`lb`=负载均衡 | 高流量推荐 `cpu` 减少缓存抖动 |
| `decode.workers` | 解码并行度 | 一般等于 `num_queues` 或其 2 倍 |
| `decode.channel_buffer` | 各阶段间 channel 缓冲大小。过小增加阻塞，过大浪费内存 | 4096-16384 |
| `reassembly.max_buffered_pages_total` | TCP 重组总内存上限（页数 x 页大小） | 按可用内存设置 |
| `reassembly.connection_timeout` | 空闲连接超时。过长占用内存，过短可能丢失慢连接数据 | 30s-2m |
| `kafka.batch_size` | 每批消息数。增大减少系统调用，但增加延迟 | 100-1000 |
| `kafka.batch_timeout` | 批次最大等待时间 | 100ms-500ms |
| `kafka.num_workers` | Kafka 写入并行度 | 2-8，视 broker 集群能力 |
| `kafka.compression` | 压缩算法。lz4 速度最快，gzip 压缩比最高 | 推荐 lz4 |

---

## 7. 监控指标参考

### 完整指标列表

| 指标名 | 类型 | 标签 | 含义 |
|-------|------|------|------|
| `netcap_packets_captured_total` | Counter | `queue` | 各队列捕获的总包数 |
| `netcap_packets_dropped_total` | Counter | `queue`, `reason` | 各队列丢弃的总包数（按原因分类） |
| `netcap_capture_bytes_total` | Counter | `queue` | 各队列捕获的总字节数 |
| `netcap_decode_latency_seconds` | Histogram | (无) | 单包解码延迟（桶：1us, 10us, 100us, 1ms, 10ms, 100ms, 1s） |
| `netcap_active_streams` | Gauge | (无) | 当前活跃的 TCP 重组流数量 |
| `netcap_reassembly_pages_used` | Gauge | (无) | TCP 重组引擎当前使用的页缓冲数 |
| `netcap_protocol_events_total` | Counter | `protocol`, `direction` | 各协议解析出的事件总数 |
| `netcap_parse_errors_total` | Counter | `protocol`, `error_type` | 各协议解析错误总数 |
| `netcap_kafka_messages_sent_total` | Counter | (无) | 成功发送到 Kafka 的消息总数 |
| `netcap_kafka_send_errors_total` | Counter | (无) | Kafka 发送失败总数 |
| `netcap_kafka_batch_latency_seconds` | Histogram | (无) | Kafka 批量写入延迟（默认桶） |
| `netcap_channel_utilization_ratio` | Gauge | `stage` | 各阶段 channel 利用率（0-1） |

### 关键指标解读

#### 丢包率计算

```
丢包率 = netcap_packets_dropped_total / (netcap_packets_captured_total + netcap_packets_dropped_total) * 100%
```

正常情况下丢包率应低于 0.01%。如果持续增长，说明抓包速度跟不上线速，需要增加队列数或优化下游处理。

#### Channel 利用率

`netcap_channel_utilization_ratio` 反映各阶段间 channel 的填充程度：

- **< 0.5**：正常，有充足的余量
- **0.5 - 0.8**：开始出现拥塞迹象，需关注
- **> 0.8**：严重拥塞，可能导致上游背压和丢包

通过 `stage` 标签定位瓶颈阶段。

#### Kafka 延迟

`netcap_kafka_batch_latency_seconds` 反映每批消息写入 Kafka 的耗时：

- **p99 < 100ms**：正常
- **p99 100ms-500ms**：Kafka 集群可能有压力
- **p99 > 500ms**：需要排查 Kafka 集群状态或网络问题

### PromQL 查询示例

```promql
# 每秒捕获包速率
rate(netcap_packets_captured_total[1m])

# 总丢包率（所有队列）
sum(rate(netcap_packets_dropped_total[5m])) / (sum(rate(netcap_packets_captured_total[5m])) + sum(rate(netcap_packets_dropped_total[5m]))) * 100

# 每秒各协议事件产出率
sum by (protocol) (rate(netcap_protocol_events_total[1m]))

# Kafka 批写入延迟 p99
histogram_quantile(0.99, rate(netcap_kafka_batch_latency_seconds_bucket[5m]))

# 解码延迟 p95
histogram_quantile(0.95, rate(netcap_decode_latency_seconds_bucket[5m]))

# Channel 利用率最高的阶段
topk(3, netcap_channel_utilization_ratio)

# 活跃 TCP 流数量
netcap_active_streams

# 重组页缓冲使用率（假设 max_buffered_pages_total 为 65536）
netcap_reassembly_pages_used / 65536 * 100

# Kafka 发送错误率
rate(netcap_kafka_send_errors_total[5m]) / rate(netcap_kafka_messages_sent_total[5m]) * 100

# 各协议解析错误 TOP 5
topk(5, sum by (protocol, error_type) (rate(netcap_parse_errors_total[5m])))
```

---

## 8. 消费端对接

### Kafka Consumer 示例（Go）

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"

    "github.com/segmentio/kafka-go"
)

// ProtocolEvent 与 netcap 输出的 JSON 结构对应
type ProtocolEvent struct {
    TimestampNs int64             `json:"timestamp_ns"`
    UID         string            `json:"uid,omitempty"`
    SrcIP       []byte            `json:"src_ip"`
    DstIP       []byte            `json:"dst_ip"`
    SrcPort     uint32            `json:"src_port"`
    DstPort     uint32            `json:"dst_port"`
    Protocol    string            `json:"protocol"`
    Direction   int               `json:"direction"`
    Metadata    map[string]string `json:"metadata,omitempty"`
    HTTPDetail  *HTTPDetail       `json:"http_detail,omitempty"`
    DNSDetail   *DNSDetail        `json:"dns_detail,omitempty"`
    TLSDetail   *TLSDetail        `json:"tls_detail,omitempty"`
    DBDetail    *DBDetail         `json:"db_detail,omitempty"`
}

type HTTPDetail struct {
    Method        string            `json:"method,omitempty"`
    URL           string            `json:"url,omitempty"`
    Host          string            `json:"host,omitempty"`
    StatusCode    int32             `json:"status_code,omitempty"`
    Headers       map[string]string `json:"headers,omitempty"`
    ContentType   string            `json:"content_type,omitempty"`
    Body          []byte            `json:"body,omitempty"`
    BodyLength    int64             `json:"body_length,omitempty"`
    BodyTruncated bool              `json:"body_truncated,omitempty"`
}

type DNSDetail struct {
    TransactionID uint16 `json:"transaction_id,omitempty"`
    ResponseCode  int32  `json:"response_code,omitempty"`
}

type TLSDetail struct {
    ServerName string `json:"server_name,omitempty"`
}

type DBDetail struct {
    System    string `json:"system,omitempty"`
    Operation string `json:"operation,omitempty"`
    Statement string `json:"statement,omitempty"`
    ErrorMsg  string `json:"error_msg,omitempty"`
}

func main() {
    r := kafka.NewReader(kafka.ReaderConfig{
        Brokers:  []string{"kafka1:9092", "kafka2:9092"},
        Topic:    "netcap-events",
        GroupID:  "my-consumer-group",
        MinBytes: 1e3,  // 1 KB
        MaxBytes: 10e6, // 10 MB
    })
    defer r.Close()

    ctx := context.Background()
    for {
        msg, err := r.ReadMessage(ctx)
        if err != nil {
            log.Fatal("read error:", err)
        }

        var event ProtocolEvent
        if err := json.Unmarshal(msg.Value, &event); err != nil {
            log.Printf("unmarshal error: %v", err)
            continue
        }

        // 按协议分流处理
        switch event.Protocol {
        case "http":
            handleHTTP(&event)
        case "dns":
            handleDNS(&event)
        case "tls":
            handleTLS(&event)
        default:
            fmt.Printf("[%s] %s:%d -> %s:%d\n",
                event.Protocol, event.SrcIP, event.SrcPort,
                event.DstIP, event.DstPort)
        }
    }
}

// pending 暂存待配对的请求，等响应到来时合并输出。
// 生产环境应配上 LRU/TTL 防止孤儿请求长期占用内存。
var pending = map[string]*ProtocolEvent{}

func handleHTTP(ev *ProtocolEvent) {
    if ev.HTTPDetail == nil || ev.UID == "" {
        return
    }
    switch ev.Direction {
    case 1: // request
        pending[ev.UID] = ev
    case 2: // response
        req, ok := pending[ev.UID]
        if !ok {
            // 孤儿响应：对应的请求可能在本消费者启动前发出，或丢失
            fmt.Printf("HTTP ?  -> %d (uid=%s)\n", ev.HTTPDetail.StatusCode, ev.UID)
            return
        }
        delete(pending, ev.UID)
        fmt.Printf("HTTP %s %s host=%s status=%d req_body=%dB resp_body=%dB rtt=%dms\n",
            req.HTTPDetail.Method, req.HTTPDetail.URL, req.HTTPDetail.Host,
            ev.HTTPDetail.StatusCode,
            len(req.HTTPDetail.Body), len(ev.HTTPDetail.Body),
            (ev.TimestampNs-req.TimestampNs)/1_000_000)
    }
}

func handleDNS(ev *ProtocolEvent)  { /* ... */ }
func handleTLS(ev *ProtocolEvent)  { /* ... */ }
```

### Kafka Consumer 示例（Python）

```python
import json
from kafka import KafkaConsumer

consumer = KafkaConsumer(
    'netcap-events',
    bootstrap_servers=['kafka1:9092', 'kafka2:9092'],
    group_id='my-python-consumer',
    auto_offset_reset='latest',
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

pending_http = {}  # 暂存待配对的请求；生产环境应使用带 TTL 的存储

for msg in consumer:
    event = msg.value
    protocol = event.get('protocol', 'unknown')
    src_port = event.get('src_port', 0)
    dst_port = event.get('dst_port', 0)

    # 按协议分流
    if protocol == 'http' and event.get('http_detail'):
        detail = event['http_detail']
        uid = event.get('uid', '')
        direction = event.get('direction', 0)
        # 简易请求-响应配对（生产环境建议带 TTL 的字典或 Redis）
        if direction == 1:
            pending_http[uid] = event
        elif direction == 2:
            req = pending_http.pop(uid, None)
            if req:
                rtt_ms = (event['timestamp_ns'] - req['timestamp_ns']) / 1_000_000
                print(f"HTTP {req['http_detail'].get('method')} "
                      f"{req['http_detail'].get('url')} -> {detail.get('status_code')} "
                      f"rtt={rtt_ms:.1f}ms uid={uid}")
            else:
                print(f"HTTP orphan response status={detail.get('status_code')} uid={uid}")

    elif protocol == 'dns' and event.get('dns_detail'):
        detail = event['dns_detail']
        questions = detail.get('questions', [])
        for q in questions:
            print(f"DNS {q['type']} {q['name']}")

    elif protocol == 'tls' and event.get('tls_detail'):
        detail = event['tls_detail']
        print(f"TLS SNI={detail.get('server_name')} "
              f"JA3={event.get('metadata', {}).get('ja3', 'N/A')}")

    elif protocol in ('mysql', 'postgres', 'redis', 'mongodb') and event.get('db_detail'):
        detail = event['db_detail']
        print(f"DB [{detail['system']}] {detail.get('operation')}: "
              f"{detail.get('statement', '')[:100]}")
```

### 数据处理建议

**按 protocol 字段分流**

建议消费端根据 `protocol` 字段将事件路由到不同的处理管道：

- HTTP 事件 -> URL 分析、WAF 规则匹配、访问日志
- DNS 事件 -> 域名信誉检查、DNS 隧道检测
- TLS 事件 -> JA3 指纹库匹配、SNI 审计
- DB 事件 -> 慢查询告警、SQL 注入检测
- 邮件协议（SMTP/IMAP/POP3）-> 邮件审计

**按 uid 配对请求-响应（推荐）**

HTTP 事件在协议解析阶段会被打上 `uid` 标签，格式 `"<conn_id_hex>-<seq>"`：

- 同一对请求/响应共享同一 `uid`
- 同一 TCP 连接 keep-alive 上的第 N 次往返 seq=N（从 0 起算）
- 客户端请求和服务端响应方向各自维护独立计数器，靠 HTTP/1.x keep-alive 的 FIFO 顺序对齐
- TCP 连接关闭时 netcap 内部状态会被清理，5 元组复用不会污染 uid

消费侧建议：

1. 用 `uid` 做主键暂存请求事件，响应到达时弹出配对
2. 给暂存表设 TTL（建议 10-60 秒）防止孤儿请求堆积
3. `timestamp_ns` 差值即往返耗时（RTT）

**按 flow key 聚合分区**

Kafka 消息 Key 是 4 元组 FNV-1a 哈希，保证同一会话写入同一分区：

1. 同一 TCP 连接的请求和响应必然落在同一分区，无需跨分区 join
2. 单分区内消息按生产顺序到达，可用 `timestamp_ns` 做时序排序
3. 配对仍以 `uid` 为准（分区只是保证局部性，不直接给出配对关系）

---

## 9. 运维操作

### 优雅重启

Netcap 监听 `SIGINT` 和 `SIGTERM` 信号，收到信号后：

1. 停止接收新数据包
2. 等待流水线各阶段处理完缓冲区中的数据（最长 15 秒超时）
3. 刷新 Kafka 未发送的消息
4. 关闭所有 Kafka writer
5. 关闭 AF_PACKET 套接字

```bash
# 优雅停止
kill -SIGTERM $(pidof netcap)

# 或使用 systemd
sudo systemctl stop netcap
sudo systemctl restart netcap
```

### 动态调整

Netcap 当前不支持配置热加载。修改配置后需要重启进程：

```bash
# 1. 编辑配置
sudo vim /etc/netcap/netcap.yaml

# 2. 验证配置语法
python3 -c "import yaml; yaml.safe_load(open('/etc/netcap/netcap.yaml'))"

# 3. 优雅重启
sudo systemctl restart netcap

# 4. 检查启动日志
journalctl -u netcap -f --since "1 min ago"
```

### 日志级别说明

| 级别 | 说明 | 典型输出 |
|------|------|---------|
| `debug` | 详细调试信息，包括每包处理细节 | 协议探测匹配、BSON 解析步骤 |
| `info` | 正常运行信息 | 启动/停止、配置加载、阶段启动 |
| `warn` | 可恢复的异常 | 协议解析失败、Kafka 重试 |
| `error` | 不可恢复的错误 | 配置错误、Kafka 连接断开、抓包失败 |

日志格式默认为 JSON（结构化日志），输出到 stderr：

```json
{"time":"2024-04-03T10:00:00Z","level":"INFO","msg":"configuration loaded","path":"/etc/netcap/netcap.yaml"}
{"time":"2024-04-03T10:00:00Z","level":"INFO","msg":"capture started","interface":"eth0","queues":4}
{"time":"2024-04-03T10:00:00Z","level":"INFO","msg":"kafka producer started","workers":2,"topic":"netcap-events"}
{"time":"2024-04-03T10:00:00Z","level":"INFO","msg":"netcap running, press Ctrl+C to stop"}
```

### 常用排查命令

```bash
# 查看进程状态和资源使用
ps aux | grep netcap
top -p $(pidof netcap) -H    # 查看各线程 CPU 使用

# 查看网卡丢包统计（系统级）
ethtool -S eth0 | grep -i drop
cat /proc/net/dev | grep eth0

# 查看 AF_PACKET 套接字统计
cat /proc/net/packet

# 检查 metrics 端点
curl -s http://localhost:9090/metrics | grep -E "netcap_(packets_dropped|kafka_send_errors)"

# 验证 Kafka 连通性
kafkacat -b kafka1:9092 -L | grep netcap-events

# 实时查看 Kafka topic 中的事件
kafkacat -b kafka1:9092 -t netcap-events -C -c 5 | jq .

# 检查 BPF filter 语法
tcpdump -d "tcp port 80 or tcp port 443"

# 查看系统内核参数（影响收包性能）
sysctl net.core.rmem_max
sysctl net.core.rmem_default
sysctl net.core.netdev_max_backlog

# 优化系统内核参数
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.rmem_default=16777216
sudo sysctl -w net.core.netdev_max_backlog=10000
```

### Systemd 服务单元示例

```ini
[Unit]
Description=NetCap Traffic Capture Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/local/bin/tune-nic.sh eth1
ExecStart=/usr/local/bin/netcap --config /etc/netcap/netcap.yaml
Restart=on-failure
RestartSec=5
LimitMEMLOCK=infinity
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_BPF
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/netcap

[Install]
WantedBy=multi-user.target
```

> 注意：`ExecStartPre` 中的网卡名称（`eth1`）需要与实际镜像口一致。

---

## 10. FAQ

### 加密流量能解析吗？

Netcap 的 TLS 解析器只提取握手阶段的明文元数据，**不解密加密内容**。可提取的信息包括：

- **SNI**（Server Name Indication）：客户端要访问的目标域名
- **JA3/JA3S 指纹**：基于 ClientHello 参数计算的指纹哈希，用于识别客户端/服务器软件
- **ALPN 协议列表**：如 h2、http/1.1
- **证书链元数据**：（需开启 `tls.extract_certificates: true`）证书主题、签发者、有效期等

对于已建立的加密会话中的应用层数据，Netcap 无法解析。

### 支持 IPv6 吗？

支持。`ProtocolEvent` 中的 `src_ip` 和 `dst_ip` 字段使用 `[]byte` 类型，IPv4 为 4 字节，IPv6 为 16 字节。AF_PACKET 抓包同时捕获 IPv4 和 IPv6 流量。

### 如何只采集特定流量？

使用 BPF filter 配置项：

```yaml
capture:
  bpf_filter: "tcp port 80 or tcp port 443"
```

BPF filter 在内核层过滤，不匹配的包不会进入用户态，性能开销极低。

常用 BPF filter 示例：

```yaml
# 只捕获 HTTP 和 HTTPS
bpf_filter: "tcp port 80 or tcp port 443"

# 只捕获特定子网的流量
bpf_filter: "net 10.0.0.0/8"

# 只捕获 DNS
bpf_filter: "port 53"

# 排除 SSH 流量
bpf_filter: "not tcp port 22"

# 组合条件
bpf_filter: "tcp and (port 80 or port 443 or port 3306) and net 10.0.0.0/8"
```

### 如何扩展新协议？

实现 `protocol.Parser` 接口，包含 4 个方法：

```go
type Parser interface {
    // Name 返回协议名称（如 "myproto"）
    Name() string
    // Ports 返回该协议的知名端口列表
    Ports() []uint16
    // Probe 检查数据是否属于该协议，返回 0-100 的置信度
    Probe(data []byte, isFromClient bool) int
    // Parse 解析载荷，返回 ProtocolEvent 列表
    Parse(data []byte, meta ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error)
}
```

步骤：

1. 在 `internal/protocol/` 下创建新包（如 `internal/protocol/myproto/`）
2. 实现 `Parser` 接口
3. 在 `cmd/netcap/main.go` 的 `buildRegistry()` 中注册：
   ```go
   reg.Register(&protomyproto.Parser{})
   ```
4. 确保在 `unknown.Parser` 之前注册（unknown 是兜底解析器，优先级最低）

### 单机最大支持多少流量？

取决于硬件配置和流量特征：

| 流量规模 | CPU 需求 | 内存需求 | 网卡要求 |
|---------|---------|---------|---------|
| < 1 Gbps | 2-4 核 | 4 GB | 千兆/万兆均可 |
| 1-5 Gbps | 8 核 | 16 GB | 万兆网卡 + RSS 多队列 |
| 5-10 Gbps | 16+ 核 | 32 GB | 万兆网卡 + RSS + CPU 亲和 fanout |
| > 10 Gbps | 需要多实例 | - | 多网卡或硬件分流 |

影响因素：

- **协议复杂度**：HTTP 解析比 DNS 开销大，TLS JA3 计算有额外开销
- **TCP 连接数**：大量短连接增加重组引擎开销
- **Kafka 集群性能**：如果 Kafka 成为瓶颈，会背压整个管道

建议在目标环境中通过逐步增加 BPF filter 范围进行压测，观察 `packets_dropped_total` 指标确定实际承载能力。
