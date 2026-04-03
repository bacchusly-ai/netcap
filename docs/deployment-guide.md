# NetCap 部署手册

## 1. 概述

NetCap 是一款高性能网络流量采集与解析代理，基于 Linux AF_PACKET 实现零拷贝抓包，经过多级流水线（抓包 -> 解码 -> TCP 重组 -> 协议解析）处理后，将结构化的协议事件（HTTP、DNS、TLS、MySQL、PostgreSQL、Redis、MongoDB、SMTP、FTP、IMAP、POP3、MQTT、WebSocket、SSH 等）以 JSON 格式写入 Kafka，供下游安全分析、流量审计及 APM 系统消费。架构采用单二进制部署，通过 Prometheus 暴露运行指标，适用于数据中心与云环境的旁路镜像抓包场景。

---

## 2. 环境要求

### 2.1 硬件要求

| 项目 | 最低要求 | 推荐配置 |
|------|---------|---------|
| CPU | 4 核 | 8 核及以上（核数越多，decode worker 与 fanout 并行度越高） |
| 内存 | 4 GB | 16 GB 及以上（TCP 重组缓冲区与 Kafka 批量写入均消耗内存） |
| 网卡 | 千兆网卡 | 万兆（10GbE）及以上，支持 RSS 多队列 |
| 磁盘 | 无特殊要求 | SSD（仅用于日志输出到文件时） |

**交换机镜像口配置：**

- 在交换机上配置 SPAN（端口镜像）或 RSPAN（远程端口镜像），将目标流量镜像到 NetCap 所在服务器的监听网卡。
- 镜像口应为独立物理端口，不承载业务流量。
- 若镜像流量超过网卡带宽，需配置镜像过滤或使用更高速率网卡。
- 建议在交换机侧开启截断镜像（truncate），仅镜像前 N 字节以降低带宽开销（配合 `snap_length` 使用）。

### 2.2 操作系统兼容性

| 类别 | 发行版 |
|------|-------|
| 国产操作系统 | 麒麟 Kylin V10、统信 UOS V20/V21、Deepin V20+ |
| 主流 Linux | CentOS 7/8/9、RHEL 7/8/9、Ubuntu 18.04/20.04/22.04/24.04、Debian 10/11/12、openEuler 22.03/24.03 |

### 2.3 CPU 架构支持

NetCap 通过交叉编译支持以下架构（对应 Makefile 中的 `PLATFORMS`）：

| 架构 | GOARCH | 代表处理器 |
|------|--------|-----------|
| x86_64 | `amd64` | Intel Xeon、AMD EPYC、海光 Hygon、兆芯 Zhaoxin |
| ARM64 | `arm64` | 华为鲲鹏 Kunpeng 920、飞腾 FT-2000/S2500 |
| LoongArch | `loong64` | 龙芯 Loongson 3A5000/3A6000 |

### 2.4 内核版本要求

- **最低要求：** Linux 3.14+（AF_PACKET v3、`PACKET_FANOUT` 支持）
- **推荐版本：** Linux 4.18+（BPF 增强、`CAP_BPF` capability 支持）
- 需确保内核编译时启用了 `CONFIG_PACKET` 和 `CONFIG_PACKET_DIAG`

### 2.5 依赖服务

| 服务 | 版本要求 | 说明 |
|------|---------|------|
| Apache Kafka | 2.8+ | 事件输出目标，需提前部署并创建 Topic |

---

## 3. 编译构建

### 3.1 编译环境要求

- Go 1.22 或更高版本
- Git
- Make

### 3.2 从源码编译

**单架构编译（当前平台）：**

```bash
git clone https://github.com/netcap/netcap.git
cd netcap
make build
```

编译产物位于 `bin/netcap`。

**多架构交叉编译：**

```bash
make build-all
```

将分别生成以下二进制文件：

| 文件 | 目标架构 |
|------|---------|
| `bin/netcap-amd64` | x86_64 |
| `bin/netcap-arm64` | ARM64 |
| `bin/netcap-loong64` | LoongArch |

**代码检查与测试：**

```bash
make vet      # 静态检查
make test     # 运行单元测试
```

### 3.3 Docker 镜像构建

项目提供多阶段 Dockerfile（`deployments/Dockerfile`），构建过程如下：

```bash
# 构建镜像（默认 amd64）
docker build -f deployments/Dockerfile -t netcap:latest .

# 多架构构建（需要 docker buildx）
docker buildx build --platform linux/amd64,linux/arm64 \
  -f deployments/Dockerfile -t netcap:latest --push .
```

镜像说明：
- **构建阶段**：基于 `golang:1.22`，CGO 禁用，静态编译
- **运行阶段**：基于 `ubuntu:22.04`，仅安装 `ca-certificates`、`ethtool`、`iproute2`
- 内含 `tune-nic.sh` 网卡调优脚本

---

## 4. 安装部署

### 4.1 二进制部署

**步骤 1：复制文件**

```bash
# 复制二进制文件
sudo cp bin/netcap /usr/local/bin/netcap
sudo chmod +x /usr/local/bin/netcap

# 复制网卡调优脚本
sudo cp scripts/tune-nic.sh /usr/local/bin/tune-nic.sh
sudo chmod +x /usr/local/bin/tune-nic.sh
```

**步骤 2：设置 Linux Capabilities**

```bash
sudo setcap 'cap_net_raw,cap_net_admin,cap_bpf+ep' /usr/local/bin/netcap
```

> 设置 capabilities 后无需以 root 运行即可抓包。

**步骤 3：创建配置目录**

```bash
sudo mkdir -p /etc/netcap
sudo cp configs/netcap.yaml /etc/netcap/netcap.yaml
```

根据实际环境编辑 `/etc/netcap/netcap.yaml`，至少修改以下配置项：

```yaml
capture:
  interface: "eth1"       # 改为实际的镜像口网卡名

kafka:
  brokers:
    - "kafka1:9092"       # 改为实际的 Kafka 地址
    - "kafka2:9092"
```

### 4.2 systemd 服务配置

**安装 service 文件：**

```bash
sudo cp deployments/systemd/netcap.service /etc/systemd/system/netcap.service
sudo systemctl daemon-reload
```

**服务文件内容说明（`netcap.service`）：**

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

> 注意：`ExecStartPre` 中的网卡名称需要与实际镜像口一致。

**管理服务：**

```bash
# 启动
sudo systemctl start netcap

# 开机自启
sudo systemctl enable netcap

# 查看状态
sudo systemctl status netcap

# 查看日志
sudo journalctl -u netcap -f
```

### 4.3 Docker 部署

```bash
docker run -d \
  --name netcap \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --cap-add BPF \
  -v /etc/netcap/netcap.yaml:/etc/netcap/netcap.yaml:ro \
  netcap:latest \
  --config /etc/netcap/netcap.yaml
```

关键参数说明：

| 参数 | 说明 |
|------|------|
| `--network host` | 使用宿主机网络命名空间，直接访问物理网卡 |
| `--cap-add NET_RAW` | 允许原始套接字抓包 |
| `--cap-add NET_ADMIN` | 允许网卡配置操作（ethtool 调优） |
| `--cap-add BPF` | 允许挂载 BPF 过滤器 |

---

## 5. 网卡调优

### 5.1 tune-nic.sh 脚本说明

项目自带 `scripts/tune-nic.sh` 脚本，systemd 服务在启动前会自动执行。脚本完成以下调优操作：

| 操作 | 命令 | 说明 |
|------|------|------|
| 增大 Ring Buffer | `ethtool -G <iface> rx 4096 tx 4096` | 增大网卡收发环形缓冲区，减少内核丢包 |
| 设置 RSS 队列数 | `ethtool -L <iface> combined <nproc>` | RSS 队列数匹配 CPU 核数，实现多核并行收包 |
| 关闭流控 | `ethtool -A <iface> rx off tx off` | 禁用 Pause Frame，避免镜像口反压 |
| 关闭硬件 Offload | `ethtool -K <iface> gro off lro off tso off gso off` | 关闭聚合/分段卸载，确保内核看到完整原始报文 |
| 增大 Socket 缓冲区 | `sysctl -w net.core.rmem_max=134217728` | Socket 接收缓冲区上限 128 MiB |
| 增大默认缓冲区 | `sysctl -w net.core.rmem_default=16777216` | Socket 默认接收缓冲区 16 MiB |
| 增大 Backlog | `sysctl -w net.core.netdev_max_backlog=50000` | 网卡接收队列积压上限 |

用法：

```bash
sudo /usr/local/bin/tune-nic.sh eth1
```

### 5.2 手动调优步骤

如果需要更细粒度的调优，可手动执行以下操作：

**Ring Buffer 调优：**

```bash
# 查看当前 ring buffer 大小
ethtool -g eth1

# 设置为最大值
sudo ethtool -G eth1 rx 4096 tx 4096
```

**RSS 多队列配置：**

```bash
# 查看当前队列数
ethtool -l eth1

# 设置队列数与 CPU 核数一致
sudo ethtool -L eth1 combined $(nproc)
```

**IRQ Affinity 绑定：**

```bash
# 查看网卡中断号
grep eth1 /proc/interrupts

# 手动设置每个队列中断绑定到不同 CPU 核
# 以中断号 50 绑定到 CPU 0 为例：
echo 1 | sudo tee /proc/irq/50/smp_affinity_list

# 或使用 irqbalance 服务自动分配
sudo systemctl start irqbalance
```

**关闭 Offload 功能：**

```bash
sudo ethtool -K eth1 gro off lro off tso off gso off rx-vlan-offload off tx-vlan-offload off
```

**sysctl 内核参数持久化：**

```bash
cat <<EOF | sudo tee /etc/sysctl.d/99-netcap.conf
net.core.rmem_max = 134217728
net.core.rmem_default = 16777216
net.core.netdev_max_backlog = 50000
net.core.optmem_max = 16777216
EOF

sudo sysctl --system
```

### 5.3 交换机镜像口配置建议

- 镜像口应为独立端口，不承载业务流量
- 配置双向镜像（ingress + egress）以获取完整会话
- 若目标流量超过镜像口带宽，配置基于 VLAN 或 ACL 的过滤规则
- 使用 TAP 设备（分光器）可作为交换机镜像的替代方案，对生产网络无影响
- 汇聚多条镜像链路时，建议使用 Network Packet Broker (NPB) 设备进行流量整合与去重

---

## 6. 配置详解

配置文件路径：`/etc/netcap/netcap.yaml`

### 6.1 capture -- 抓包配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `capture.interface` | string | `"eth0"` | 抓包网卡接口名称 |
| `capture.mode` | string | `"afpacket"` | 抓包后端，可选 `"afpacket"` 或 `"pcap"` |
| `capture.num_queues` | int | `1` | AF_PACKET 接收队列数量 |
| `capture.buffer_size` | int | `4194304` | 每个队列的 Ring Buffer 大小（字节），默认 4 MiB |
| `capture.snap_length` | int | `9000` | 每包最大捕获字节数（支持 Jumbo Frame） |
| `capture.bpf_filter` | string | `""` | BPF 过滤表达式，空表示捕获全部流量 |
| `capture.fanout.enabled` | bool | `false` | 是否开启 AF_PACKET fanout 多线程抓包 |
| `capture.fanout.group_id` | int | `1` | Fanout 组 ID |
| `capture.fanout.type` | string | `"hash"` | Fanout 类型：`"hash"`、`"lb"`、`"cpu"`、`"rollover"` |
| `capture.fanout.size` | int | `4` | Fanout socket 数量 |

### 6.2 decode -- 解码配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `decode.workers` | int | `4` | 并行解码 worker 数量 |
| `decode.channel_buffer` | int | `4096` | 抓包与解码之间的 channel 缓冲区大小 |

### 6.3 reassembly -- TCP 重组配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `reassembly.max_buffered_pages_per_conn` | int | `256` | 单个 TCP 连接最大缓冲页数 |
| `reassembly.max_buffered_pages_total` | int | `65536` | 全局最大缓冲页数 |
| `reassembly.connection_timeout` | duration | `"2m"` | 连接空闲超时后刷出 |
| `reassembly.max_connection_age` | duration | `"10m"` | 连接最大存活时间 |
| `reassembly.flush_interval` | duration | `"30s"` | 定期刷出过期连接的周期 |

### 6.4 protocols -- 协议解析配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `protocols.enabled` | []string | `["http", "dns", "tls"]` | 启用的应用层协议解析器列表 |
| `protocols.http.max_body_capture` | int | `65536` | HTTP Body 最大捕获字节数，0 表示不捕获 |
| `protocols.http.capture_headers` | bool | `true` | 是否捕获 HTTP 请求/响应头 |
| `protocols.tls.extract_ja3` | bool | `true` | 是否提取 JA3/JA3S 指纹 |
| `protocols.tls.extract_certificates` | bool | `false` | 是否提取证书链（开销较大） |
| `protocols.db.max_query_length` | int | `4096` | 数据库协议（MySQL/PostgreSQL/Redis/MongoDB）SQL 查询最大捕获长度 |

支持的全部协议列表：HTTP、DNS、TLS、MySQL、PostgreSQL、Redis、MongoDB、SMTP、FTP、IMAP、POP3、MQTT、WebSocket、SSH。

### 6.5 kafka -- Kafka 输出配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `kafka.brokers` | []string | `["localhost:9092"]` | Kafka Broker 地址列表 |
| `kafka.topic` | string | `"netcap-events"` | 写入的 Kafka Topic 名称 |
| `kafka.batch_size` | int | `100` | 批量发送的消息条数 |
| `kafka.batch_timeout` | duration | `"500ms"` | 批量发送超时（未满 batch_size 也发送） |
| `kafka.compression` | string | `"lz4"` | 压缩算法：`"lz4"`、`"snappy"`、`"gzip"`、`""` |
| `kafka.required_acks` | int | `1` | ACK 策略：`-1` 全部副本确认、`0` 不等待、`1` Leader 确认 |
| `kafka.num_workers` | int | `2` | 并行 Kafka 写入 goroutine 数量 |
| `kafka.max_message_bytes` | int | `1048576` | 单条 Kafka 消息最大字节数，默认 1 MiB |

### 6.6 metrics -- 监控指标配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `metrics.enabled` | bool | `true` | 是否启用 Prometheus 指标端点 |
| `metrics.listen` | string | `":9090"` | 指标 HTTP 监听地址 |
| `metrics.path` | string | `"/metrics"` | 指标暴露路径 |

### 6.7 logging -- 日志配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `logging.level` | string | `"info"` | 日志级别：`"debug"`、`"info"`、`"warn"`、`"error"` |
| `logging.format` | string | `"json"` | 日志格式：`"json"` 或 `"text"` |
| `logging.output` | string | `"stderr"` | 日志输出：`"stderr"`、`"stdout"` 或文件路径 |

### 6.8 runtime -- 运行时配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `runtime.gomaxprocs` | int | `0` | GOMAXPROCS 覆盖值，0 表示使用 Go 默认值（等于 CPU 核数） |

---

## 7. Kafka 对接

### 7.1 Topic 创建建议

```bash
kafka-topics.sh --bootstrap-server kafka1:9092 \
  --create \
  --topic netcap-events \
  --partitions 16 \
  --replication-factor 3 \
  --config retention.ms=604800000 \
  --config retention.bytes=-1 \
  --config max.message.bytes=1048576 \
  --config compression.type=lz4
```

| 参数 | 建议值 | 说明 |
|------|-------|------|
| 分区数 | 16（按流量规模调整） | 建议与 NetCap 写入 worker 数量的倍数对齐 |
| 副本数 | 3 | 生产环境至少 3 副本保证高可用 |
| retention.ms | 604800000 (7天) | 按存储容量和下游消费速度调整 |
| max.message.bytes | 1048576 | 与 NetCap 配置的 `kafka.max_message_bytes` 一致 |
| compression.type | lz4 | 与 NetCap 配置的 `kafka.compression` 一致 |

### 7.2 消息格式说明

当前版本使用 **JSON** 格式序列化协议事件（`JSONSerializer`），后续计划支持 **Protobuf** 格式以降低序列化开销和消息体积。

消息结构示例（HTTP 事件）：

```json
{
  "timestamp": "2026-04-03T10:30:00.123456Z",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dst_ip": "10.0.0.1",
  "dst_port": 80,
  "protocol": "http",
  "direction": "request",
  "http": {
    "method": "GET",
    "uri": "/api/v1/users",
    "host": "example.com",
    "headers": {"User-Agent": "curl/7.68.0"},
    "status_code": 200,
    "body_truncated": false
  }
}
```

### 7.3 分区策略

NetCap 采用 **Flow 五元组 Hash** 分区策略，确保同一会话（src_ip, dst_ip, src_port, dst_port, protocol）的所有事件写入同一分区，保证：

- 同一 TCP 连接的请求和响应在同一分区内有序
- 下游消费者可按分区独立处理完整的会话流
- 负载在各分区间均匀分布

---

## 8. 监控与告警

### 8.1 Prometheus 指标列表

NetCap 在 `metrics.listen` 配置的地址（默认 `:9090/metrics`）暴露以下指标：

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| `netcap_packets_captured_total` | Counter | `queue` | 各队列捕获的数据包总数 |
| `netcap_packets_dropped_total` | Counter | `queue`, `reason` | 各队列丢弃的数据包总数 |
| `netcap_capture_bytes_total` | Counter | `queue` | 各队列捕获的字节总数 |
| `netcap_decode_latency_seconds` | Histogram | -- | 单包解码延迟（秒），桶范围 1us ~ 1s |
| `netcap_active_streams` | Gauge | -- | 当前活跃的 TCP 重组流数量 |
| `netcap_reassembly_pages_used` | Gauge | -- | 重组引擎当前使用的页缓冲区数量 |
| `netcap_protocol_events_total` | Counter | `protocol`, `direction` | 各协议解析事件总数 |
| `netcap_parse_errors_total` | Counter | `protocol`, `error_type` | 各协议解析错误总数 |
| `netcap_kafka_messages_sent_total` | Counter | -- | 成功发送到 Kafka 的消息总数 |
| `netcap_kafka_send_errors_total` | Counter | -- | Kafka 发送失败总数 |
| `netcap_kafka_batch_latency_seconds` | Histogram | -- | Kafka 批量写入延迟（秒） |
| `netcap_channel_utilization_ratio` | Gauge | `stage` | 各流水线阶段 channel 利用率（0~1） |

**Prometheus 抓取配置示例：**

```yaml
scrape_configs:
  - job_name: 'netcap'
    static_configs:
      - targets: ['netcap-host:9090']
    scrape_interval: 15s
```

### 8.2 Grafana 面板建议

建议创建以下 Grafana Dashboard 面板：

| 面板 | 查询示例 | 说明 |
|------|---------|------|
| 抓包速率 | `rate(netcap_packets_captured_total[1m])` | 每秒抓包数 |
| 抓包带宽 | `rate(netcap_capture_bytes_total[1m]) * 8` | 捕获流量速率（bps） |
| 丢包率 | `rate(netcap_packets_dropped_total[1m]) / rate(netcap_packets_captured_total[1m])` | 丢包百分比 |
| 解码延迟 P99 | `histogram_quantile(0.99, rate(netcap_decode_latency_seconds_bucket[5m]))` | 解码延迟 P99 |
| 活跃 TCP 流 | `netcap_active_streams` | 实时 TCP 重组流数 |
| 重组缓冲使用率 | `netcap_reassembly_pages_used / 65536` | 页缓冲区使用百分比 |
| 协议事件速率 | `rate(netcap_protocol_events_total[1m])` | 按协议分组的事件速率 |
| Kafka 写入速率 | `rate(netcap_kafka_messages_sent_total[1m])` | Kafka 每秒写入消息数 |
| Kafka 写入延迟 P99 | `histogram_quantile(0.99, rate(netcap_kafka_batch_latency_seconds_bucket[5m]))` | Kafka 批写延迟 P99 |
| Channel 利用率 | `netcap_channel_utilization_ratio` | 各阶段 channel 填充比 |

### 8.3 关键告警规则

```yaml
groups:
  - name: netcap
    rules:
      - alert: NetCapHighDropRate
        expr: rate(netcap_packets_dropped_total[5m]) / rate(netcap_packets_captured_total[5m]) > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "NetCap 丢包率超过 1%"
          description: "丢包率 {{ $value | humanizePercentage }}，请检查 Ring Buffer 和 CPU 负载"

      - alert: NetCapReassemblyBufferHigh
        expr: netcap_reassembly_pages_used / 65536 > 0.8
        for: 3m
        labels:
          severity: warning
        annotations:
          summary: "TCP 重组缓冲区使用率超过 80%"
          description: "当前使用 {{ $value | humanizePercentage }}，可能导致连接被强制刷出"

      - alert: NetCapKafkaSendErrors
        expr: rate(netcap_kafka_send_errors_total[5m]) > 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "NetCap Kafka 写入持续失败"
          description: "过去 5 分钟 Kafka 发送错误率 {{ $value }}/s"

      - alert: NetCapChannelBackpressure
        expr: netcap_channel_utilization_ratio > 0.9
        for: 3m
        labels:
          severity: warning
        annotations:
          summary: "流水线 channel 接近满载"
          description: "阶段 {{ $labels.stage }} 利用率 {{ $value | humanizePercentage }}"

      - alert: NetCapDown
        expr: up{job="netcap"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "NetCap 进程不可达"
          description: "Prometheus 无法抓取 NetCap 指标端点"
```

---

## 9. 安全加固

### 9.1 Linux Capabilities 最小权限

NetCap 仅需以下三个 capabilities 即可完成抓包，无需以 root 运行：

| Capability | 用途 |
|-----------|------|
| `CAP_NET_RAW` | 创建原始套接字（AF_PACKET） |
| `CAP_NET_ADMIN` | 网卡配置操作（ethtool 调优、BPF 挂载） |
| `CAP_BPF` | 加载 BPF 过滤程序（内核 4.18+） |

设置方式：

```bash
# 为二进制文件设置 capabilities
sudo setcap 'cap_net_raw,cap_net_admin,cap_bpf+ep' /usr/local/bin/netcap

# 验证
getcap /usr/local/bin/netcap
```

> 注意：如果内核版本低于 4.18，不支持 `CAP_BPF`，需使用 `CAP_SYS_ADMIN` 替代或以 root 运行。

### 9.2 systemd 安全选项说明

NetCap 的 systemd service 文件已启用以下安全加固选项：

| 选项 | 值 | 说明 |
|------|---|------|
| `AmbientCapabilities` | `CAP_NET_RAW CAP_NET_ADMIN CAP_BPF` | 仅授予必要的 capabilities |
| `NoNewPrivileges` | `true` | 禁止进程及其子进程获取新的特权 |
| `ProtectSystem` | `strict` | 文件系统以只读方式挂载（除 /dev、/proc、/sys） |
| `ProtectHome` | `true` | 禁止访问用户主目录 |
| `ReadOnlyPaths` | `/etc/netcap` | 配置目录只读 |
| `LimitMEMLOCK` | `infinity` | 允许无限锁定内存（AF_PACKET Ring Buffer 需要） |
| `LimitNOFILE` | `1048576` | 文件描述符上限（高并发连接需要） |

可进一步加固的选项：

```ini
# 在 [Service] 段追加
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
SystemCallFilter=@system-service @network-io @io-event
```

### 9.3 网络隔离建议

- **管理网与抓包网分离**：NetCap 服务器应配备至少两块网卡，一块用于镜像流量接收（无 IP 地址），一块用于管理通信（Kafka、Prometheus 等）
- **防火墙规则**：管理网卡仅放行必要端口
  - 出站：Kafka Broker 端口（默认 9092）
  - 入站：Prometheus 指标端口（默认 9090）
  - 入站：SSH 管理端口（限制源 IP）
- **镜像口网卡不配 IP**：抓包网卡不分配 IP 地址，仅工作在混杂模式，防止被外部访问
- **VLAN 隔离**：管理网络与业务网络使用不同 VLAN
- **Kafka 通信加密**：生产环境建议启用 Kafka TLS 加密和 SASL 认证

---

## 10. 常见问题排查

### 10.1 启动失败

**权限不足**

```
错误信息：failed to start capture: operation not permitted
```

原因：缺少 `CAP_NET_RAW` 等 capabilities。

解决：

```bash
# 方式一：设置 capabilities
sudo setcap 'cap_net_raw,cap_net_admin,cap_bpf+ep' /usr/local/bin/netcap

# 方式二：以 root 运行（不推荐）
sudo /usr/local/bin/netcap --config /etc/netcap/netcap.yaml
```

**网卡不存在**

```
错误信息：failed to start capture: no such device: eth0
```

原因：配置中的 `capture.interface` 指定的网卡名不存在。

解决：

```bash
# 查看可用网卡
ip link show

# 修改配置为正确的网卡名
# 注意不同发行版网卡命名规则可能不同（ens33、enp0s3 等）
```

**Kafka 连接失败**

```
错误信息：kafka: client has run out of available brokers to talk to
```

原因：无法连接 Kafka Broker。

解决：

```bash
# 检查网络连通性
telnet kafka1 9092

# 检查 Kafka 服务状态
kafka-broker-api-versions.sh --bootstrap-server kafka1:9092

# 确认防火墙规则
sudo iptables -L -n | grep 9092
```

### 10.2 运行时问题

**丢包率高**

排查步骤：

1. 检查系统级丢包：

```bash
# 查看网卡统计
ethtool -S eth1 | grep -i drop

# 查看内核丢包
cat /proc/net/softnet_stat
```

2. 检查 NetCap 指标：

```bash
curl -s http://localhost:9090/metrics | grep netcap_packets_dropped
```

3. 调优措施：
   - 增大 `capture.buffer_size`（如 16 MiB、32 MiB）
   - 开启 `capture.fanout` 多线程抓包
   - 运行 `tune-nic.sh` 确保 Ring Buffer 和 RSS 已调优
   - 增加 `decode.workers` 数量
   - 检查 CPU 是否瓶颈，使用 `top` / `htop` 观察

**内存持续增长**

排查步骤：

1. 检查 TCP 重组缓冲区：

```bash
curl -s http://localhost:9090/metrics | grep netcap_reassembly_pages_used
```

2. 检查 channel 积压：

```bash
curl -s http://localhost:9090/metrics | grep netcap_channel_utilization
```

3. 调优措施：
   - 降低 `reassembly.max_buffered_pages_total`
   - 缩短 `reassembly.connection_timeout` 和 `reassembly.max_connection_age`
   - 检查下游 Kafka 是否写入缓慢导致 channel 积压

**Kafka 写入慢**

排查步骤：

1. 检查 Kafka 批写延迟：

```bash
curl -s http://localhost:9090/metrics | grep netcap_kafka_batch_latency
```

2. 检查 Kafka 集群状态：

```bash
kafka-consumer-groups.sh --bootstrap-server kafka1:9092 --describe --group netcap
```

3. 调优措施：
   - 增加 `kafka.num_workers`
   - 增大 `kafka.batch_size` 和 `kafka.batch_timeout`
   - 检查 Kafka Broker 磁盘 I/O 和网络带宽
   - 将 `kafka.required_acks` 设为 `1`（Leader 确认）以降低延迟

### 10.3 日志说明

NetCap 默认以 JSON 格式输出结构化日志到 stderr，systemd 环境下可通过 journalctl 查看：

```bash
# 实时查看日志
sudo journalctl -u netcap -f

# 查看最近 100 行
sudo journalctl -u netcap -n 100

# 按时间范围查看
sudo journalctl -u netcap --since "2026-04-03 10:00:00" --until "2026-04-03 11:00:00"

# 按级别过滤（JSON 格式下需 jq 辅助）
sudo journalctl -u netcap -o cat | jq 'select(.level == "ERROR")'
```

日志级别说明：

| 级别 | 说明 |
|------|------|
| `debug` | 详细调试信息，包括每包处理细节，仅用于开发调试 |
| `info` | 常规运行信息，如启动、配置加载、阶段初始化 |
| `warn` | 警告信息，如网卡调优失败、临时性 Kafka 重试 |
| `error` | 错误信息，如抓包失败、Kafka 持续不可达 |

如需将日志写入文件而非 stderr，修改配置：

```yaml
logging:
  output: "/var/log/netcap/netcap.log"
```

并确保目录存在且进程有写入权限。
