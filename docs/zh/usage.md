# WireMark 使用说明

## WireMark 是什么

WireMark 是双端主动式 **IPv4 包真实性与完整性网关**。

它的核心承诺只有一个：

```text
接收端接受的 IPv4 包 = 对端 WireMark 产生过、认证通过、内容未改的原始 IPv4 包
```

它不是 VPN，不是代理，不是可靠传输，不是抗阻断工具，不隐藏流量，也不做通用
路由/NAT。丢包、延迟、重复和乱序是链路行为或审计数据；WireMark 只保证被接受
的内容是真的。

## 主模式流程

`wiremark run` 默认使用 NFQUEUE：

```text
原始 IPv4 包进入 OUTPUT NFQUEUE
-> WireMark 规范化 checksum，记录 SHA256/时间/序号/五元组，计算 tag12
-> AES-256-GCM 封装成 WireMark UDP fragment
-> 原始包 DROP
-> 对端 INPUT NFQUEUE 收到 wrapper fragment
-> 重组、解密、验证 tag12
-> 用恢复出的原始 IPv4 包替换 wrapper
-> ACCEPT 放回内核
```

只要包被 NFQUEUE 规则覆盖，WireMark 不关心上层是 SSH、HTTPS、QUIC、DNS
还是自定义协议。

## 编译

安装依赖：

```sh
# Arch
sudo pacman -S --needed base-devel cmake openssl pkgconf libnetfilter_queue iptables

# Debian/Ubuntu
sudo apt install build-essential cmake pkg-config libssl-dev libnetfilter-queue-dev iptables

# Fedora
sudo dnf install gcc-c++ make cmake openssl-devel pkgconf-pkg-config libnetfilter_queue-devel iptables

# RHEL / Rocky / Alma
sudo dnf install gcc-c++ make cmake openssl-devel pkgconf-pkg-config libnetfilter_queue-devel iptables
# 如果找不到 libnetfilter_queue-devel，先启用该发行版对应的 EPEL/CRB 类仓库。
```

编译并自测：

```sh
cmake -S . -B build
cmake --build build -j
./build/wiremark selftest
```

检查主模式所需环境：

```sh
./build/wiremark doctor --peer-ip PEER_IP
```

主模式至少需要看到：

```text
built_with_nfqueue=yes
module_dir="/lib/modules/$(uname -r)" exists=yes
module_nfnetlink_queue=yes
```

如果 NFQUEUE 不可用，`wiremark run` 必须失败关闭，不会把 TUN 当成达标结果。

## 密钥和双端使用

两端使用同一个高熵密钥文件：

```sh
openssl rand -hex 32 > wiremark.key
chmod 600 wiremark.key
```

安全复制到另一端。不要提交进 git，不要放入公开日志或 issue。

### 1. 设置端点变量

在两台机器上都先执行这一组变量。`WIREMARK_PEER` 是当前机器看到的对端 IP。这是后面命令里唯一需要改的 IP。

```sh
export WIREMARK_PEER="replace-with-peer-ip"
export WIREMARK_PORT="47000"
export WIREMARK_QUEUE="70"
export WIREMARK_KEY="wiremark.key"
export WIREMARK_LOG_DIR="logs"
```

例子：

```text
本机：WIREMARK_PEER 填 VPS 公网 IP
VPS： WIREMARK_PEER 填本机公网 IP
```

`WIREMARK_PORT` 是 WireMark 自己的 UDP wrapper 端口，不是被保护应用的端口。

### 2. 放行 wrapper UDP 端口

安装 NFQUEUE 规则前，两端都要放行入站 UDP `$WIREMARK_PORT`。如果一端是 VPS，还要在云安全组里放行同一个 UDP 端口，并确认本机 firewalld、ufw、nftables 或 iptables 没有拦截。WireMark 不会替你修改云安全组。

主机防火墙例子：

```sh
# firewalld
sudo firewall-cmd --add-port="${WIREMARK_PORT}/udp" --permanent
sudo firewall-cmd --reload

# ufw
sudo ufw allow "${WIREMARK_PORT}/udp"
```

### 3. 先启动 WireMark，再安装 NFQUEUE 规则

两端各开一个终端 A，先启动 daemon：

```sh
./build/wiremark doctor --peer-ip "$WIREMARK_PEER"

sudo ./build/wiremark run \
  --queue-num "$WIREMARK_QUEUE" \
  --listen "0.0.0.0:$WIREMARK_PORT" \
  --peer "$WIREMARK_PEER:$WIREMARK_PORT" \
  --key-file "$WIREMARK_KEY" \
  --device-id wiremark-node \
  --log-dir "$WIREMARK_LOG_DIR" \
  --session nfq \
  --quarantine-dir "$WIREMARK_LOG_DIR/quarantine" \
  --invalid-policy drop \
  --replay-policy drop
```

不要在 daemon 启动前先加宽范围 NFQUEUE 规则。远程 SSH 机器上，宽范围规则会把本机 OUTPUT 流量送进队列；daemon 没准备好时可能中断你的 SSH 会话。

如果一端公网地址不固定，可以在理解固定 peer 路径后再实验 `--peer auto`。项目语义仍然是双端持钥认证：未知来源的内容必须通过解密和 tag 验证后才有资格进入恢复路径。

### 4. 在另一个终端安装 NFQUEUE 规则

daemon 已经运行后，在终端 B 添加规则：

```sh
sudo scripts/nfq-rules.sh add \
  --scope all \
  --peer-ip "$WIREMARK_PEER" \
  --wrapper-port "$WIREMARK_PORT" \
  --queue-num "$WIREMARK_QUEUE"
```

`--scope all` 会处理本机 OUTPUT 流量和入站 WireMark wrapper 流量，只适合专用实验机器。

窄范围实验，例如只保护一个 UDP/443 目标流：

```sh
export TARGET_PORT="443"
export TARGET_PROTO="udp"

sudo scripts/nfq-rules.sh add \
  --scope flow \
  --peer-ip "$WIREMARK_PEER" \
  --target-port "$TARGET_PORT" \
  --wrapper-port "$WIREMARK_PORT" \
  --proto "$TARGET_PROTO" \
  --queue-num "$WIREMARK_QUEUE"
```

`--target-port` 是被保护应用的端口。`--wrapper-port` 是 WireMark 自己的 UDP wrapper 端口。

### 5. 安全停止

停止 daemon 前先删除规则：

```sh
sudo scripts/nfq-rules.sh del \
  --scope all \
  --peer-ip "$WIREMARK_PEER" \
  --wrapper-port "$WIREMARK_PORT" \
  --queue-num "$WIREMARK_QUEUE"
```

窄范围模式删除时，使用和 add 完全相同的变量：

```sh
sudo scripts/nfq-rules.sh del \
  --scope flow \
  --peer-ip "$WIREMARK_PEER" \
  --target-port "$TARGET_PORT" \
  --wrapper-port "$WIREMARK_PORT" \
  --proto "$TARGET_PROTO" \
  --queue-num "$WIREMARK_QUEUE"
```

规则删除后，再用 Ctrl-C 停止 WireMark daemon。

### 6. 可选示例脚本

示例脚本使用同一组环境变量：

```sh
WIREMARK_PEER="$WIREMARK_PEER" WIREMARK_PORT="$WIREMARK_PORT" WIREMARK_QUEUE="$WIREMARK_QUEUE" examples/run-local.sh
WIREMARK_PEER="$WIREMARK_PEER" WIREMARK_PORT="$WIREMARK_PORT" WIREMARK_QUEUE="$WIREMARK_QUEUE" examples/run-remote.sh
```


`--peer auto` 是被动学习模式。使用 `auto` 的端点必须先收到并验证对端
wrapper，之后才能发送受保护的 outbound 包。不要让两端同时使用 `--peer auto`。

## 接收端策略和 quarantine 接口

接收端最终只按认证结果和同一 session 内的 WireMark 序号是否重复来给 verdict：

- `accepted`: tag12 正确，序号没见过，恢复原始 IPv4 包并放行。即使
  `packet_sha256` 以前出现过，也默认放行，只在日志里附加
  `same_sha_seen_before: true`。
- `verify_failed`: 认证失败，候选原包不可信，默认不恢复、不放行。
- `duplicate_sequence`: tag12 正确，但同一 WireMark sequence 已经出现过，
  属于重复/重放 wrapper，按 replay policy 处理。

原始包 SHA256 只是日志/审计指纹，字段名是 `packet_sha256`。WireMark 不用
SHA 判断包是否可信，也不把“内容重复”当成异常主类。内容重复只是内容重复，
不一定异常。

未 accepted 的 wrapper 会保存到 quarantine 目录：

```text
logs/quarantine/VERDICT/*.json
logs/quarantine/VERDICT/*.packet.bin
logs/quarantine/VERDICT/*.wrapper.bin
```

其中 JSON manifest 是给用户外接工具使用的稳定接口。WireMark 不处理这些包，
只保存候选原包、wrapper 和判定信息。外部工具可以监听目录、读取 manifest，
再自行决定如何分析或处置。

策略参数控制内核 verdict：

```sh
--invalid-policy drop|accept
--replay-policy drop|accept
```

默认都是 `drop`。`--invalid-policy accept` 是 unsafe/debug 模式，会关闭
WireMark 对认证失败包的核心完整性保证，可能把未认证候选内容放回内核；不能把
这种运行结果当作 WireMark 的安全承诺。`--replay-policy accept` 只影响认证通过
但 sequence 重复的 wrapper。

## 日志

日志写入 `--log-dir`：

```text
SESSION.packets.jsonl
SESSION.summary.json
```

日志的用途是核对核心性质：

```text
发送端记录：这个原始包被 WireMark 捕获、计算 tag12 并封装过
接收端记录：这个恢复包 tag12 认证通过，并按序号策略处理
```

可分析项目包括发送序号、接收序号、`packet_sha256`、认证失败、缺失、
重复 sequence、内容重复、乱序和延迟。丢包和阻断属于链路行为；它们不代表
内容被成功伪造或篡改。

`packet_decision` 事件包含：

```text
verdict, action, policy, origin, verify_ok, verify_kind,
duplicate_sequence, same_sha_seen_before, packet_sha256, quarantine_manifest
```

## 其他命令

- `wiremark interfaces`: 查看并分类本机网卡。
- `wiremark capture --iface auto`: 被动抓包，只记录，不保护通信内容。
- `wiremark probe`: 诊断实验入口，不属于主安全路径。
- `wiremark tun`: 显式非主路径 TUN 实验模式。它不是默认模式，也不是 `run` 的 fallback。

## 操作原则

- 只把 NFQUEUE 主路径的成功作为 WireMark 主目标达成。
- 不把 TUN、capture 或普通连通性测试当成主模式成功。
- 不声称 WireMark 防丢包、防阻断、防流量分析或提供 VPN 功能。
- 只声称：被接收端接受的原始 IPv4 包，是持钥对端产生过且内容未被修改的包。
