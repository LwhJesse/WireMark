# WireMark 技术设计

## 项目边界

WireMark 是一个双端主动式 **IPv4 包真实性与完整性网关**。

它只做一件事：

> 接收端每一个被放回内核的 IPv4 包，都必须是对端 WireMark 捕获过、
> 认证通过、内容未被中间网络修改的原始 IPv4 包。

等价地说：

```text
accepted IPv4 packet == authenticated original IPv4 packet from peer
```

WireMark 不做 VPN，不做代理，不做可靠传输，不做抗阻断，不做隐蔽流量，
不做通用路由/NAT，也不承诺所有包一定送达。丢包、延迟、限速、断流、重复、
乱序都是链路行为或审计数据，不是 WireMark 要“修复”的对象。

## 威胁模型

WireMark 防的是中间网络对内容的无认证修改、伪造和非法插入。

攻击者不知道 WireMark 密钥时，不能构造一个会被接收端接受的“新内容”，
也不能把你发出的内容改成另一个内容后让接收端无感接受。

攻击者仍然可以：

- 丢弃包；
- 延迟包；
- 限速或阻断流量；
- 复制已看到的 wrapper；
- 重复投递旧的合法 wrapper；
- 观察两端 IP、端口、大小、方向和时序。

这些能力不破坏 WireMark 的核心承诺：**只要接收端接受了一个包，它就是持钥
对端产生过且内容未被修改的原始 IPv4 包。**

如果应用需要 exactly-once 语义或业务级去重，应在 WireMark 之上实现。WireMark
层的 sequence 和日志可以帮助观察丢包、重复和乱序，但项目核心不是可靠交付。

## 主后端

默认 `wiremark run` 使用 NFQUEUE，不使用 TUN。TUN 只保留为显式
`wiremark tun` 非主路径实验后端，不是默认路径，也不是失败回退路径。

普通机器/VPS 的可落地层级是：

```text
SmartNIC/DPU/FPGA 固件层: 当前项目不依赖
Linux 内核 verdict 路径: WireMark 主路径
TUN/应用代理层: 更高层，只能显式实验使用
```

主路径选择 NFQUEUE verdict：

```text
OUTPUT NFQUEUE: 拦截原始 IPv4 包 -> 认证封装 -> DROP 原包
INPUT  NFQUEUE: 拦截 wrapper -> 验证解封 -> 替换成原始 IPv4 包 -> ACCEPT
```

如果 NFQUEUE 不可用，程序必须失败关闭，不能自动降级成 TUN 或被动抓包。

## 数据路径

发送端：

```text
原始 IPv4 包进入 OUTPUT NFQUEUE
-> 规范化 checksum
-> 记录 metadata 和 SHA256
-> 计算带密钥 tag12
-> 放入 compact plaintext
-> AES-256-GCM 加密认证
-> UDP wrapper 应用层分片发送
-> 原始包 NF_DROP
```

接收端：

```text
wrapper fragment 进入 INPUT NFQUEUE
-> fragment 重组
-> AES-256-GCM 解密认证
-> 校验 tag12
-> 判断认证结果和同一 session 内 sequence 是否重复
-> 恢复原始 IPv4 包
-> 规范化 checksum
-> 用恢复包替换当前 queued wrapper
-> NF_ACCEPT
```

验证失败、重组失败、格式错误、密钥错误或 tag 错误时，默认不恢复原始包。
接收端策略只处理认证失败和 sequence 重复。SHA256 只作为日志/审计指纹，不参与可信判定。
非 accepted wrapper 会保存到 quarantine 接口，供用户外接工具处理。

## Compact plaintext

每个 encrypted plaintext 当前承载一个原始包，格式保留 batch 能力：

```text
base_sequence varint
packet_count varint

repeat:
  original_len varint
  tag12 12 bytes
  original_packet original_len bytes
```

`tag12` 是带密钥认证标签：

```text
tag12 = HMAC-SHA256(integrity_key, seq || original_packet)[0:12]
```

这里的目标不是普通哈希去重，而是让非持钥者无法构造可通过验证的原始包内容。

## 外层 WireMark frame

compact plaintext 进入 WireMark frame：

```text
magic/version/type/flags
session_id
frame_sequence
nonce
ciphertext_length
AES-256-GCM ciphertext+tag
```

frame header 作为 AES-GCM AAD 被认证，payload 被加密。共享密钥认证的是“两端
都持有同一密钥”的事实；它不是第三方不可抵赖签名。

## UDP wrapper 分片

NFQUEUE 主后端通过 UDP 发送 wrapper。为避免依赖外层 IP 分片，WireMark 在
应用层分片：

```text
WMF1
frame_id
fragment_index
fragment_count
fragment_len
fragment_payload
```

接收端对非最后到齐的 fragment 返回 DROP/等待；只有重组出完整 WireMark frame
并验证成功后，才用恢复的原始 IPv4 包替换当前 queued wrapper。

## Checksum 处理

WireMark 在计算 tag 前规范化 IPv4 header checksum，并对未分片 TCP/UDP/ICMP
包重新计算 L4 checksum。接收端恢复前再次规范化，避免把 checksum-offload 的
中间状态当成普通字节注入对端内核。

## 规则作用域

`scripts/nfq-rules.sh` 支持两种作用域：

- `--scope all`: 排队本机 OUTPUT 链上的 IPv4 包和 inbound wrapper，适合专用
  实验机器。它不是通用 VPN 或透明代理承诺。
- `--scope flow`: 只排队指定 peer/protocol/port 的流量和 inbound wrapper，适合
  小范围验证。

如果 WireMark 自己发出的 outbound wrapper 被 OUTPUT 规则再次排队，程序会识别
它是 wrapper 并直接 ACCEPT，避免递归封装。

## 日志语义

日志用于审计 WireMark 的核心性质：发送端产生了哪些原始包，接收端接受了哪些
验证通过的恢复包。

发送端记录序号、发送时间、原始包 SHA256、五元组和长度。
接收端记录接收时间、验证结果、恢复包 SHA256、五元组和长度。

日志可以用于分析：

- 哪些序号被发送；
- 哪些序号被验证并接受；
- 哪些序号缺失；
- 是否存在验证失败、重复、乱序或异常延迟。

日志不把“丢包”解释为内容安全失败；丢包是链路行为或干扰统计。

## 异常策略与 quarantine 接口

接收端 verdict：

- `accepted`: tag12 正确，sequence 新，恢复并放行。
- `verify_failed`: 认证失败，默认 drop，不恢复。
- `duplicate_sequence`: tag12 正确，但同一 session 内 sequence 已经见过，按 replay policy 处理。

`packet_sha256` 只用于日志/审计。tag 正确 + sequence 新 + SHA 旧仍然是
`accepted`，只附加 `same_sha_seen_before: true`。WireMark 不再使用 SHA 重复
决定是否丢包。

默认策略都是 `drop`。用户可用 CLI 改成 `accept`：

```text
--invalid-policy drop|accept
--replay-policy drop|accept
```

`--invalid-policy accept` 是 unsafe/debug 模式，会关闭认证失败包的核心完整性
保证；这种模式下不能声称 WireMark 仍满足“接受包必定认证通过”的安全承诺。
`--replay-policy accept` 只影响认证通过但 sequence 重复的 wrapper。

非 accepted wrapper 会写：

```text
quarantine/VERDICT/*.json
quarantine/VERDICT/*.packet.bin
quarantine/VERDICT/*.wrapper.bin
```

JSON manifest 是给外接工具的稳定接口。WireMark 不承担任何业务处理、修复或
取证分析逻辑。内容重复只是内容重复，不一定异常；编号重复才是重复 wrapper。

## 当前实现范围

- 主路径只支持 IPv4。
- 主模式是 NFQUEUE；TUN 是显式非主路径实验模式。
- 当前运行路径每个 WireMark frame 承载一个原始包；格式预留 batch，但尚未做
  吞吐优化。
- WireMark 不保护未被 NFQUEUE 规则覆盖的流量。
- WireMark 不保护已被攻破的端点、泄露的密钥、被篡改的规则或被替换的进程。
