# wxdet-gate（Go 前置分流网关）

旁路网关的前置分流门。nftables 把受管网段的 TCP 重定向到 TCP `:12347`、
公网 UDP 全量 TPROXY 到 UDP `:12348`；本进程 peek 首包判定，
只输出两种判决，不指定下游软件：

- TCP：标准 TLS（严判）→ `pass`/`tls_direct`；明文 HTTP 下载特征
  （Host 名单→`dl_direct`、Range 头→`dl_range`、URL query 签名→`dl_query`、
  下载器 UA→`dl_ua`、二进制媒体后缀→`dl_ext`）→ `pass`；其余一切 →
  `proxy`/`default`。`pass` 由 gate 直拨下游普通入口（`WD_PASS_SOCKS`，
  默认 `127.0.0.1:18081`），`proxy` 经下游代理入口（`WD_PROXY_SOCKS`，
  默认 `127.0.0.1:10811`）；失败一律 fail-closed（`gate_pass_fail`/
  `gate_proxy_fail`，不回退、不改拨第二腿）。
  旧政策（DoH 封堵、私有协议指纹、关键词、BSF、`http_plain`/`port80`、
  443/段内兜底、代理记忆、逃生文件、SNI 解析）已删；第三腿（历史形态，`10808`）
  gate 永不再拨。
  `:80` 仍用 `WD_PEEK80_MS`（默认 80ms）短读。
- 日志：`gate.log` 每行含 `proto`（`tcp`/`udp`）；`verdict=err` 行另含
  64B 截断 `detail`（拨号失败原因，`tail` 即定位）；UDP `local_dst`
  丢弃限速采样。stats 记 `verdict/reason` 分级计数（assoc 建链/升级成功记，
  TCP 同口径）。
- UDP `:12348`：`udp4` + `IP_RECVORIGDSTADDR` + `recvmsg` 逐包取真目的
  （DNAT 已退役：本机返回 NAT 后目的恒黑洞，只能 TPROXY）。
  判路（STUN 优先）：先看形状——STUN（标准魔数 + 长度一致 / 变种）任意端口
  命中即 `proxy`/`stun_udp`；非 STUN 再按端口：≤10000 → `proxy`/`udp_proxy`，
  >10000 → `pass`（`udp_direct`/`udp_short`）。assoc 表 idle 120s/512 条；
  中继条件仍 `verdict==proxy`，assoc 失败 fail-closed；pass→proxy 单向升级保留。
- UDP 下行源欺骗：握手期校验源的客户端会拒收非对端源的回包，gate 为每个
  assoc 建透明 socket 绑定对端地址回包，失败时降级为监听 socket（各记一个
  计数器，只降级一次）。

构建与部署：

```sh
cd gate
gofmt -l . && go vet ./... && go test ./...
GOOS=linux GOARCH=arm64 go build -o wxdet-gate .
# 覆盖运行中的二进制不能直接 scp 到目标路径（ETXTBSY）：
# 先传到 /tmp 再停服务替换，精确找 pid 看二进制 exe 链接：
# for p in /proc/[0-9]*; do [ "$(readlink $p/exe)" = "/usr/bin/wxdet-gate" ] && echo ${p#/proc/}; done
```

## 加固要点（审查后修复）

- **TCP 本机目的守卫**：`handleConn` 在 origdst 之后判本机地址
  （loopback/private/link-local/unspecified，与 UDP 同口径），命中即
  drop + `gate_tcp_local_drop`。没有它时本机进程直连监听口会形成自连风暴
  直到 `too many open files`。**不做端口判断**。
- **TLS 首包续读**：`0x16` 开头但首读不足 6 字节时，在同一 150ms 预算内续读到
  6 字节再做 TLS 严判；peek buf 为 1KB。
- **头/体隔离**：Host/Path/UA/Range 只在 header block 内找，POST body
  里的特征串不再翻转判路。
- **UDP**：建链移出 recv 循环（assoc 壳先入表，包进有界队列，溢出计数）；
  支持 **pass→proxy 单向升级**（失败计数且保持原腿）；封装决策在 `send`
  的锁内完成（换腿窗口不许把裸载荷写进代理的 SOCKS5-UDP socket）；
  错误日志每进程限速。
- 其他：`socks5Dial` 校验回复；`logGate` 只渲染前 24B hex；`classifyEx`
  为纯函数，统计副作用留在 `classify` 包装层。

观测：`tail gate.log`（assoc/`verdict=`），`tail -3 stats.tsv`。
直连面（`pass`/`tls_direct`）不进事件流（体量最大），改走**聚合台账**：字节/时长
累计后每分钟增量刷进 `stats.tsv`，键为 `gate_tlsdirect_close`/`gate_tlsdirect_up_B`/
`gate_tlsdirect_down_B`/`gate_tlsdirect_dur_ms`（无流量时一行都不写；进程被杀最坏
丢一分钟增量）。
名单 30s 热加载（`dl-domains`/`dl-ua`/`dl-ext`/`dl-query`，见 `lists/*.example`；
Range 只判有无，强弱只做计数不改判路）。

## fail-closed（行为 + 用例钉死）

出站决策点收拢成单函数：`proxy`→代理入口、`pass`→下游普通入口，
**每个 verdict 只拨一跳**；失败即返回 `nil`（客户端断流），只记失败计数
并落 `err` 事件。回归测试钉死两条：代理入口回失败、普通入口回失败都必须
不断第二腿（另带正常时真走对应入口的正控），反向验证（把失败分支改成
回退另一腿，用例立刻转红）。
