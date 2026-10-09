# 校园网多设备检测与对抗（背景补充）

本文是 `campus-device-bypass` 的补充材料，解释"为什么要有一个前置分流门"：
校园网如何发现一个账号/IP 后面挂了几台设备（或一台路由器、一个热点），以及一套
OpenWrt 旁路网关可以对应做什么。技术梳理为主，使用边界见文末。

> 一句话版本：检测看的是"你的流量里混了几种设备/OS/账号的痕迹"；对抗的主线是
> **把多设备收敛成"一台设备的样子"**，并把仍带识别价值的流量**藏进加密隧道**。

## 0. 检测信号的性价比排序

校园网实际落地的检测强度大致是：

```
TTL ≈ HTTP UA  >  IPID ≈ DPI 应用特征  >  私有心跳协议（客户端学校）
>  TCP 握手指纹 / 时钟偏移 / NTP / DHCP-DNS / JA3（多为设备厂商能力或论文方案，校园少开）
```

HTTPS 普及正在把检测重心从 UA 推向 JA3/DPI + 时钟偏移，但受性能与误报限制，
多数学校仍以 **TTL + UA + 会话/行为** 这套"老三样"为主。

| # | 手段 | 原理一句话 | 典型检出 | 校园落地度 |
|---|---|---|---|---|
| 1 | HTTP UA | 明文 UA 自带 OS 声明，同 IP 短窗内出现多类 OS 即判 | 手机+电脑混用 | ★★★ 高 |
| 2 | IP TTL | 过一跳减 1；初始值 Windows=128、Linux/Android/iOS=64，NAT 后再减 1 | 路由器 NAT、OS 混用 | ★★★ 高 |
| 3 | IPID 序列 | Windows 的 IPv4 ID 是全局递增计数器，同 IP 出现多条递增轨迹即多机 | 全 Windows 环境 | ★★ 中 |
| 4 | TCP 握手指纹（p0f 类） | SYN 的 TTL/窗口/MSS/Options 组合识别 OS | NAT、手机+电脑 | ★☆ 低-中 |
| 5 | TCP 时间戳时钟偏移 | 晶振 ppm 差异 → TSval 增速回归出不同斜率=不同物理机 | 同 OS 多机也计数 | ★ 论文级 |
| 6 | NTP 行为 | 多设备的 NTP 域名/周期/时钟行为各不相同，成弱画像 | 辅助佐证 | ★☆ 低 |
| 7 | UDP 会话行为 | 单 IP 并发五元组数/端口分配速率/心跳密度超限 | 宿舍路由、P2P | ★★ 中 |
| 8 | 私有心跳协议 | 客户端专有保活绑定账号+MAC+IP+进程，挂路由/热点即暴露 | 客户端管制学校 | ★★（有客户端时 ★★★） |
| 9 | JA3/JA4 | ClientHello 明文组合指纹，同 IP 多簇即多设备/多 App | HTTPS 时代的 UA 替代 | ★☆ 新兴 |
| 10 | DHCP/DNS 画像 | DHCP Option55/60 + OS 固定域名（更新/推送/时间） | tethering/NAT | ★★ 中 |
| 11 | DPI 行为画像 | 应用层账号/设备 ID/行为序列（微信/QQ/应用商店等） | 多设备多账号同时活跃 | ★★ 中（性能贵） |

## 1. 各手段详解

### 1.1 HTTP User-Agent
- **原理**：明文 HTTP 头里的 `User-Agent` 自带 OS/浏览器声明；同一认证 IP 在时间
  窗口内出现两类以上 OS 关键字即判共享。成本最低的被动检测。
- **局限**：HTTPS 占比高，检出率持续下降；自定义 UA、单机双系统会误报/漏报。
- **对抗点**：把出口 UA 全量归一为一个主流、真实的值（见 §3.2 与本仓库
  `deploy/ua3f/`）。

### 1.2 IP TTL
- **原理**：不同 OS 初始 TTL 不同，经 NAT 转发再减 1（Windows 128→127，
  Linux/Android/iOS 64→63）。"非 64/128"或"同 IP 多 TTL"即露馅。
- **局限**：一条 mangle 规则即可统一；跨网跳数、隧道封装会干扰；只能定性。
- **对抗点**：出口统一 TTL=64（`deploy/nftables/32-egress-fingerprint.nft`）。

### 1.3 IPID 序列
- **原理**：Windows 的 IPv4 Identification 是全局递增计数器；同一 IP 出现多条
  互不连续的递增序列即多台 Windows（Bellovin 2002 的 NAT 计数方法）。
- **局限**：只对 Windows 规律有效（Linux/macOS 多为 0，BSD 随机）；低流量易漏；
  重写 IPID 即失效。
- **对抗点**：原子包 IPID 统一置 0（同上 nft 文件），与 Linux/macOS 默认形态拉齐。

### 1.4 TCP 握手指纹（p0f 类）
- **原理**：SYN 的 `TTL + 窗口 + MSS + Options 顺序`组合可识别 OS（如
  Linux 64/5840，Win7 128/8192）。
- **局限**：指纹库对 Win10/11 与手机热点误判多；中间设备会改 MSS；样本常不足。
- **对抗点**：由代理出口重建连接（ua3f/sing-box），让出口只呈现一种指纹
  （`deploy/ua3f/ua3f.example` 的 `l3_rewrite_*`；`via-ua3f` 出口）。

### 1.5 TCP 时间戳时钟偏移
- **原理**：每台机器晶振有 ppm 级固有偏差，TCP Timestamps 的增速是其"影子"；
  同 IP 多条不同斜率即多台物理机（Kohno 2005）。为补 IPID 对 Linux/BSD 失效而生。
- **局限**：需要长时间、大量包；Windows 默认不带时间戳；NTP 调时会污染。
- **对抗点**：出口去时间戳（ua3f `l3_rewrite_tcpts`）或由代理重建连接。

### 1.6 NTP
- **原理**：多设备的 NTP 查询域名/周期不同（弱信号），且多台时钟的校准行为不同。
- **对抗点**：把 UDP 123 劫持到本机，出口只剩路由器一种时钟行为
  （`deploy/nftables/33-dns-ntp.nft`）。

### 1.7 UDP 会话行为
- **原理**：BRAS/AC 统计单 IP 的并发会话/五元组数、UDP 心跳密度，超限即限速或
  冻结（配额各校自定；分不清"单机 P2P"还是"多机共享"，只能一刀切）。
- **对抗点**：限制单机并发（BT/P2P 限速）、加密隧道收敛连接数、错峰使用（§3.12）。

### 1.8 私有心跳协议
- **原理**：部分认证系统（Dr.COM/锐捷/深信服等客户端）除认证外另发专有保活，
  绑定账号+MAC+IP+进程；挂路由、开热点、杀进程即下线/冻结。与流量特征无关。
- **局限**：只对安装了客户端的 PC 有效；Web Portal 学校无此招；第三方拨号器长期对抗。
- **对抗点**：MAC 克隆 + 路由 NAT/PPPoE 代拨（§3.10），或使用兼容的开源客户端
  （见 §6）。

### 1.9 JA3/JA4
- **原理**：TLS ClientHello 的版本/套件/扩展组合做哈希；同 IP 出现多个稳定
  互异的指纹簇即多设备/多 App。是 HTTPS 时代对 UA 的替代。
- **局限**：同一 Chrome 跨 OS 指纹接近；GREASE、会话恢复、ECH/QUIC、uTLS 伪造
  都会让检测失真；校园设备多数还没开。
- **对抗点**：出口统一客户端指纹、uTLS 伪装成主流浏览器、UA 与指纹保持一致
  （§3.9）；把有账号价值的流量整体藏进隧道。

### 1.10 DHCP / DNS 行为
- **原理**：DHCP Option55/60 可识别 OS/路由器型号；DNS 查询的域名集合本身
  就是 OS 画像（约 30 个固定域名即可区分 OS，"DHCP 指 Windows 却发 Android
  域名"=笔记本开热点）。经典研究：清华 RAIM'15，仅 DNS log >90% 准确率。
- **局限**：DNS 被劫持/缓存后出口只见路由器；DoH/DoT 后失效。
- **对抗点**：DNS 劫持到本机 + DoH 上游（`33-dns-ntp.nft` 与本仓库 README 的
  dnsmasq 配置）；同时封堵客户端自带的加密 DNS（见 §1.10 与 gate 的 DoH 名单）。

### 1.11 DPI 行为画像
- **原理**：深度解析应用层，提取账号/设备 ID/行为序列（同 IP 多微信号、多
  应用商店行为等）。厂商口径的"正统"方案，也是性能最贵的一项。
- **局限**：加密后应用识别失效；单人多号/双开误报；特征库维护昂贵。
- **对抗点**：全流量隧道（DPI 直接无解）+ 行为收敛；这也是本方案把
  微信/QQ/抖音/游戏等有账号价值的流量全部送进加密上行组的直接原因。

## 2. 常见厂商与产品（速览）

| 厂商 | 防共享产品/形态 | 检测特征概要 |
|---|---|---|
| 锐捷 | SAM/SAM+ 认证计费 + ASME1000 旁路嗅探 | DPI 多维度 + 代理特征库 + AI；防随身 WiFi/ICS/NAT |
| Dr.COM（城市热点） | APG 防代理网关（旁挂/串接）+ 客户端 | 认证分析/客户端特征/路由器特征/网元日志/热点/DPI 六维 |
| H3C | ACG1000/防火墙 + EIA/UAM | 时间戳、UA、应用特征（QQ/微信等）、IPID-APR、Flash/WebRTC |
| 华为 | iMaster NCE-Campus 准入 + BRAS/USG | 终端识别（MAC/DHCP/UA）+ 绑定，防共享多靠 BRAS/第三方 |
| 深信服 | AC 上网行为管理 | DPI + Flash Cookie + 字体检测 + URL 特征，秒级发现小路由 |
| 深澜 | Srun 认证计费 + 防代理系统 | DPI 七层 + 特征码 + 终端数策略（提醒/降速/下线/封禁） |
| 神码 DCN / 天融信 / 联奕 | 存量/中等/无检测 | 多为绑定与审计；联奕本身不做流量检测 |

> 选型视角的共性：**旁路只能发现不能阻断**；真正执行点在串接防火墙/BRAS 或
> AC。对抗视角的共性：**TTL 固定 + UA 统一 + IPID 归一 + NTP/DNS 收敛 +
> 有识别价值的流量加密**。

## 3. 对抗手段清单（OpenWrt 场景）

叠加顺序建议：`TTL → UA → NTP/DNS → 代理单出口 → IPID/时间戳 → 行为`。
每加一层都用 `conntrack`/UA 回显/抓包验证，不要一次全上。

### 3.1 TTL 统一（性价比最高）
```sh
# nftables/fw4：出受管网段的包统一 TTL=64
nft add rule inet fw4 iot_mangle_post oifname "br-lan" ip ttl set 64
# 终端辅助：sysctl net.ipv4.ip_default_ttl=64（网关自身）
```
**必关卸载**：flow offloading / TurboACC / fastpath 会跳过 mangle hook，
`uci set firewall.@defaults[0].flow_offloading=0`。副作用：弱 CPU 负载上升。

### 3.2 HTTP UA 归一
- 演进路径：`Privoxy → xmurp-ua（内核，仅 80）→ UA2F（NFQUEUE）→ UA3F（Go，SOCKS5/L3 重写）`。
- 要点：伪装值用主流真实值（干净 Chrome 系）；**UA 必须与 TLS 指纹一致**；
  自带 App 尾巴的 UA 反而成为特征；必须关闭流量卸载。
- 本仓库对应：`deploy/ua3f/ua3f.example`（`via-ua3f` 出口 + GLOBAL 改写）。

### 3.3 IPID 随机化/统一
- 彻底解法是单出口代理重建（出口 IPID 自然统一）；直连流量用 nft 把原子包
  IPID 置 0（本仓库 32 号文件），或内核模块 `rkp-ipid` 做 0x10/0x20 策略。

### 3.4 TCP 时间戳关闭/统一
- 终端全关（`net.ipv4.tcp_timestamps=0`，协商制）或网关剥离/重写 SYN 时间戳；
  推荐由代理终结重建（ua3f `l3_rewrite_tcpts`）。副作用：损失 RTT 测量/PAWS。

### 3.5 TCP 窗口 / MSS 钳制
```sh
iptables -t mangle -A FORWARD -o pppoe-wan -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu
# nft：tcp option maxseg size set rt mtu（注意双向）
```
只改出向会复现"单边钳制"问题，需要双向一致。

### 3.6 NTP 收敛（强特征，必做）
```sh
uci set system.ntp.enable_server='1'
iptables -t nat -I PREROUTING -p udp --dport 123 -j ntp_force_local
# 排除 0/8、127/8、192.168/16 后 DNAT 到网关
```
副作用：下游时钟全跟路由器，路由器漂移则全网漂移。

### 3.7 单设备代理出口（一招收敛 L3/L4 + 加密 DPI）
- `客户端 → nftables TPROXY/REDIRECT → 代理核心 → ua3f → 校园网`：
  ua3f 关闭客户端 TCP、用路由协议栈重发起，L3/L4 指纹统一 + UA 改写。
- 单栈：IPv6 drop + 关 RA/RDNSS（TPROXY 只写 v4 是常见穿帮点）；封 QUIC
  （`udp dport 443 reject` 比 drop 回落更快，也避免 QUIC 绕过代理链）。
- 激进：FORWARD 默认 DROP 只放行代理用户。副作用：CPU/内存上升、单点故障；
  单账号并发过大（>100–500）仍会被行为检测抓。
- 本仓库的主角就是这个环节：**gate 决定哪些流量必须进隧道**，
  sing-box 负责其余流量的精细分流（直连/改写/隧道）。

### 3.8 DHCP / DNS 收敛
- DNS 全劫持到 dnsmasq，dnsmasq 上游走 DoH；关 RA 多余 RDNSS；DHCP 只下发
  一个 DNS+网关。**同时要封堵客户端自带的加密 DNS**（DoH 域名/IP block +
  DoT 853 reject），否则等于把 §1.10 的画像直接交给上游。
- 副作用：银行/政务 App 对 DNS 劫持敏感，新域名先观察日志再执法。

### 3.9 TLS 指纹收敛
- 代理客户端强制 `client-fingerprint: chrome`（或与 UA 匹配的主流值）；
  统一全家出口的 TLS 客户端栈；UA 与指纹对齐（UA 声称 Chrome、指纹是 Go = 自爆）。
- 验证：`tls.peet.ws` 之类回显站点对比浏览器与代理出口。

### 3.10 MAC 与认证策略
- WAN 口克隆已认证设备 MAC + 固定静态 IP；意外封锁的自愈（失败探针 → 换 MAC/
  重拨/重认证）要限频，频繁换 MAC 反而触发更严的惩罚。
- 一号多机场景更稳的做法是不同的出口设备用不同账号/线路，而不是挤同一个号。

### 3.11 心跳 / Flash / 私有协议
- 老式 AC 的 Flash 探测、字体检测、私有串特征等，整体思路是加密 + 不暴露
  明文特征；杀客户端进程会触发离线，别用"伪装客户端"半成品。

### 3.12 行为收敛（加密也藏不住的一维）
- 限速 + 限连接（单账号压到单机合理值）；BT/P2P 限速或闲时跑；避免多设备
  同时大流量活跃；错峰使用。体验降级换稳定，阈值收紧即失效。

### 3.13 运营策略（风险最低）
- 确认本校开了哪几维检测，再针对性叠加；被误判走申诉/白名单；公共设备用完注销。

## 4. 本仓库的映射：检测项 → 实现位置

| 检测项 | 本方案对应 | 实现位置 |
|---|---|---|
| HTTP UA | 出口 UA 全量改写为统一值 | ua3f（`deploy/ua3f/ua3f.example`，经 sing-box `via-ua3f` 出口） |
| IP TTL | 出受管网段统一 TTL=64 | `deploy/nftables/32-egress-fingerprint.nft`（`iot_mangle_post`） |
| IPID | 原子包 IPID=0 | 同上（`all-ipid-zero-iot`） |
| TCP 指纹/时间戳 | 直连类流量经 ua3f 重建；`tcp/443` 也规则化走 `via-ua3f` | sing-box 路由 + ua3f `l3_rewrite_*` |
| NTP | UDP 123 劫持到本机 | `deploy/nftables/33-dns-ntp.nft` + `system.ntp.enable_server` |
| DNS/DoH 画像 | 53 劫持到 dnsmasq→DoH；853 reject；DoH 域名/IP 封堵 | `33-dns-ntp.nft` + gate 的 DoH 名单（`lists/doh-*.example`）+ sing-box block 规则 |
| JA3/DPI 应用特征 | 有账号价值的流量（微信/QQ/抖音/游戏/私有协议）全部进加密上行组 | gate 判定 + sing-box `hezi` 组（`deploy/sing-box/example.json`） |
| UDP 会话/STUN | STUN 统一进 gate 判定并中继，非 STUN 才直连 | `deploy/nftables/31-gate-udp.nft` + `gate/udp.go` |
| QUIC 绕过代理链 | `udp/443` reject 逼回 TCP | `32-egress-fingerprint.nft`（`iot_quic_block`） |
| 私有心跳（客户端类） | 不在本仓库范围（认证层问题） | 另见 §6 的第三方客户端项目 |

## 5. 边界与风险

- **加密 ≠ 隐身**：隧道只藏内容与协议特征；流量行为（并发、时段、总量、
  单隧道本身的形态）仍可能被观测。行为层收敛与运营策略（§3.12/3.13）
  不可省。
- **检测强度随时升级**：本文基于公开资料与 2025–2026 年的公开案例整理，
  各校配置不同；上量前先小范围验证自家环境开了哪几维。
- **影响面**：TTL/IPID/UA 改写会影响所有受管设备；DoH 封堵、QUIC 拒绝、
  限速等策略会让个别 App 变慢或异常（银行/政务 App 对 DNS 劫持敏感，
  新封禁项先日志后执法）。
- **合规**：绕过校园网的多设备限制/计费策略通常违反学校网络管理规定，
  可能触发断网、限速、冻结账号等处罚。请在**自有或获授权的网络**里、
  以学习与研究为目的使用本方案，风险自负。

## 6. 延伸阅读（公开项目）

- 认证客户端：`drcoms/drcom-generic`（Dr.COM 逆向总源）、`mchome/dogcom`、
  `cyp0633/drcom-go`、`HustLion/mentohust`、`updateing/minieap`、`zu1k/srun`
- UA 改写：`SunBK201/UA3F`、`Zxilly/UA2F`、`GiriNeko/xmurp-ua`
- 代理核心：`SagerNet/sing-box`、`MetaCubeX/mihomo`
- 指纹伪装：`refraction-networking/utls`、`bogdanfinn/tls-client`、`p0f/p0f`（验证用）
- 本类实践：`SunBK201` 的校园网系列文章、`crack-campus-network`
- DoH 名单源：`dibdot/DoH-IP-blocklists`、`Sekhan/TheGreatWall`
