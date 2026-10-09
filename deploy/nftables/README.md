# nftables 片段说明

这些文件是参考部署里 `wxdet-gate` 相关的 nftables 规则片段，部署位置
`/etc/nftables.d/`（fw4 会在 `inet fw4` 表上下文 include 该目录，可直接引用
fw4 的具名 set/链）。文件编号即加载顺序，可自行改名，链名保持与实际部署一致。

| 文件 | 内容 |
|---|---|
| `30-gate-redir.nft` | 受管网段 TCP → `:12347` 重定向（`iot_redir`）+ 保留口防护（`drop1080`） |
| `31-gate-udp.nft` | UDP 三条腿：STUN/UDP80/8080 → gate `:12348`（`iot_stun_dnat`）+ 其余 UDP TPROXY → 下游 `:12346`（`iot_udp_proxy`） |
| `32-egress-fingerprint.nft` | 出口指纹整理：TTL=64、IPID=0、ICMP 伪装、IPv6 drop、QUIC reject |
| `33-dns-ntp.nft` | DNS 收敛（53 劫持、853 拒绝）与 NTP 劫持 |

## 使用与注意事项

- **前置条件**：`uci set firewall.@defaults[0].flow_offloading=0`。flow offloading /
  TurboACC / 硬件加速会让包绕过 mangle hook，32 号文件的指纹整理会全部失效。
- **策略路由**：31 号文件使用 `tproxy`，需要 `deploy/init.d/iot-tproxy` 的
  `ip rule` + `ip route` 配合，否则被 mark 的包无路可走。
- **生效方式**：优先 `nft -f <file>` 增量加载 + `nft list chain inet fw4 <chain>` 确认；
  小改动用 `nft add/delete rule` 直接热修。不建议动不动 `fw4 reload` —— 它会清零
  全部链计数器，破坏基于计数器的观测与排障基线（本项目大量使用 counter 做 tripwire）。
- **网段替换**：示例中 `192.168.2.0/24` 为受管网段、`192.168.2.1` 为该网段本机地址、
  `192.168.71.1` 为上游网关、`br-iot`/`br-lan` 为接口名，全部按你的网络替换。
- 这些片段只覆盖"与分流相关"的部分；完整的防火墙 zone、DHCP、无线配置不在本仓库范围。
