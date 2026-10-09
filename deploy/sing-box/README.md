# sing-box 接入说明

`example.json` 是从实际部署裁剪出的**最小可跑骨架**（原部署为 sing-box 1.14.x，
31 条路由；示例保留结构语义、裁掉长名单）。配合 `deploy/nftables/31-gate-udp.nft`
与 `deploy/init.d/iot-tproxy` 即可让 UDP TPROXY、gate 判流、UA 改写三条链完整跑通。

## 入站

| tag | 端口 | 作用 |
|---|---|---|
| `socks` | `127.0.0.1:10808` | 通用 SOCKS5/mixed：gate 判 `pass` 的流量从这里进；也是本机排障入口（`curl -x socks5h://127.0.0.1:10808 ...`） |
| `proxy-in` | `127.0.0.1:10811` | **gate 判 `proxy` 专用**：gate 的 fail-closed 拨号目标，只监听 loopback |
| `transparent-udp` | `[::]:12346` | nft `tproxy` 送进来的 UDP（配合策略路由） |

## 出站

| tag | 说明 |
|---|---|
| `direct` | 直连 |
| `via-ua3f` | 经本机 ua3f SOCKS5（`127.0.0.1:18081`）出口，统一 UA/L3 指纹 |
| `proxy-direct` | 本机另一种隧道客户端（例如 hysteria2 的 socks5 入口 `127.0.0.1:18082`） |
| `lx` | 远程隧道节点示例（VLESS+TLS，字段按示例填，换你自己的节点） |
| `proxy` | `urltest` 出口组：在 `proxy-direct` 与 `lx` 间按延迟选路、故障转移；gate 与路由规则都只引用组名 |
| `block` | 阻断（加密 DNS 封堵等） |

> 实际部署的隧道腿使用 XHTTP 传输 + ECH + VLESS 后量子 `encryption`
> （需要支持这些特性的 sing-box fork / 自编译版本）；示例为兼容性起见用
> 通用 VLESS+TLS 形态。传输协议、节点数量都可按你的环境替换，路由与 gate
> 不受影响 —— 它们只认 `proxy` 这个组名。

## 路由顺序（语义关键，改规则务必保持）

1. `sniff`：对 socks/透明入站嗅探 SNI/HTTP Host（300ms 超时）。
2. **`inbound == proxy-in` → `proxy` 必须排最前**：gate 已经做完判定，
   不能被后续 block/域名/443 规则截走。
3. `udp/443` → `block`、DoH 域名/IP → `block`：**必须排在 `tcp/443` 规则之前**，
   否则加密 DNS 会被 443 兜底规则送进普通出口。
4. `tcp/443` → `via-ua3f`：443 流量也要过 UA/指纹整理（有意为之，不是最终直连）。
5. 下载站 / 运营商 BSF 信令域名 → `via-ua3f`（走代理出口但统一指纹）。
6. STUN 端口 → `proxy`（nft 已先 DNAT 进 gate，这里是双保险）。
7. 私网段 → `direct`（不进隧道）。
8. 业务域名（微信/抖音/游戏等）→ `proxy`：这些流量在校园网侧有应用层/账号级
   检测价值，全部藏进隧道。
9. 末条 `network: tcp` 锚点 → `via-ua3f`；`final: direct`（UDP 没有兜底规则，
   默认直连）。

## 部署

```sh
# 1) 配置放入 /etc/sing-box/config.json；日志目录要先存在（缺失会起不来）
mkdir -p /tmp/wxdet
# 2) 跑通前必查
sing-box check -c /etc/sing-box/config.json
# 3) 重启（注意：restart 有秒级断流；名单类重写尽量放在低峰）
/etc/init.d/sing-box restart
```

实际部署用 `/etc/init.d/sing-box` 从 overlay 种子解压二进制到 `/tmp`（tmpfs）
再运行，避免写坏 overlay；这里不再重复，按你的系统服务方式托管即可。
