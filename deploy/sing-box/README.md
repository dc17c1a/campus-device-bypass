# sing-box 接入说明

`example.json` 是与现网同构的**最小可跑骨架**（路由四规则 + final direct；
长名单与真实节点已裁掉，字段按示例占位填你自己的）。

## 入站

| tag | 端口 | 作用 |
|---|---|---|
| `socks` | `127.0.0.1:10808` | 通用 SOCKS5/mixed：本机排障/管理入口（`curl -x socks5h://127.0.0.1:10808 ...`）；gate 的 `pass` 默认直拨 `:18081`，不经这里（可改 `WD_PASS_SOCKS` 接入） |
| `proxy-in` | `127.0.0.1:10811` | **gate 判 `proxy` 专用**：gate 的 fail-closed 拨号目标，只监听 loopback（与现网同端口，tag 名按你的配置） |

## 出站

| tag | 说明 |
|---|---|
| `direct` | 直连 |
| `via-ua3f` | 经本机 ua3f SOCKS5（`127.0.0.1:18081`）出口，统一 UA/L3 指纹 |
| `lx` | 远程隧道节点示例（VLESS+TLS，`tunnel.example.com:8443` 占位，换你自己的节点） |
| `lx2` | 第二条远程腿占位（同 `tunnel.example.com`，端口/uuid 都是占位）—— 故障转移要有第二条腿才有意义，换成你的第二个节点 |
| `proxy` | `urltest` 出口组：在 `lx`/`lx2` 等远程腿间按延迟选路、故障转移；gate 与路由规则都只引用组名（示例两条腿，按你的节点补齐成员） |
| `block` | 阻断（加密 DNS 封堵等） |

> 实际部署的隧道腿使用 XHTTP 传输 + ECH + VLESS 后量子 `encryption`
> （需要支持这些特性的 sing-box fork / 自编译版本）；示例为兼容性起见用
> 通用 VLESS+TLS 形态。传输协议、节点数量都可按你的环境替换，路由与 gate
> 不受影响 —— 它们只认 `proxy` 这个组名。

## 路由顺序（语义关键，改规则务必保持；与现网四规则一致）

1. **`inbound == proxy-in` → `proxy` 必须排最前**：gate 已经做完判定，
   不能被后续规则截走（现网无 `sniff` 规则，它就在第一位）。
2. 私网段 → `direct`（不进隧道）。
3. 本地域名（占位）→ `direct`（本地解析保护，按你的内网域替换）。
4. 末条 `network: tcp` 兜底 → `via-ua3f`；`final: direct`（UDP 没有兜底规则，
   默认直连）。

历史形态（早期部署曾有，已瘦身删除；`example.json` 不再保留）：
DoH/QUIC block、tcp/443 单独规则、下载站与 STUN 端口早位规则、业务域名→proxy。
下载站归 gate 名单（`lists/dl-*`）、STUN 归 gate UDP 门，gate 为唯一判点。

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
