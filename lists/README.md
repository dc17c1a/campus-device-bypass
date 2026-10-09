# lists 说明

`wxdet-gate` 与 sing-box 消费的名单**样例**。使用时把需要的文件复制到
`/etc/wxdet/`（保持示例名去掉 `.example` 后的文件名），gate 会每 30 秒按
mtime/size 热加载，不用重启进程；文件缺失/某次读取失败时保留上一份快照。

| 文件 | 复制为 | 消费方与语义 |
|---|---|---|
| `gate.kw.example` | `/etc/wxdet/gate.kw` | gate TCP 关键词：对 HTTP Host / 请求行 / UA 做**小写子串**匹配（域名/包名/协议串混杂），命中即 `hezi` |
| `dl-domains.example` | `/etc/wxdet/dl-domains.txt` | 下载站域名：**精确或子域后缀**匹配，命中 → `xray/dl_direct`（交给代理核心） |
| `dl-ua.example` | `/etc/wxdet/dl-ua.txt` | 下载器 UA token：**小写子串**匹配，命中 → `xray/dl_ua` |
| `dl-ext.example` | `/etc/wxdet/dl-ext.txt` | 二进制/媒体 URL 后缀（不含 `.`），命中 → `xray/dl_ext` |
| `bsf-domains.example` | `/etc/wxdet/bsf-domains.txt` | 运营商 BSF/RCS 信令域名，命中 → `xray/bsf_direct`（运营信令直连，不随逃生开关回滚） |
| `doh-domains.example` | `/etc/wxdet/doh-domains.txt` | 加密 DNS 域名：精确/子域命中 → `block/dns_block`；sing-box 路由里还有一份同源 block 规则 |
| `doh-ips.example` | `/etc/wxdet/doh-ips.txt` | 加密 DNS 解析器 IP：**精确**命中（443 端口）→ `block/dns_block`；gate 内置一份常见解析器种子，文件只增不减 |

说明：

- 列表是**样例**而非全量生产名单。特别是 DoH 两份长名单（实际部署 1923 域 /
  3514 IP），请自行从上游组合生成，例如
  [dibdot/DoH-IP-blocklists](https://github.com/dibdot/DoH-IP-blocklists)、
  [Sekhan/TheGreatWall](https://github.com/Sekhan/TheGreatWall)。
- 格式统一为逐行一条、`#` 开头为注释；域名匹配大小写不敏感、忽略结尾点。
- 改名单后若要同步 sing-box 路由规则（如下载站 `via-ua3f` 早位规则、
  DoH block 规则、hezi 尾段），需要按你的 sing-box 配置方式重新生成并
  `sing-box check` 后重启；gate 侧名单是即时生效的。
