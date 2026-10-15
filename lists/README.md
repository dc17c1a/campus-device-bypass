# lists 说明

`wxdet-gate` 消费的名单**样例**；下游代理路由可按同源规则同步。使用时把需要的文件复制到
`/etc/wxdet/`（保持示例名去掉 `.example` 后的文件名），gate 会每 30 秒按
mtime/size 热加载，不用重启进程；文件缺失/某次读取失败时保留上一份快照。

| 文件 | 复制为 | 消费方与语义 |
|---|---|---|
| `dl-domains.example` | `/etc/wxdet/dl-domains.txt` | gate：下载站域名**精确或子域后缀**匹配，命中 → `pass/dl_direct`（转交下游入口） |
| `dl-ua.example` | `/etc/wxdet/dl-ua.txt` | gate：下载器 UA token**小写子串**匹配，命中 → `pass/dl_ua` |
| `dl-ext.example` | `/etc/wxdet/dl-ext.txt` | gate：二进制/媒体 URL 后缀（不含 `.`），命中 → `pass/dl_ext` |
| `dl-query.example` | `/etc/wxdet/dl-query.txt` | gate：URL query 预签名/强制下载参数子串，命中 → `pass/dl_query`（排 Range 之后） |
| `bsf-domains.example` | `/etc/wxdet/bsf-domains.txt` | 下游代理路由用：运营商信令域名（gate 当前版本不读，留作路由侧合并规则输入） |
| `doh-domains.example` | `/etc/wxdet/doh-domains.txt` | 下游代理路由用：加密 DNS 域名 block（gate 当前版本不判 `block`，封堵由下游执行） |
| `doh-ips.example` | `/etc/wxdet/doh-ips.txt` | 下游代理路由用：加密 DNS 解析器 IP block（同上） |

说明：

- 列表是**样例**而非全量生产名单。特别是 DoH 两份长名单，生产请自行从上游组合生成，例如
  [dibdot/DoH-IP-blocklists](https://github.com/dibdot/DoH-IP-blocklists)、
  [Sekhan/TheGreatWall](https://github.com/Sekhan/TheGreatWall)。
- 格式统一为逐行一条、`#` 开头为注释；域名匹配大小写不敏感、忽略结尾点。
- 改名单后若要同步下游代理路由规则，需要按你的下游代理配置方式重新生成；示例后端用
  `sing-box check` 后重启；gate 侧名单是即时生效的。
  （历史形态注记：早期的下载站 `via-ua3f` 早位规则、DoH block 规则现网已删，
  gate 为下载站/STUN 的唯一判点；`example.json` 已同步为四规则形态。）
