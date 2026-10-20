# zapret 接入说明
#
# zapret（开源，见 https://github.com/bol-van/zapret）在这里承担出口
# 全 TCP（端口白名单在 nfqws 侧）的 DPI 脱敏：nfqws 接管 NFQUEUE，对首包做
# 伪造分片/乱序/坏序列，让明文 SNI 与 HTTP 特征逃过被动 DPI；established 后零开销。
# 本方案里 desync 只由 zapret 做，ua3f 的 desync 开关保持关闭（见 deploy/ua3f）。

## 文件

| 文件 | 部署位置 | 说明 |
|---|---|---|
| `zapret.nft` | `/etc/zapret.nft`（**不可**放 `/etc/nftables.d/`，嵌套 table 会导致 fw4 启动失败） | 独立 `table inet zapret`：出向进队 + 入向散件进队 + 豁免 + 免跟踪 |
| `zapret.config.example` | `/etc/config/zapret`（去掉 `.example`） | 唯一策略源 `option nfqws_opt`；改参数只改 config |
| `zapret_guard.sh` | `/root/zapret_guard.sh`（cron 每分钟） | 补表/补进程看护：缺什么补什么，正常态零动作零日志 |
| `../init.d/zapret` | `/etc/init.d/zapret` | 表恢复 + 隧道端点豁免刷新 + nfqws 进程托管 |

看护脚本挂 cron（每分钟）：

```
* * * * * /root/zapret_guard.sh
```

## 豁免（必须按你的环境填）

- `nozapret` 集：自家隧道端点 IP（本机发出的加密隧道流量不能被 fake 包搞坏）。
  静态写进 nft 文件；动态端点由 init 脚本在启动时解析域名补刷（见 init 脚本
  `ZAPRET_DOMAINS`），另建议 cron **每小时**补刷一次（IP 变化即失效）——init
  启动时的后台补刷挡的是"断网期 cron 跑不通"这段空窗。
- 豁免端口：示例只留 SSH 22；管理/隧道端口按你的环境追加。

## 观测：desync 是否真的生效

`nft list chain inet zapret postnat_hook` 看 queue 规则内嵌 `counter` 的
`packets`（规则打的 comment 是 `queue-all-tcp-egress` 等）：`packets` 不涨就说明
desync 没生效。这是 **silent fail** 的判据 —— 有两条静默失效路径：
`/tmp/nfqws` 丢了（queue 靠 `flags bypass` 空转，包照过、一条不改、无报错）
与 nfqws 活着但 queue 规则没了（表被别的东西重建/清掉）。`zapret_guard.sh`
每分钟补一次，正常态零日志。

## 放宽覆盖范围时：回包规则必须锁方向

回包入队规则必须带 `ct direction reply`（本表的 `pre` 链已经这么写）。放宽入队
范围时尤其要盯住这一点——这是把覆盖范围从 80/443 扩到全 TCP 时踩出来的坑。
原因：`ct reply packets N` 是**连接级计数，与当前这个包的方向无关**；客户端刚
发请求时该连接回包计数只有 1（仅 SYN-ACK），只按计数放行会把原始方向
（客户端→路由器）的包也卷进队列，nfqws 便对"发给路由器本机的请求"注入假载荷，
客户端收到越界 ACK 后丢掉该连接全部响应段（现象：握手成功、0 字节、永久转圈）。
细节与事故复盘见 `zapret.nft` 的 `pre` 链注释。

## 启动顺序

zapret START=98：在 sing-box（99）之前，gate（94）之后。完整顺序见
`deploy/init.d/README.md`。
