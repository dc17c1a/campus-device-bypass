# zapret 接入说明
#
# zapret（开源，见 https://github.com/bol-van/zapret）在这里承担出口
# TCP 80/443 的 DPI 脱敏：nfqws 接管 NFQUEUE，对首包做伪造分片/乱序/坏序列，
# 让明文 SNI 与 HTTP 特征逃过被动 DPI；established 后零开销。
# 本方案里 desync 只由 zapret 做，ua3f 的 desync 开关保持关闭（见 deploy/ua3f）。

## 文件

| 文件 | 部署位置 | 说明 |
|---|---|---|
| `zapret.nft` | `/etc/zapret.nft`（**不可**放 `/etc/nftables.d/`，嵌套 table 会导致 fw4 启动失败） | 独立 `table inet zapret`：出向进队 + 入向散件进队 + 豁免 + 免跟踪 |
| `zapret.config.example` | `/etc/config/zapret`（去掉 `.example`） | 唯一策略源 `option nfqws_opt`；改参数只改 config |
| `../init.d/zapret` | `/etc/init.d/zapret` | 表恢复 + 隧道端点豁免刷新 + nfqws 进程托管 |

## 豁免（必须按你的环境填）

- `nozapret` 集：自家隧道端点 IP（本机发出的加密隧道流量不能被 fake 包搞坏）。
  静态写进 nft 文件；动态端点由 init 脚本在启动时解析域名补刷（见 init 脚本
  `ZAPRET_DOMAINS`），另建议 cron 每天补刷一次（IP 变化即失效）。
- 豁免端口：示例只留 SSH 22；管理/隧道端口按你的环境追加。

## 启动顺序

zapret START=98：在 sing-box（99）之前，gate（94）之后。完整顺序见
`deploy/init.d/README.md`。
