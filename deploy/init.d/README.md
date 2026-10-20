# init.d 启动脚本说明（部署位置 /etc/init.d/，`chmod 755` + `enable`）
#
# | 文件 | START | 职责 |
# |---|---|---|
# | `iot-tproxy` | 18 | TPROXY 策略路由（fwmark 0x100 → 本地投递） |
# | `ipidfix` | 20 | DF 包 IPID 归零独立表 |
# | `wxdet-gate` | 94 | 前置分流门（TCP :12347 + UDP :12348） |
# | `ua3f desync` | — | 出口 TCP 前 2KB/前 8 包经 NFQUEUE 由 ua3f 做 reorder（全端口；zapret 已退役，见下） |
# | `sing-box` | 99 | 下游代理核心（种子自恢复 + 先 check 后 run） |
# | `ua3f` | 99 | 指纹整理（同二进制可起第二实例） |
#
# 顺序语义：分流（18/20）→ 判决（94）→ 出口（99）；脱敏由 ua3f 实例内建 desync 承担，不再有独立脱敏服务。
# 本目录只覆盖与分流/脱敏/出口相关的服务；防火墙 zone、DHCP、无线、
# 流量旁路采集等不在本仓库范围。

> 注：`zapret`（NFQUEUE 脱敏）已退役并删除：fake 包曾毒化近端游戏前置导致登录失败；desync 现由 ua3f 接管。
