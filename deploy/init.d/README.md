# init.d 启动脚本说明（部署位置 /etc/init.d/，`chmod 755` + `enable`）
#
# | 文件 | START | 职责 |
# |---|---|---|
# | `iot-tproxy` | 18 | TPROXY 策略路由（fwmark 0x100 → 本地投递） |
# | `ipidfix` | 20 | DF 包 IPID 归零独立表 |
# | `wxdet-gate` | 94 | 前置分流门（TCP :12347 + UDP :12348） |
# | `zapret` | 98 | 出口 TCP 全量 NFQUEUE 脱敏（在下游代理之前） |
# | `sing-box` | 99 | 下游代理核心（种子自恢复 + 先 check 后 run） |
# | `ua3f` | 99 | 指纹整理（同二进制可起第二实例） |
#
# 顺序语义：分流（18/20）→ 判决（94）→ 脱敏（98）→ 出口（99）。
# 本目录只覆盖与分流/脱敏/出口相关的服务；防火墙 zone、DHCP、无线、
# 流量旁路采集等不在本仓库范围。
