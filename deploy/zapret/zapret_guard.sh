#!/bin/sh
# zapret 看护（每分钟 1 次，cron）：desync "静默失效" 的两条路径各补一道网。
# 背景（实测）：/tmp/nfqws 丢失时 queue 靠 `flags bypass` 空转 —— 包照过、
#   一条都不改，desync 静默失效且没有任何报错。反向同理：nfqws 活着但 queue 规则没了
#   （表被别的东西重建/清掉），一样静默。
# 本脚本只做"缺什么补什么"，不做策略判断：策略唯一来源仍是 /etc/config/zapret（nfqws 参数）
#   与 /etc/zapret.nft（nft 表）。参数/策略改动一律不走这里。
# 幂等：正常态零动作、零日志（每分钟跑不会有噪音）。
NFT=/usr/sbin/nft

have_table() { $NFT list table inet zapret >/dev/null 2>&1; }
have_queue() { $NFT --stateless list chain inet zapret postnat_hook 2>/dev/null | grep -q "queue.*to 200"; }

restore_table() {
	# 先删后建：表存在但规则缺失时，直接 `nft -f` 会因表同名报错，故统一走重建。
	$NFT delete table inet zapret >/dev/null 2>&1
	$NFT -f /etc/zapret.nft || { logger -t zapret_guard "restore from /etc/zapret.nft FAILED"; return 1; }
}

if ! have_table; then
	logger -t zapret_guard "table inet zapret missing -> restore"
	restore_table
elif ! have_queue; then
	logger -t zapret_guard "queue rule to 200 missing -> rebuild table"
	restore_table
fi

if ! pidof nfqws >/dev/null 2>&1; then
	logger -t zapret_guard "nfqws not running -> /etc/init.d/zapret start"
	/etc/init.d/zapret start >/dev/null 2>&1 || logger -t zapret_guard "zapret start FAILED"
fi
exit 0
