package main

// wxdet-gate —— 旁路网关的前置分流门（TCP :12347 + UDP :12348）。
//
// nftables 把受管网段的 TCP 重定向（以及 STUN / UDP 80 / UDP 8080 的 DNAT）到本进程；
// 本进程 peek 客户端首包，按协议指纹与明文特征把连接分成四类：
//
//	verdict=proxy  必须走代理：拨到下游的敏感/加密入口；失败不回退直连。
//	verdict=pass   转交下游：拨到下游的普通入口，由下游自行决定路由。
//	verdict=block  政策阻断（加密 DNS 等），直接断流。
//	verdict=direct 仅 UDP：直连回源（非 STUN 残渣）。
//
// 设计取向：会被厂商私有协议/明文特征直接识别为“多设备”的流量，宁绕路不漏放；
// 其余流量转交下游入口精细分流，保证吞吐与体验。gate 只做判决，不指定下游软件。
import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const soOriginalDst = 80

// defProxySocks = 下游敏感/加密入口（SOCKS5）；gate 判 proxy 的流量经它进入下游。
// 示例默认指向本机 127.0.0.1:10811，可用 WD_PROXY_SOCKS 覆盖为任意代理入口。
const defProxySocks = "127.0.0.1:10811"

var (
	listenAddr  = envStr("WD_LISTEN", "0.0.0.0:12347")
	passSocks   = envStr("WD_PASS_SOCKS", "127.0.0.1:10808")
	proxySocks  = envStr("WD_PROXY_SOCKS", defProxySocks)
	kwPath      = envStr("WD_KW_FILE", "/etc/wxdet/gate.kw")
	gateLogPath = envStr("WD_LOG", "/tmp/wxdet/gate.log")
	statsPath   = envStr("WD_STATS", "/tmp/wxdet/stats.tsv")
	peekWait    = time.Duration(envInt("WD_PEEK_MS", 400)) * time.Millisecond
	peekWait80  = time.Duration(envInt("WD_PEEK80_MS", 80)) * time.Millisecond
	kwPollSec   = envInt("WD_KW_POLL_SEC", 30)
	kws         atomic.Value // stores []string；热加载时原子替换，读无锁
	kwMu        sync.Mutex
	kwModTime   time.Time
	kwSize      int64
	statFile    *os.File
	gateLogFile *os.File
	ioMu        sync.Mutex
	connSeq     uint64
)

func envStr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

type dstAddr struct {
	ip   net.IP
	port int
}

func (d dstAddr) String() string {
	return net.JoinHostPort(d.ip.String(), strconv.Itoa(d.port))
}

func main() {
	log.SetFlags(log.LstdFlags)
	nkw := loadKeywords()
	ndoh, nip := loadDohLists()
	log.Printf("doh lists: dom=%d ip=%d", ndoh, nip)
	ndl, nua, next, nbsf := loadDLLists()
	log.Printf("dl lists: dom=%d ua=%d ext=%d bsf=%d", ndl, nua, next, nbsf)
	os.MkdirAll(filepath.Dir(gateLogPath), 0755)
	var err error
	statFile, err = os.OpenFile(statsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("warn: stats %s: %v", statsPath, err)
	}
	gateLogFile, err = os.OpenFile(gateLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("warn: gate log %s: %v", gateLogPath, err)
	}
	// 统一事件流：失败只记 stats，不影响转发（与 gate.log/stats.tsv 共存）。
	_ = initEvents()
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", listenAddr, err)
	}
	log.Printf("wxdet-gate listening on %s (passSocks=%s proxySocks=%s kws=%d peek=%s)", listenAddr, passSocks, proxySocks, nkw, peekWait)
	go watchKeywords()
	if udpListenAddr != "" && udpListenAddr != "off" {
		go serveUDP()
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				return
			}
			log.Printf("accept: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go handleConn(c)
	}
}

func writeStat(key string, val int) {
	if statFile == nil {
		return
	}
	ioMu.Lock()
	fmt.Fprintf(statFile, "%d\t%s\t%d\n", time.Now().Unix(), key, val)
	ioMu.Unlock()
}

func logGate(src string, od dstAddr, verdict, reason string, b []byte) {
	if gateLogFile == nil {
		return
	}
	hex := fmt.Sprintf("%x", b)
	if len(b) > 24 {
		hex = fmt.Sprintf("%x", b[:24]) + ".."
	}
	ioMu.Lock()
	fmt.Fprintf(gateLogFile, "{\"ts\":%d,\"src\":%q,\"dst\":%q,\"verdict\":%q,\"reason\":%q,\"first\":%q}\n",
		time.Now().Unix(), src, od.String(), verdict, reason, hex)
	ioMu.Unlock()
}

func originalDst(c *net.TCPConn) (dstAddr, error) {
	sc, err := c.SyscallConn()
	if err != nil {
		return dstAddr{}, err
	}
	return origDstFromSC(sc) // 实现见 udp.go（TCP/UDP 共用）
}

func shouldPeekMore(b0 byte) bool {
	if b0 == 0x02 {
		return true
	}
	switch b0 {
	case 0x15, 0x16, 0x17, 0x19:
		return true
	}
	return false
}

// peekClient 阻塞读客户端首包（最多 len(buf)，返回字节数；调用后清 deadline）。
// :80 用 opportunistic 短读（peekWait80，默认 80ms）——HTTP 客户端建连即发
// 请求，局域网内数据必在途，读到即走正常 classify（dl_direct/bsf_direct/
// http_plain 可达）；静默/超时/空/非 HTTP 则 n=0 落 proxy/port80（fail-closed）。
// 443/奇端口沿用 peekWait（要载荷做 TLS/HTTP 判定，省不掉）。
func peekClient(c net.Conn, buf []byte, port int) int {
	wait := peekWait
	if port == 80 {
		wait = peekWait80
	}
	c.SetReadDeadline(time.Now().Add(wait))
	defer c.SetReadDeadline(time.Time{})
	n := 0
	if m, err := c.Read(buf); m > 0 {
		n = m
		if port != 80 && n == 1 && shouldPeekMore(buf[0]) {
			c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			if k, _ := c.Read(buf[n:]); k > 0 {
				n += k
			}
		}
	} else if err != nil && !isTimeout(err) {
		// client closed without data; fall through with n=0 (default path)
	}
	return n
}

// DoH 服务端域名正则（2026-09 实测名单）：覆盖 Google/Cloudflare/阿里/DNSPod/360
// 及通用加密 DNS 命名（dns./doh./dot. 前缀、-dns 后缀、alidns 等），边界限定避免
// 误伤（如 madnson、dnspod.cn 主站、ddns 动态域名均不命中）。
var dohSNIRe = regexp.MustCompile(`(?i)(^|\.)(dns|doh|dot)[.-]|cloudflare-dns|alidns|dns\.google|google-public-dns|doh\.pub|dot\.pub|dns\.pub|doh\.360|dot\.360|quad9|opendns|dns-over-https|securedns|one\.one\.one\.one|1dot1dot1dot1|dns64`)

// proxy 端点记忆（静默复用连接收敛）：已实锤 proxy 的非 80 (ip:port)
// 在 peek 为空时复用原 reason 判 proxy；未知端点仍 default fail-open。
// 只记不阻：proxy 出口可达时流量照走，仅绕路不断流；TTL 12h，cap 2048。
var (
	proxyMemMu  sync.Mutex
	proxyMem    = map[string]proxyMemEnt{}
	proxyMemCap = 2048
	proxyMemTTL = int64(12 * 3600)
)

type proxyMemEnt struct {
	reason string
	ts     int64
}

func proxyMemKey(od dstAddr) string { return od.ip.String() + ":" + strconv.Itoa(od.port) }

func proxyMemStore(od dstAddr, reason string) {
	if od.port == 80 {
		return // :80 静默本就 port80 fail-closed，不占记忆
	}
	now := time.Now().Unix()
	proxyMemMu.Lock()
	defer proxyMemMu.Unlock()
	if len(proxyMem) >= proxyMemCap {
		for k, e := range proxyMem {
			if now-e.ts > proxyMemTTL {
				delete(proxyMem, k)
			}
		}
		if len(proxyMem) >= proxyMemCap {
			proxyMem = map[string]proxyMemEnt{}
		}
	}
	proxyMem[proxyMemKey(od)] = proxyMemEnt{reason: reason, ts: now}
}

func proxyMemLookup(od dstAddr) (string, bool) {
	proxyMemMu.Lock()
	defer proxyMemMu.Unlock()
	e, ok := proxyMem[proxyMemKey(od)]
	if !ok {
		return "", false
	}
	if time.Now().Unix()-e.ts > proxyMemTTL {
		delete(proxyMem, proxyMemKey(od))
		return "", false
	}
	return e.reason, true
}

// 公网解析器 IP：443 打到这些即 IP 字面 DoH。
var dnsResolverIPs = map[string]bool{
	"223.5.5.5": true, "223.6.6.6": true, "119.29.29.29": true,
	"1.12.12.12": true, "120.53.53.53": true, "180.76.76.76": true,
	"114.114.114.114": true, "114.114.115.115": true,
	"101.226.4.6": true, "218.30.118.6": true, "123.125.81.6": true, "140.207.198.6": true,
	"8.8.8.8": true, "8.8.4.4": true, "1.1.1.1": true, "1.0.0.1": true,
	"9.9.9.9": true, "208.67.222.222": true, "208.67.220.220": true,
}

// DoH 封堵名单（dibdot 全量 + Sekhan，去重 1923 域 / 3514 IP，热加载）：
// 域名精确或子域后缀命中，IP 精确命中。单文件缺失保留旧快照；IP 以内置种子为基线只增不减。
var (
	dohDomPath = envStr("WD_DOH_DOM_FILE", "/etc/wxdet/doh-domains.txt")
	dohIPPath  = envStr("WD_DOH_IP_FILE", "/etc/wxdet/doh-ips.txt")
	dohDoms    atomic.Value // map[string]bool
	dohIPs     atomic.Value // map[string]bool
	dohMu      sync.Mutex
	dohMarks   = map[string]fileMark{}
)

type fileMark struct {
	mod  time.Time
	size int64
}

func init() {
	seed := map[string]bool{}
	for k := range dnsResolverIPs {
		seed[k] = true
	}
	dohIPs.Store(seed)
}

func parseLineSet(b []byte) map[string]bool {
	m := map[string]bool{}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(ln, ".")))
		if f := strings.Fields(ln); len(f) == 2 && (f[0] == "0.0.0.0" || f[0] == "127.0.0.1" || f[0] == "::") {
			ln = f[1]
		} else if len(f) != 1 {
			continue
		}
		if ln != "" && !strings.HasPrefix(ln, "#") {
			m[ln] = true
		}
	}
	return m
}

func dohDomSnapshot() map[string]bool {
	if v := dohDoms.Load(); v != nil {
		return v.(map[string]bool)
	}
	return nil
}

func dohIPSnapshot() map[string]bool {
	if v := dohIPs.Load(); v != nil {
		return v.(map[string]bool)
	}
	return nil
}

// matchDohDomain 精确或子域后缀命中（可单测）。
func matchDohDomain(sni string, set map[string]bool) bool {
	s := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(sni), "."))
	if s == "" {
		return false
	}
	if set[s] {
		return true
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '.' && set[s[i+1:]] {
			return true
		}
	}
	return false
}

func dohDomainHit(sni string) bool { return matchDohDomain(sni, dohDomSnapshot()) }
func dohIPHit(ip string) bool      { return dohIPSnapshot()[ip] }

func noteDohMark(path string) {
	if fi, err := os.Stat(path); err == nil {
		dohMu.Lock()
		dohMarks[path] = fileMark{mod: fi.ModTime(), size: fi.Size()}
		dohMu.Unlock()
	}
}

// loadDohLists 读域名/IP 名单并原子替换（IP 合并内置种子；单文件缺失保留旧快照）。
func loadDohLists() (nd, ni int) {
	if b, err := os.ReadFile(dohDomPath); err == nil {
		m := parseLineSet(b)
		dohDoms.Store(m)
		nd = len(m)
		noteDohMark(dohDomPath)
	} else {
		log.Printf("warn: doh dom file %s: %v", dohDomPath, err)
	}
	m := map[string]bool{}
	for k := range dnsResolverIPs {
		m[k] = true
	}
	if b, err := os.ReadFile(dohIPPath); err == nil {
		for k := range parseLineSet(b) {
			m[k] = true
		}
		noteDohMark(dohIPPath)
	} else {
		log.Printf("warn: doh ip file %s: %v", dohIPPath, err)
	}
	dohIPs.Store(m)
	ni = len(m)
	return nd, ni
}

func checkDohReload() bool {
	changed := false
	dohMu.Lock()
	for _, p := range []string{dohDomPath, dohIPPath} {
		if fi, err := os.Stat(p); err == nil {
			if mk, ok := dohMarks[p]; !ok || fi.ModTime().After(mk.mod) || fi.Size() != mk.size {
				changed = true
			}
		}
	}
	dohMu.Unlock()
	if !changed {
		return false
	}
	nd, ni := loadDohLists()
	log.Printf("doh reloaded: dom=%d ip=%d", nd, ni)
	writeStat("gate_doh_reload", 1)
	return true
}

// 下载站/下载器/BSF 名单（30s 热加载，见 lists/）：
// dl-domains 精确/子域匹配记 pass/dl_direct；dl-ua 为 UA token 子串匹配记
// pass/dl_ua；dl-ext 为 URL 后缀匹配记 pass/dl_ext；bsf-domains 精确/子域匹配
// 记 pass/bsf_direct。单文件缺失保留旧快照。
var (
	dlDomPath  = envStr("WD_DL_DOM_FILE", "/etc/wxdet/dl-domains.txt")
	dlUAPath   = envStr("WD_DL_UA_FILE", "/etc/wxdet/dl-ua.txt")
	dlExtPath  = envStr("WD_DL_EXT_FILE", "/etc/wxdet/dl-ext.txt")
	bsfDomPath = envStr("WD_BSF_DOM_FILE", "/etc/wxdet/bsf-domains.txt")
	dlDoms     atomic.Value // map[string]bool
	dlUAs      atomic.Value // []string
	dlExts     atomic.Value // []string
	bsfDoms    atomic.Value // map[string]bool
	dlMu       sync.Mutex
	dlMarks    = map[string]fileMark{}
)

// 逃生文件：存在即明文通判（http_plain）+ 80 短路（port80）全部回退 pass
// （reason 拼写不变，只换 verdict）；关键词/下载站/BSF/下载器特征规则照旧。
var noPlainProxyPath = envStr("WD_NO_PLAINHTTP_PROXY", "/etc/wxdet/no-plainhttp-proxy")

func noPlainProxy() bool {
	_, err := os.Stat(noPlainProxyPath)
	return err == nil
}

func dlDomSnapshot() map[string]bool {
	if v := dlDoms.Load(); v != nil {
		return v.(map[string]bool)
	}
	return nil
}

func bsfDomSnapshot() map[string]bool {
	if v := bsfDoms.Load(); v != nil {
		return v.(map[string]bool)
	}
	return nil
}

func dlUASnapshot() []string {
	if v := dlUAs.Load(); v != nil {
		return v.([]string)
	}
	return nil
}

func dlExtSnapshot() []string {
	if v := dlExts.Load(); v != nil {
		return v.([]string)
	}
	return nil
}

func dlDomainHit(host string) bool  { return matchDohDomain(host, dlDomSnapshot()) }
func bsfDomainHit(host string) bool { return matchDohDomain(host, bsfDomSnapshot()) }

// dlUAHit 下载器 UA token 子串命中（大小写不敏感）。
func dlUAHit(ua string) bool {
	s := strings.ToLower(ua)
	for _, tok := range dlUASnapshot() {
		if tok != "" && strings.Contains(s, tok) {
			return true
		}
	}
	return false
}

// dlExtHit 二进制/媒体 URL 后缀命中（大小写不敏感，?query/#frag 剥离；
// tar.gz 类多段以后缀全串匹配）。
func dlExtHit(path string) bool {
	p := strings.ToLower(path)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	for _, e := range dlExtSnapshot() {
		e = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(e)), ".")
		if e == "" {
			continue
		}
		if strings.HasSuffix(p, "."+e) {
			return true
		}
	}
	return false
}

func noteDLMark(path string) {
	if fi, err := os.Stat(path); err == nil {
		dlMu.Lock()
		dlMarks[path] = fileMark{mod: fi.ModTime(), size: fi.Size()}
		dlMu.Unlock()
	}
}

// loadDLLists 读四个名单并原子替换（单文件缺失保留旧快照）。
func loadDLLists() (nd, nu, ne, nb int) {
	if b, err := os.ReadFile(dlDomPath); err == nil {
		m := parseLineSet(b)
		dlDoms.Store(m)
		nd = len(m)
		noteDLMark(dlDomPath)
	} else {
		log.Printf("warn: dl dom file %s: %v", dlDomPath, err)
	}
	if b, err := os.ReadFile(dlUAPath); err == nil {
		list := parseKeywords(b)
		dlUAs.Store(list)
		nu = len(list)
		noteDLMark(dlUAPath)
	} else {
		log.Printf("warn: dl ua file %s: %v", dlUAPath, err)
	}
	if b, err := os.ReadFile(dlExtPath); err == nil {
		list := parseKeywords(b)
		dlExts.Store(list)
		ne = len(list)
		noteDLMark(dlExtPath)
	} else {
		log.Printf("warn: dl ext file %s: %v", dlExtPath, err)
	}
	if b, err := os.ReadFile(bsfDomPath); err == nil {
		m := parseLineSet(b)
		bsfDoms.Store(m)
		nb = len(m)
		noteDLMark(bsfDomPath)
	} else {
		log.Printf("warn: bsf dom file %s: %v", bsfDomPath, err)
	}
	return nd, nu, ne, nb
}

func checkDLReload() bool {
	changed := false
	dlMu.Lock()
	for _, p := range []string{dlDomPath, dlUAPath, dlExtPath, bsfDomPath} {
		if fi, err := os.Stat(p); err == nil {
			if mk, ok := dlMarks[p]; !ok || fi.ModTime().After(mk.mod) || fi.Size() != mk.size {
				changed = true
			}
		}
	}
	dlMu.Unlock()
	if !changed {
		return false
	}
	nd, nu, ne, nb := loadDLLists()
	log.Printf("dl reloaded: dom=%d ua=%d ext=%d bsf=%d", nd, nu, ne, nb)
	writeStat("gate_dl_reload", 1)
	return true
}

func classify(od dstAddr, b []byte) (string, string) {
	// DoH-IP 直连封堵：HTTPS(443) 打到名单 IP 即 DoH（IP 字面，无 SNI 可看）。名单=文件+内置种子。
	if od.port == 443 && dohIPHit(od.ip.String()) {
		return "block", "dns_block"
	}
	if len(b) >= 2 && b[1] == 0xF1 {
		switch b[0] {
		case 0x15, 0x16, 0x17, 0x19:
			return "proxy", "mmtls"
		}
	}
	if len(b) >= 1 && b[0] == 0x02 {
		return "proxy", "oicq"
	}
	if len(b) >= 8 && b[2] == 0x08 && b[3] == 0x00 &&
		(b[4] == 0x06 || b[4] == 0x07 || b[4] == 0x08) && b[5] == 0x06 && b[6] == 0x07 && b[7] == 0x62 {
		// MSF/Beacon framing（全端口）：u16be 首部为包长自描述，08 00 为 OICQ
		// 08xx 命令族，XX 06 07 62 为同族常量（XX∈{06,07,08} 三值等价）。
		// peek 最多截前 1024B，大包恒被截断，故用 decl>=len(b) 而非相等；
		// 6 固定字节 + 长度自洽，碰撞≈0。
		if decl := int(binary.BigEndian.Uint16(b[0:2])); decl >= len(b) {
			return "proxy", "msf"
		}
	}
	if len(b) >= 20 && b[2] == 0x08 && b[3] == 0x00 &&
		string(b[7:20]) == "TYPE_COMPRESS" {
		// MSF 家族 TYPE_COMPRESS 变种（全端口）：QQ Beacon 上报的一种帧形态，
		// 08 00 命令族 + offset 7 起 13 字节 ASCII 魔串 + 同款 decl>=len 自洽。
		if decl := int(binary.BigEndian.Uint16(b[0:2])); decl >= len(b) {
			return "proxy", "msf"
		}
	}
	if len(b) >= 16 && b[4] == 0x01 &&
		b[5] == 0x33 && b[6] == 0x52 && b[7] == 0x39 &&
		b[8] == 0x00 && b[9] == 0x00 && b[10] == 0x00 && b[11] == 0x00 &&
		b[12] == 0x04 && string(b[13:16]) == "MSF" {
		// MSF 家族 u32be 变种（全端口）：u32be 包长 + 01 33 52 39 + u32be 0 +
		// 04 "MSF"。实测 QQ 在 443/8080/14000 用此帧头（u16be 分支恒 miss，
		// 会全部漏过）。u32 decl 语义不明（21 vs peek 长度对不上），故不用
		// decl 自洽，纯靠 12 固定字节（≈96bit）定性，碰撞可忽略。
		return "proxy", "msf"
	}
	if len(b) >= 8 && b[0] == 0x00 && b[1] == 0x00 && b[2] == 0x00 &&
		b[4] == 0x00 && b[5] == 0x00 && b[6] == 0x00 && b[7] == 0xc8 {
		// MSF 家族全零头变种（全端口）：实测 QQ 在 8080 用此帧头
		//（00 00 00 1a/20 00 00 00 c8，疑似 TLV：len + type=200），
		// u16be/u32be/TYPE_COMPRESS 分支均 miss 会漏过。
		// 7 固定字节（≈56bit）定性，碰撞可忽略。
		return "proxy", "msf"
	}
	if len(b) >= 8 && b[0] == 0x08 && b[2] == 0x08 && b[3] == 0x00 &&
		b[4] == 0x07 && b[5] == 0x06 && b[6] == 0x0c && b[7] == 0x73 {
		// MSF 家族 0806 变种（全端口）：实测腾讯游戏鉴权在 8081 用此帧头
		//（08 XX 08 00 07 06 0c 73，XX 随包变化）。
		// 与 u16be 分支仅 b[6]/b[7] 之差（0c 73 vs 07 62），独立分支精确
		// 匹配。b[0] 为常量 0x08 而非长度字节，故不用 decl 自洽，
		// 纯靠 7 固定字节（≈56bit）定性，碰撞可忽略。
		return "proxy", "msf"
	}
	if len(b) >= 12 && b[2] == 0x00 && b[3] == 0x01 &&
		b[6] == 0x21 && b[7] == 0x12 && b[8] == 0xa4 && b[9] == 0x42 {
		// STUN-over-TCP 媒体腿（全端口）：u16be 首部为后随长度（2 字节前缀），
		// 00 01 为 Binding Request，21 12 a4 42 为 STUN magic cookie。
		// 微信视频/直播（tlivesource 信令配套）实测；注意非腾讯 App 的 TCP STUN
		// 也会命中，误伤代价仅为绕路（proxy 出口仍可达），上线后看 stun verdict
		// 的目的分布复核。
		decl := int(binary.BigEndian.Uint16(b[0:2]))
		stunLen := int(binary.BigEndian.Uint16(b[4:6]))
		if decl == 20+stunLen && decl+2 >= len(b) {
			return "proxy", "stun"
		}
	}
	if len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 {
		if sni := tlsSNI(b); sni != "" {
			// DoH 域名封堵（政策）：名单精确/子域命中即丢；未知模式再走正则兜底。
			if dohDomainHit(sni) {
				return "block", "dns_block"
			}
			// 未知加密 DNS 模式走正则兜底。
			if dohSNIRe.MatchString(sni) {
				return "block", "dns_block"
			}
		}
		// TLS 全端口转交：非 DoH 的 TLS 一律 pass/tls_direct（转交下游入口）；
		// 手机 App 基本不用 h2c，TLS 误判不考虑。
		return "pass", "tls_direct"
	}
	// 判定顺序：下载站 Host（pass/dl_direct，bulk 优先于关键词）→ UA/HTTP
	// 关键词（腾讯身份优先于下载器特征：aweme 等命中即 proxy，短视频流不因
	// .flv 后缀被 dl_ext 抢走）→ 下载器特征 dl_range → dl_ua → dl_ext →
	// BSF Host（pass/bsf_direct，http_plain 之前）→ 明文通判 http_plain →
	// 80 短路 port80 → pass/default。
	isH := isHTTPRequest(b)
	if isH {
		if h := httpHost(b); h != "" && dlDomainHit(h) {
			return "pass", "dl_direct"
		}
	}
	// UA 头匹配（全端口，不受 80/8080 门限约束）：UA 是客户端自报身份，
	// 包名级 token（aweme/MicroMessenger）误报≈0，专治 Host 为 IP 的形态。
	if ua := httpUserAgent(b); ua != "" && kwMatch(ua) {
		return "proxy", "http_ua_kw"
	}
	// 明文 HTTP 关键词（全端口，不设端口门）：方法行语义校验挡随机二进制。
	// fail-closed（守门员策略）：识别到的包只许进 proxy，proxy 不通即断流，
	// 绝不回退 pass。宁断不错放。
	if r := httpKeyword(b); r != "" {
		return "proxy", r
	}
	if isH {
		// 下载器特征三层（请求侧信号；响应侧 206/Content-Length gate 看不到，
		// 不做）：Range 头（多线程/断点续传/seek 最强信号）→ 下载器 UA →
		// 二进制/媒体 URL 后缀。Range/UA/后缀一般在首包前 600B 内，超长
		// Cookie 挤出 1024B peek 窗则 miss，安全落回 http_plain 进 proxy。
		if hasRangeHeader(b) {
			return "pass", "dl_range"
		}
		if ua := httpUserAgent(b); ua != "" && dlUAHit(ua) {
			return "pass", "dl_ua"
		}
		if p := httpPath(b); p != "" && dlExtHit(p) {
			return "pass", "dl_ext"
		}
		// BSF 运营商信令 direct-by-policy（http_plain 之前，不随逃生回滚）。
		if h := httpHost(b); h != "" && bsfDomainHit(h) {
			return "pass", "bsf_direct"
		}
		// 明文 HTTP 通判：方法行合法、无关键词、非下载站/BSF。逃生文件存在
		// 即回退 pass（reason 拼写不变）。
		if noPlainProxy() {
			return "pass", "http_plain"
		}
		return "proxy", "http_plain"
	}
	// 80 短路（fail-closed）：80 非 HTTP/空载荷无条件进 proxy；逃生回退 pass。
	if od.port == 80 {
		if noPlainProxy() {
			return "pass", "port80"
		}
		return "proxy", "port80"
	}
	// 8000-9000 兜底：魔数/TLS/关键词/下载特征已在上游返回，
	// 落到这里的非 TLS 私有协议残渣一律 proxy（fail-closed，无视逃生文件，
	// reason 复用 default 以保持 reason 字符串稳定）。
	if od.port >= 8000 && od.port <= 9000 {
		return "proxy", "default"
	}
	return "pass", "default"
}

func kwMatch(s string) bool {
	s = strings.ToLower(s)
	for _, kw := range kwSnapshot() {
		if kw != "" && strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// parseKeywords 解析关键词文件（小写、去空行/# 注释）。
func parseKeywords(b []byte) []string {
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.ToLower(strings.TrimSpace(ln))
		if ln != "" && !strings.HasPrefix(ln, "#") {
			out = append(out, ln)
		}
	}
	return out
}

func setKeywords(list []string) {
	kws.Store(list)
}

func kwSnapshot() []string {
	if v := kws.Load(); v != nil {
		return v.([]string)
	}
	return nil
}

// loadKeywords 读取关键词文件并原子替换内存快照，返回条数。
func loadKeywords() int {
	b, err := os.ReadFile(kwPath)
	if err != nil {
		log.Printf("warn: kw file %s: %v", kwPath, err)
		return 0
	}
	list := parseKeywords(b)
	setKeywords(list)
	if fi, serr := os.Stat(kwPath); serr == nil {
		kwMu.Lock()
		kwModTime = fi.ModTime()
		kwSize = fi.Size()
		kwMu.Unlock()
	}
	return len(list)
}

// checkKwReload 文件 mtime/size 变化则重载，返回是否发生重载（可单测）。
func checkKwReload() bool {
	fi, err := os.Stat(kwPath)
	if err != nil {
		return false
	}
	kwMu.Lock()
	changed := fi.ModTime().After(kwModTime) || fi.Size() != kwSize
	kwMu.Unlock()
	if !changed {
		return false
	}
	n := loadKeywords()
	log.Printf("kw reloaded: %s (%d keywords)", kwPath, n)
	writeStat("gate_kw_reload", 1)
	return true
}

// watchKeywords 周期性轮询关键词文件（WD_KW_POLL_SEC，<=0 关闭），变化即热加载，不断连接。
func watchKeywords() {
	if kwPollSec <= 0 {
		return
	}
	t := time.NewTicker(time.Duration(kwPollSec) * time.Second)
	defer t.Stop()
	for range t.C {
		checkKwReload()
		checkDohReload()
		checkDLReload()
	}
}

func tlsSNI(b []byte) string {
	if len(b) < 9 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01 {
		return ""
	}
	p := 9 + 34
	if len(b) < p+1 {
		return ""
	}
	p += int(b[p]) + 1
	if len(b) < p+2 {
		return ""
	}
	p += 2 + (int(b[p])<<8 | int(b[p+1]))
	if len(b) < p+1 {
		return ""
	}
	p += int(b[p]) + 1
	if len(b) < p+2 {
		return ""
	}
	end := p + 2 + (int(b[p])<<8 | int(b[p+1]))
	if end > len(b) {
		end = len(b)
	}
	p += 2
	for p+4 <= end {
		et := int(b[p])<<8 | int(b[p+1])
		el := int(b[p+2])<<8 | int(b[p+3])
		p += 4
		if p+el > end {
			break
		}
		if et == 0 && el >= 5 {
			nameLen := int(b[p+3])<<8 | int(b[p+4])
			if p+5+nameLen <= p+el {
				return string(b[p+5 : p+5+nameLen])
			}
		}
		p += el
	}
	return ""
}

// httpMethods 方法行语义校验表：h2c 的 PRI * HTTP/2.0 不在表里，会穿过
// 通判走 pass/default（手机 App 基本不用 h2c，记一笔不修）。
var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "DELETE ", "PATCH ", "CONNECT "}

// isHTTPRequest 方法行语义校验：首行以标准请求方法开头，挡随机二进制。
func isHTTPRequest(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	line := string(b)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	up := strings.ToUpper(line)
	for _, m := range httpMethods {
		if strings.HasPrefix(up, m) {
			return true
		}
	}
	return false
}

// httpFirstLine 首行（去尾 \r）。
func httpFirstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, "\r")
}

// httpHost 提取 Host 头（小写、去端口、去尾点；无头返回 ""，IP 字面原样返回）。
func httpHost(b []byte) string {
	lower := strings.ToLower(string(b))
	i := strings.Index(lower, "\nhost:")
	if i < 0 {
		return ""
	}
	rest := lower[i+6:]
	if j := strings.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[:j]
	}
	host := strings.TrimSpace(strings.TrimSuffix(rest, "\r"))
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}
	return strings.TrimSuffix(hostOnly, ".")
}

// httpPath 提取请求路径（方法行第二段；绝对 URL 原样返回，后缀匹配照常工作）。
func httpPath(b []byte) string {
	parts := strings.SplitN(strings.TrimSpace(httpFirstLine(b)), " ", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// hasRangeHeader 是否带 Range: 头（断点续传/音视频 seek 信号；调用方已保证 isHTTPRequest）。
func hasRangeHeader(b []byte) bool {
	return strings.Contains(strings.ToLower(string(b)), "\nrange:")
}

// httpUserAgent 提取 HTTP 请求的 User-Agent 头值（小写去首尾空格）。
// 要求载荷以标准请求方法开头，过滤随机二进制偶然含头字样的情况。
func httpUserAgent(b []byte) string {
	if len(b) < 14 {
		return ""
	}
	if !isHTTPRequest(b) {
		return ""
	}
	lower := strings.ToLower(string(b))
	i := strings.Index(lower, "\nuser-agent:")
	if i < 0 {
		return ""
	}
	rest := lower[i+12:]
	if j := strings.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

func httpKeyword(b []byte) string {
	// 关键词专用（通判 http_plain 由 classify 后置步骤处理，不在此返回，
	// 否则 dl_range/dl_ua/dl_ext/BSF 会被短路）：域名 Host 只判 host kw
	// （无 kw 返回 ""，由通判接住进 proxy）；IP 字面/无 Host 判首行 path kw。
	if !isHTTPRequest(b) {
		return ""
	}
	line := httpFirstLine(b)
	hostOnly := httpHost(b)
	if hostOnly != "" && net.ParseIP(hostOnly) == nil {
		if kwMatch(hostOnly) {
			return "http_host_kw"
		}
		return ""
	}
	if kwMatch(line) {
		return "http_path_kw"
	}
	return ""
}

func socks5Dial(proxy string, od dstAddr, bindIP net.IP, bindPort int) (*net.TCPConn, error) {
	ip4 := od.ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("non-ipv4 dst %s", od.ip)
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	if bindIP != nil && bindPort > 0 {
		d.LocalAddr = &net.TCPAddr{IP: bindIP, Port: bindPort}
	}
	conn, err := d.Dial("tcp", proxy)
	if err != nil && d.LocalAddr != nil {
		d.LocalAddr = nil
		conn, err = d.Dial("tcp", proxy)
	}
	if err != nil {
		return nil, err
	}
	tc := conn.(*net.TCPConn)
	tc.SetNoDelay(true)
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	fail := func(e error) (*net.TCPConn, error) {
		tc.Close()
		return nil, e
	}
	if _, err := tc.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(tc, r); err != nil {
		return fail(err)
	}
	if r[0] != 5 || r[1] != 0 {
		return fail(fmt.Errorf("socks greet %x", r))
	}
	req := []byte{5, 1, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], byte(od.port >> 8), byte(od.port)}
	if _, err := tc.Write(req); err != nil {
		return fail(err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(tc, hdr); err != nil {
		return fail(err)
	}
	if hdr[1] != 0 {
		return fail(fmt.Errorf("socks rep=%d", hdr[1]))
	}
	var skip int
	switch hdr[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(tc, lb); err != nil {
			return fail(err)
		}
		skip = int(lb[0])
	default:
		return fail(fmt.Errorf("socks atyp=%d", hdr[3]))
	}
	if _, err := io.CopyN(io.Discard, tc, int64(skip+2)); err != nil {
		return fail(err)
	}
	tc.SetDeadline(time.Time{})
	return tc, nil
}

func relay(a, b *net.TCPConn, src string, od dstAddr, verdict, reason string, start time.Time) {
	// 计数 writer 包两端：cwUp 计 client->server（up_B），cwDown 计反向（down_B）。
	// closer 近似：先返回的 Copy 其读端即关闭方（up 先返=>client 先关，down 先返=>server 先关）。
	var upB, downB int64
	cwUp := &countWriter{w: b, n: &upB}
	cwDown := &countWriter{w: a, n: &downB}
	done := make(chan string, 2)
	go func() {
		io.Copy(cwUp, a)
		b.CloseWrite()
		done <- "up"
	}()
	go func() {
		io.Copy(cwDown, b)
		a.CloseWrite()
		done <- "down"
	}()
	first := <-done
	closer := "server"
	if first == "up" {
		closer = "client"
	}
	<-done
	durMs := time.Since(start).Milliseconds()
	emitCloseEvent("tcp", src, od, verdict, reason, durMs, upB, downB, closer)
}

// passBindAddr 让发往下游普通入口的连接带上可还原的源地址
// （127.0.0.<客户端末位>:<客户端源端口>），便于在下游连接日志里关联回原始客户端。
func passBindAddr(src net.Addr) (net.IP, int) {
	host, portStr, err := net.SplitHostPort(src.String())
	if err != nil {
		return nil, 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return nil, 0
	}
	ip := net.ParseIP(host).To4()
	if ip == nil || ip[0] != 192 || ip[1] != 168 {
		return nil, 0
	}
	last := int(ip[3])
	if last < 2 || last > 254 {
		return nil, 0
	}
	return net.IPv4(127, 0, 0, byte(last)), port
}

func handleConn(raw net.Conn) {
	defer raw.Close()
	tc, ok := raw.(*net.TCPConn)
	if !ok {
		return
	}
	tc.SetNoDelay(true)
	id := atomic.AddUint64(&connSeq, 1)
	src := raw.RemoteAddr().String()
	start := time.Now()
	od, err := originalDst(tc)
	if err != nil || od.port == 0 {
		writeStat("gate_origdst_err", 1)
		log.Printf("#%d %s origdst: %v", id, src, err)
		return
	}
	buf := make([]byte, 1024)
	// opportunistic peek：:80 短读（有数据即判正常 classify，无则 port80）；
	// 443/奇端口全量 peek（TLS/HTTP 判定省不掉）。
	n := peekClient(tc, buf, od.port)

	verdict, reason := classify(od, buf[:n])
	if n == 0 && od.port != 80 && verdict != "proxy" && verdict != "block" {
		// 非 80 静默连接查 proxy 端点记忆，命中则复用原 reason 进 proxy
		// （fail-closed）；未知端点仍 default fail-open（如 5438 类保活）。
		if rsn, ok := proxyMemLookup(od); ok {
			verdict, reason = "proxy", rsn
			writeStat("gate_silentreuse", 1)
		}
	}
	bindIP, bindPort := passBindAddr(raw.RemoteAddr())
	emitOpen("tcp", src, od, verdict, reason)
	var up *net.TCPConn
	if verdict == "block" {
		// 政策阻断（DoH 等）：直接断流，不建上游。
		writeStat("gate_block", 1)
		logGate(src, od, "block", reason, buf[:n])
		return
	}
	if verdict == "proxy" {
		// fail-closed（守门员策略）：识别到的包只许进代理——拨号目标是下游
		// 敏感/加密入口（proxySocks，可用 WD_PROXY_SOCKS 覆盖）；下游不可用
		// 才断流（err/*_proxy_fail），绝不回退直连。若下游支持拨号超时重试，
		// 可在同一请求内重试一次（可选）。非 80 端点同时记入 proxy 端点记忆，
		// 供后续静默复用连接收敛。
		proxyMemStore(od, reason)
		up, err = socks5Dial(proxySocks, od, nil, 0)
		if err != nil {
			writeStat("gate_proxy_fail", 1)
			writeStat("gate_dial_err", 1)
			logGate(src, od, "err", reason+"_proxy_fail", buf[:n])
			emitErrorEvent("tcp", src, od, "err", reason+"_proxy_fail", err.Error())
			log.Printf("#%d %s -> %s proxy dial fail (fail-closed): %v", id, src, od, err)
			return
		}
	} else {
		up, err = socks5Dial(passSocks, od, bindIP, bindPort)
	}
	if err != nil {
		writeStat("gate_dial_err", 1)
		logGate(src, od, "err", reason, buf[:n])
		emitErrorEvent("tcp", src, od, "err", reason, err.Error())
		log.Printf("#%d %s -> %s dial: %v", id, src, od, err)
		return
	}
	defer up.Close()
	if n > 0 {
		if _, err := up.Write(buf[:n]); err != nil {
			writeStat("gate_write_err", 1)
			emitErrorEvent("tcp", src, od, "err", reason, err.Error())
			return
		}
	}
	writeStat("gate_conn", 1)
	writeStat("gate_"+verdict, 1)
	writeStat("gate_rsn_"+reason, 1)
	logGate(src, od, verdict, reason, buf[:n])
	relay(tc, up, src, od, verdict, reason, start)
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
