package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const soOriginalDst = 80

// defProxySocks = 下游代理的 socks 入站；gate 判 proxy 的流量经它进入代理，由代理侧做故障转移。
const defProxySocks = "127.0.0.1:10811"

var (
	listenAddr  = envStr("WD_LISTEN", "0.0.0.0:12347")
	passSocks   = envStr("WD_PASS_SOCKS", "127.0.0.1:18081")
	proxySocks  = envStr("WD_PROXY_SOCKS", defProxySocks)
	gateLogPath = envStr("WD_LOG", "/tmp/wxdet/gate.log")
	statsPath   = envStr("WD_STATS", "/tmp/wxdet/stats.tsv")
	peekWait    = time.Duration(envInt("WD_PEEK_MS", 400)) * time.Millisecond
	peekWait80  = time.Duration(envInt("WD_PEEK80_MS", 80)) * time.Millisecond
	kwPollSec   = envInt("WD_KW_POLL_SEC", 30)
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
	ndl, nua, next, nq := loadDLLists()
	log.Printf("dl lists: dom=%d ua=%d ext=%d query=%d", ndl, nua, next, nq)
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
	log.Printf("wxdet-gate listening on %s (proxy=%s pass=%s peek=%s)", listenAddr, proxySocks, passSocks, peekWait)
	go watchDLLists()
	go startLedgerFlush(60 * time.Second)
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

// writeStat64 给字节/时长这类量用。arm64 上 int 已是 64 位，单独一个函数是为了
// 显式表达「这里可能是 int64 量级」，避免将来换 32 位平台时静默截断。
func writeStat64(key string, val int64) {
	if statFile == nil {
		return
	}
	ioMu.Lock()
	fmt.Fprintf(statFile, "%d\t%s\t%d\n", time.Now().Unix(), key, val)
	ioMu.Unlock()
}

func logGate(proto, src string, od dstAddr, verdict, reason string, b []byte) {
	if gateLogFile == nil {
		return
	}
	// P2-8：只渲染要落盘的 24B（旧版先对整段 1024B Sprintf 再截断，白烧 CPU/GC）。
	hx := b
	if len(hx) > 24 {
		hx = hx[:24]
	}
	hex := fmt.Sprintf("%x", hx)
	if len(b) > 24 {
		hex += ".."
	}
	ioMu.Lock()
	fmt.Fprintf(gateLogFile, "{\"ts\":%d,\"proto\":%q,\"src\":%q,\"dst\":%q,\"verdict\":%q,\"reason\":%q,\"first\":%q}\n",
		time.Now().Unix(), proto, src, od.String(), verdict, reason, hex)
	ioMu.Unlock()
}

// logGateErr err 行专用：比 logGate 多一个截断到 64B 的 detail（拨号失败原因等）。
// 背景：proxy burst / pass i/o timeout 这类根因以前只在 events（detail 全量）与 logd stderr 里
// 看得到，gate.log 的 err 行只有 reason+首包 hex，tail gate.log 定位不到原因。
func logGateErr(proto, src string, od dstAddr, verdict, reason, detail string, b []byte) {
	if len(detail) > 64 {
		detail = detail[:64] + ".."
	}
	// detail 复用 logGate 的落盘锁与格式：先记尸检行，再由调用方补事件。
	saved := gateLogFile
	if saved == nil {
		return
	}
	hx := b
	if len(hx) > 24 {
		hx = hx[:24]
	}
	hex := fmt.Sprintf("%x", hx)
	if len(b) > 24 {
		hex += ".."
	}
	ioMu.Lock()
	fmt.Fprintf(saved, "{\"ts\":%d,\"proto\":%q,\"src\":%q,\"dst\":%q,\"verdict\":%q,\"reason\":%q,\"detail\":%q,\"first\":%q}\n",
		time.Now().Unix(), proto, src, od.String(), verdict, reason, detail, hex)
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
// R8：:80 用 opportunistic 短读（peekWait80，默认 80ms）——HTTP 客户端建连即发
// 请求，局域网内数据必在途，读到即走正常 classify（dl_direct/dl_range/dl_ua/
// dl_ext 可达）；静默/超时/空/非 HTTP 则 n=0 落 proxy/default（fail-closed）。
// 443/奇端口沿用 peekWait（要载荷做 TLS/HTTP 判定，省不掉）。
// 0x16 开头但首读不足 6B 时在同一 150ms 预算内续读到 6B（TLS 严判需
// 16 03 … 01 六字节）；b[1]==0xF1（mmtls）即早停，字节收集行为保持原样。
// peekBudget 首包 peek 时间预算：:80 用 opportunistic 短读（R8，peekWait80），
// 其余端口全量 peek（peekWait，要载荷做 TLS/HTTP 判定）。P1-2 的 TLS 续读
// 复用同一预算（绝对 deadline），不新增等待层级。
func peekBudget(port int) time.Duration {
	if port == 80 {
		return peekWait80
	}
	return peekWait
}

func peekClient(c net.Conn, buf []byte, port int) int {
	wait := peekBudget(port)
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
		if port != 80 && n >= 2 && n < 6 && buf[0] == 0x16 && buf[1] != 0xF1 {
			// 短读补齐：TLS 严判需 6 字节（16 03 … 01），首读 2-5 字节时在同一
			// 150ms 预算内续读。b[1]==0xF1 即早停——字节收集早停不变；判路无 mmtls/oicq
			// reason，一律三判。
			dl := time.Now().Add(150 * time.Millisecond)
			for n < 6 && time.Now().Before(dl) {
				c.SetReadDeadline(dl)
				if k, _ := c.Read(buf[n:]); k > 0 {
					n += k
				} else {
					break
				}
			}
		}
	} else if err != nil && !isTimeout(err) {
		// client closed without data; fall through with n=0 (default path)
	}
	return n
}

type fileMark struct {
	mod  time.Time
	size int64
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

// matchDomainSuffix 精确或子域后缀命中（dl-domains 用，可单测）。
func matchDomainSuffix(sni string, set map[string]bool) bool {
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

// 下载站/下载器名单（30s 热加载，lists/ 镜像）：
// dl-domains 精确/子域匹配记 pass/dl_direct；dl-ua 为 UA token 子串匹配记
// pass/dl_ua；dl-ext 为 URL 后缀匹配记 pass/dl_ext；dl-query 为 URL query
// 预签名/强制下载参数子串匹配记 pass/dl_query（不依赖 Host 名单的新增召回）。
// 单文件缺失保留旧快照。
var (
	dlDomPath   = envStr("WD_DL_DOM_FILE", "/etc/wxdet/dl-domains.txt")
	dlUAPath    = envStr("WD_DL_UA_FILE", "/etc/wxdet/dl-ua.txt")
	dlExtPath   = envStr("WD_DL_EXT_FILE", "/etc/wxdet/dl-ext.txt")
	dlQueryPath = envStr("WD_DL_QUERY_FILE", "/etc/wxdet/dl-query.txt")
	dlDoms      atomic.Value // map[string]bool
	dlUAs       atomic.Value // []string
	dlExts      atomic.Value // []string
	dlQuerys    atomic.Value // []string
	dlMu        sync.Mutex
	dlMarks     = map[string]fileMark{}
)

func dlDomSnapshot() map[string]bool {
	if v := dlDoms.Load(); v != nil {
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

func dlQuerySnapshot() []string {
	if v := dlQuerys.Load(); v != nil {
		return v.([]string)
	}
	return nil
}

func dlDomainHit(host string) bool { return matchDomainSuffix(host, dlDomSnapshot()) }

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
func loadDLLists() (nd, nu, ne, nq int) {
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
	if b, err := os.ReadFile(dlQueryPath); err == nil {
		list := parseKeywords(b)
		dlQuerys.Store(list)
		nq = len(list)
		noteDLMark(dlQueryPath)
	} else {
		log.Printf("warn: dl query file %s: %v", dlQueryPath, err)
	}
	return nd, nu, ne, nq
}

func checkDLReload() bool {
	changed := false
	dlMu.Lock()
	for _, p := range []string{dlDomPath, dlUAPath, dlExtPath, dlQueryPath} {
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
	nd, nu, ne, nq := loadDLLists()
	log.Printf("dl reloaded: dom=%d ua=%d ext=%d query=%d", nd, nu, ne, nq)
	writeStat("gate_dl_reload", 1)
	return true
}

// looksLikeTLSRecord：旧粗判（16 03 前缀 + ≥6B）。保留仅用于观测对照：
// 命中本判但未过 isTLSClientHello 的连接计入 gate_tls_strict_fail。
func looksLikeTLSRecord(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03
}

// isTLSClientHello：严判（对齐 Zeek/Suricata 系解析器口径）。
// 在 16 03 前缀基础上要求：
//   - b[2] 记录层版本 minor ∈ {0x00..0x03}（Zeek 记录层白名单 / Suricata 客户端模式）；
//   - b[3:5] 记录长度 ∈ [1, 16384+2048]（tls-parser MAX_RECORD_LEN 上限；下限 1 =
//     允许记录级分片的首记录只有 1-3B 负载，空记录拒绝）；
//   - b[5] 握手类型 == 0x01（客户端首包只可能是 ClientHello）。
//
// 使"16 03 开头的任意二进制（如 u16be 长度前缀 0x1603）"不再判成 TLS：
// 误判率由 ~1 降到 ~1/(256×64)≈6e-5/连接。
func isTLSClientHello(b []byte) bool {
	if !looksLikeTLSRecord(b) {
		return false
	}
	if b[2] > 0x03 {
		return false
	}
	if rl := int(b[3])<<8 | int(b[4]); rl < 1 || rl > 18432 {
		return false
	}
	return b[5] == 0x01
}

// classify 生产入口：与原版逐字节一致，仅在严判失败时落 gate_tls_strict_fail（P2-12：
// 判路本体拆成无副作用的 classifyEx，单测不再写文件）。
func classify(od dstAddr, b []byte) (string, string) {
	v, r, strictFail := classifyEx(od, b)
	if strictFail {
		writeStat("gate_tls_strict_fail", 1)
	}
	if r == "dl_range" {
		// Range 强弱只做观测分级（gate_range_strong/weak），不改判路：
		// 弱 Range 翻转会降召回（视频 seek 进代理烧带宽），等计数说话再定。
		if rangeStrong(b) {
			writeStat("gate_range_strong", 1)
		} else {
			writeStat("gate_range_weak", 1)
		}
	}
	return v, r
}

// classifyEx 纯判路（无副作用）。三判：标准 TLS → pass；明文 HTTP 下载特征
// （Host 名单 > Range > URL query 签名 > 下载器 UA > 后缀）→ pass；其余一切 → proxy/default。
// strictFail = 旧粗判(16 03)真、严判假，由 classify 计数（纯观测，不改判路）。
// 注意顺序：Range 在前保既有 dl_range 标签稳定（query 只收无 Range 的单 GET 下载链）。
// strictFail = 旧粗判(16 03)真、严判假，由 classify 计数（纯观测，不改判路）。
func classifyEx(od dstAddr, b []byte) (verdict, reason string, strictFail bool) {
	_ = od // 判路端口无关（peek 预算仍按端口，见 peekBudget）
	if isTLSClientHello(b) {
		return "pass", "tls_direct", false
	}
	if looksLikeTLSRecord(b) {
		strictFail = true
	}
	if isHTTPRequest(b) {
		if h := httpHost(b); h != "" && dlDomainHit(h) {
			return "pass", "dl_direct", strictFail
		}
		if hasRangeHeader(b) {
			return "pass", "dl_range", strictFail
		}
		if p := httpPath(b); p != "" && dlQueryHit(p) {
			return "pass", "dl_query", strictFail
		}
		if ua := httpUserAgent(b); ua != "" && dlUAHit(ua) {
			return "pass", "dl_ua", strictFail
		}
		if p := httpPath(b); p != "" && dlExtHit(p) {
			return "pass", "dl_ext", strictFail
		}
	}
	return "proxy", "default", strictFail
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

// watchDLLists 周期性轮询名单文件（WD_KW_POLL_SEC，<=0 关闭），变化即热加载，不断连接。
func watchDLLists() {
	if kwPollSec <= 0 {
		return
	}
	t := time.NewTicker(time.Duration(kwPollSec) * time.Second)
	defer t.Stop()
	for range t.C {
		checkDLReload()
	}
}

// httpMethods 方法行语义校验表：h2c 的 PRI * HTTP/2.0 不在表里，会穿过
// 通判走 proxy/default（手机 App 基本不用 h2c，记一笔不修）。
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

// headerBlock 只留 HTTP 头部块（首个 \r\n\r\n 之前）。没有该分隔符就返回整段，
// 保持"头部还没收全"的现有语义（P1-4：头部类判据只看头部，避免 POST body 里
// 恰好出现的 "\nRange:"/"\nUser-Agent: Thunder" 把判路翻转）。
func headerBlock(b []byte) []byte {
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		return b[:i]
	}
	return b
}

// httpHost 提取 Host 头（小写、去端口、去尾点；无头返回 ""，IP 字面原样返回）。
func httpHost(b []byte) string {
	lower := strings.ToLower(string(headerBlock(b)))
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
	parts := strings.SplitN(strings.TrimSpace(httpFirstLine(headerBlock(b))), " ", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// dlQueryHit URL query 预签名/强制下载参数子串命中（大小写不敏感）。
// 只收各云互不相同的签名参数名；sign=/token=/expires= 这类登录态通用参数绝不进名单。
func dlQueryHit(path string) bool {
	s := strings.ToLower(path)
	for _, tok := range dlQuerySnapshot() {
		if tok != "" && strings.Contains(s, tok) {
			return true
		}
	}
	return false
}

// rangeStrong Range 值语义分级：多段逗号 / If-Range / 首字节非零即强信号；
// 单段 bytes=0- 与 bytes=-N 尾段为弱信号。只看头部块（body 里的 Range 不算）。
func rangeStrong(b []byte) bool {
	lower := strings.ToLower(string(headerBlock(b)))
	i := strings.Index(lower, "\nrange:")
	if i < 0 {
		return false
	}
	rest := lower[i+len("\nrange:"):]
	if j := strings.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[:j]
	}
	val := strings.TrimSpace(rest)
	if strings.Contains(val, ",") {
		return true
	}
	if strings.Contains(lower, "\nif-range:") {
		return true
	}
	if k := strings.IndexByte(val, '='); k >= 0 {
		val = strings.TrimSpace(val[k+1:])
	}
	if strings.HasPrefix(val, "-") {
		return false
	}
	digits := ""
	for _, c := range val {
		if c < '0' || c > '9' {
			break
		}
		digits += string(c)
	}
	return strings.TrimLeft(digits, "0") != ""
}

// hasRangeHeader 是否带 Range: 头（断点续传/音视频 seek 信号；调用方已保证 isHTTPRequest）。
func hasRangeHeader(b []byte) bool {
	return strings.Contains(strings.ToLower(string(headerBlock(b))), "\nrange:")
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
	lower := strings.ToLower(string(headerBlock(b)))
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
	// P2-6：回复头必须 VER=5 / RSV=0（旧版只读 hdr[1]，垃圾首字节会被当成合法 REP=0
	// 而把完全不是 SOCKS5 的字节流当成功连接转发）。
	if hdr[0] != 5 {
		return fail(fmt.Errorf("socks reply ver=%d", hdr[0]))
	}
	if hdr[2] != 0 {
		return fail(fmt.Errorf("socks reply rsv=%d", hdr[2]))
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
	if shouldEmitOpen(verdict, reason) {
		emitCloseEvent("tcp", src, od, verdict, reason, durMs, upB, downB, closer)
		return
	}
	// 不进事件流的流（当前唯一例外 tls_direct）：字节/时长改走聚合台账，
	// 每分钟增量刷进 stats.tsv —— 直连面不再是黑盒，且不会撑爆 events。
	ledgerAdd(durMs, upB, downB)
}

// isLocalDst 本机/私网/链路本地/未指定目的地址。正常 iot 重定向流的目的恒为公网
// （nft redirect 规则已排除 10/8、127/8、172.16/12、192.168/16），命中即"直连
// gate 监听口"的非重定向流量，必须丢（P0-1）。与 UDP 侧 udp.go 的
// gate_udp_local_drop 同口径，注释见那里的防环说明。
func isLocalDst(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

// tcpLocalDropLogNs 本机目的丢弃的 gate.log 限速（纳秒时间戳）：计数每次都记，
// 日志 5s 最多一行，防端口扫描刷屏。
var tcpLocalDropLogNs atomic.Int64

func logTCPLocalDrop(src string, od dstAddr) {
	now := time.Now().UnixNano()
	last := tcpLocalDropLogNs.Load()
	if now-last < int64(5*time.Second) || !tcpLocalDropLogNs.CompareAndSwap(last, now) {
		return
	}
	logGate("tcp", src, od, "drop", "local_dst", nil)
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
	if isLocalDst(od.ip) {
		// P0-1：非重定向流（LAN 设备/本机进程直连 gate 监听口）。放行会让
		// origdst=本机:port → proxy/default → 代理侧路由连回自己，
		// 形成链式自环直到 fd 打满（实测一条连接可链出 252 条）。只按地址类别
		// 判、不看端口：公网真有 :12347 服务，正常重定向流可能合法命中。
		writeStat("gate_tcp_local_drop", 1)
		logTCPLocalDrop(src, od)
		return
	}
	buf := make([]byte, 1024)
	// R8 opportunistic peek：:80 短读；443/奇端口全量 peek（TLS/HTTP 判定省不掉）。
	n := peekClient(tc, buf, od.port)

	verdict, reason := classify(od, buf[:n])
	emitOpen("tcp", src, od, verdict, reason)
	up := openUpstream(verdict, reason, od, src, id, buf[:n])
	if up == nil {
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
	logGate("tcp", src, od, verdict, reason, buf[:n])
	relay(tc, up, src, od, verdict, reason, start)
}

// openUpstream 按 verdict 拨**唯一**上游；返回 nil 表示本连接已收尾
// （失败一律 fail-closed：断流，绝不改拨第二条腿）。
// pass→passSocks（失败计 gate_pass_fail），proxy→proxySocks（失败计 gate_proxy_fail），
// 未知 verdict 防御性归入 pass 腿（classify 只产出 pass/proxy，到不了这里）。
func openUpstream(verdict, reason string, od dstAddr, src string, id uint64, head []byte) *net.TCPConn {
	if verdict == "proxy" {
		up, err := socks5Dial(proxySocks, od, nil, 0)
		if err != nil {
			writeStat("gate_proxy_fail", 1)
			writeStat("gate_dial_err", 1)
			logGateErr("tcp", src, od, "err", reason+"_proxy_fail", err.Error(), head)
			emitErrorEvent("tcp", src, od, "err", reason+"_proxy_fail", err.Error())
			log.Printf("#%d %s -> %s proxy dial fail (fail-closed): %v", id, src, od, err)
			return nil
		}
		return up
	}
	up, err := socks5Dial(passSocks, od, nil, 0)
	if err != nil {
		writeStat("gate_pass_fail", 1)
		writeStat("gate_dial_err", 1)
		logGateErr("tcp", src, od, "err", reason, err.Error(), head)
		emitErrorEvent("tcp", src, od, "err", reason, err.Error())
		log.Printf("#%d %s -> %s dial: %v", id, src, od, err)
		return nil
	}
	return up
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
