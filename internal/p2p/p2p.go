// Package p2p：节点自身的**打洞条件预检**与**连通性检查**。
//
// 为什么节点要自己做这件事（而不是只让云端 CLI 做）：
//
//	① NAT 状况是**每台机器**的事 —— 内网节点所在网络跟开发者的笔记本往往不是同一个出口；
//	② 纯内网/跨网场景下，两端可能都不方便走云端信令，得能直接对打；
//	③ 结论要能落进节点自述（/api/meta、/api/p2p/self），别人才知道「能不能跟它直连」。
//
// 与 spike（`spike/p2p-transport/`）的关系：那是最初的实验装置（pion/WebRTC 全链路 + 量化），
// 这里是**结论的落地**：只用 STUN 判断「打不打得到」，不引 pion、不建 DTLS/SCTP 数据通道
// （真正的数据通道属于 P2.2，见 ncc-platform/prd/ncc-p2p-data.md）。
//
// 只依赖标准库。判定方法与 spike 逐字一致：
//
//	映射行为（RFC 5780 §4.3）：同 IP 换端口 → 换 IP 同端口 → 换 IP 换端口
//	过滤行为（RFC 5780 §4.4）：CHANGE-REQUEST 0x06（改 IP+端口）→ 0x02（只改端口）
package p2p

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/* ---------------- STUN 原语 ---------------- */

const (
	magicCookie   uint32 = 0x2112A442
	bindingReq    uint16 = 0x0001
	bindingOK     uint16 = 0x0101
	attrMapped    uint16 = 0x0001
	attrChange    uint16 = 0x0003
	attrXorMapped uint16 = 0x0020
	attrOther     uint16 = 0x802c

	changeIPPort uint32 = 0x06 // 改 IP + 改端口
	changePort   uint32 = 0x02 // 只改端口

	defaultStunPort = 3478
)

// DefaultSTUN 默认 STUN 列表：必须 ≥2 台**不同公网 IP** 的服务器，
// 否则判不了映射行为（只能靠 RFC 5780 那台）。实测某些网络下 Google STUN 不可达，
// 所以默认带上国内可达的两台；**单台超时不等于 NAT 不友好**。
var DefaultSTUN = []string{
	"stun:stun.miwifi.com:3478",
	"stun:stun.qq.com:3478",
	"stun:stun.l.google.com:19302",
}

func newTxID() []byte {
	b := make([]byte, 12)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(rand.Uint32())))
	for i := range b {
		b[i] = byte(rnd.Intn(256))
	}
	return b
}

func attr(t uint16, val []byte) []byte {
	out := make([]byte, 0, 4+len(val)+3)
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:2], t)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(val)))
	out = append(out, hdr[:]...)
	out = append(out, val...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

func buildMessage(kind uint16, txid []byte, attrs []byte) []byte {
	out := make([]byte, 0, 20+len(attrs))
	var hdr [20]byte
	binary.BigEndian.PutUint16(hdr[0:2], kind)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(hdr[4:8], magicCookie)
	copy(hdr[8:20], txid)
	out = append(out, hdr[:]...)
	return append(out, attrs...)
}

func bindingRequest(txid []byte, change uint32, withChange bool) []byte {
	var attrs []byte
	if withChange {
		v := make([]byte, 4)
		binary.BigEndian.PutUint32(v, change)
		attrs = attr(attrChange, v)
	}
	return buildMessage(bindingReq, txid, attrs)
}

// bindingSuccess 把观察到的对端源地址回填进 XOR-MAPPED-ADDRESS：
// 对端因此在自己那侧也拿到「被穿透成功」的证据（ICE 双向检查的道理）。
func bindingSuccess(txid []byte, observed net.Addr) []byte {
	udp, _ := observed.(*net.UDPAddr)
	if udp == nil {
		return nil
	}
	val := []byte{0x00}
	ip4 := udp.IP.To4()
	if ip4 == nil {
		return nil // 只做 IPv4：IPv6 场景本身不需要打洞
	}
	val = append(val, 0x01)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(udp.Port)^uint16(magicCookie>>16))
	val = append(val, p[:]...)
	var m [4]byte
	binary.BigEndian.PutUint32(m[:], magicCookie)
	for i := 0; i < 4; i++ {
		val = append(val, ip4[i]^m[i])
	}
	return buildMessage(bindingOK, txid, attr(attrXorMapped, val))
}

type attribute struct {
	typ uint16
	val []byte
}

func parseAttrs(msg []byte) []attribute {
	if len(msg) < 20 {
		return nil
	}
	total := int(binary.BigEndian.Uint16(msg[2:4]))
	end := 20 + total
	if end > len(msg) {
		end = len(msg)
	}
	var out []attribute
	for i := 20; i+4 <= end; {
		t := binary.BigEndian.Uint16(msg[i : i+2])
		l := int(binary.BigEndian.Uint16(msg[i+2 : i+4]))
		if i+4+l > end {
			break
		}
		out = append(out, attribute{t, msg[i+4 : i+4+l]})
		i += 4 + l
		if pad := (4 - l%4) % 4; pad > 0 {
			i += pad
		}
	}
	return out
}

func decodeXorMapped(v []byte) *net.UDPAddr {
	if len(v) < 8 || v[1] != 0x01 {
		return nil
	}
	port := int(binary.BigEndian.Uint16(v[2:4]) ^ uint16(magicCookie>>16))
	var m [4]byte
	binary.BigEndian.PutUint32(m[:], magicCookie)
	ip := net.IPv4(v[4]^m[0], v[5]^m[1], v[6]^m[2], v[7]^m[3])
	return &net.UDPAddr{IP: ip, Port: port}
}

func decodePlain(v []byte) *net.UDPAddr {
	if len(v) < 8 || v[1] != 0x01 {
		return nil
	}
	port := int(binary.BigEndian.Uint16(v[2:4]))
	return &net.UDPAddr{IP: net.IPv4(v[4], v[5], v[6], v[7]), Port: port}
}

// ResolveSTUN 解析 `stun:host:port` / `host`（缺端口补 3478）。
func ResolveSTUN(s string) (*net.UDPAddr, error) {
	raw := strings.TrimSpace(s)
	for _, p := range []string{"stun:", "turn:", "stuns:", "turns:"} {
		raw = strings.TrimPrefix(raw, p)
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	if strings.Count(raw, ":") == 0 {
		raw = net.JoinHostPort(raw, strconv.Itoa(defaultStunPort))
	}
	return net.ResolveUDPAddr("udp4", raw)
}

type stunReply struct {
	from      *net.UDPAddr
	xorMapped *net.UDPAddr
	other     *net.UDPAddr
	rtt       time.Duration
}

// exchange 发一次 Binding 请求并等**事务 ID 匹配**的响应（来源不限 —— 改 IP/端口的测试
// 正是要收到来自另一个地址的响应）。
func exchange(conn *net.UDPConn, dst *net.UDPAddr, change uint32, withChange bool, timeout time.Duration) (*stunReply, error) {
	txid := newTxID()
	req := bindingRequest(txid, change, withChange)
	start := time.Now()
	if _, err := conn.WriteToUDP(req, dst); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	deadline := start.Add(timeout)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		if n < 20 || string(buf[8:20]) != string(txid) {
			continue
		}
		rep := &stunReply{from: from, rtt: time.Since(start)}
		for _, a := range parseAttrs(buf[:n]) {
			switch a.typ {
			case attrXorMapped:
				rep.xorMapped = decodeXorMapped(a.val)
			case attrMapped:
				if rep.xorMapped == nil {
					rep.xorMapped = decodePlain(a.val)
				}
			case attrOther:
				rep.other = decodePlain(a.val)
			}
		}
		return rep, nil
	}
}

/* ---------------- ① probe：本机 NAT 画像 ---------------- */

// Profile 打洞条件画像（字段与 spike / PRD 一致，便于两端比对）。
type Profile struct {
	LocalIP           string   `json:"localIpv4"`
	LocalAddrKind     string   `json:"localAddrKind"` // public | private | cgnat
	LocalPort         int      `json:"localPort"`
	PublicIP          string   `json:"publicIp,omitempty"`
	Mapped            string   `json:"mapped,omitempty"`
	ServersTried      int      `json:"serversTried"`
	ServersReached    int      `json:"serversReached"`
	Servers           []string `json:"servers"`
	MappingBehavior   string   `json:"mappingBehavior"` // endpoint_independent | address_dependent | address_and_port_dependent | unknown
	MappingMethod     string   `json:"mappingMethod"`   // rfc5780 | multi-stun
	FilteringBehavior string   `json:"filteringBehavior"`
	FilteringMethod   string   `json:"filteringMethod"` // rfc5780 | unsupported
	RFC5780           bool     `json:"rfc5780Supported"`
	Verdict           string   `json:"verdict"` // direct | likely_direct | relay_likely | blocked | unknown
	Advice            string   `json:"advice"`
}

func hostAddrKind(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return "unknown"
	}
	switch {
	case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127:
		return "cgnat"
	case v4[0] == 10, v4[0] == 192 && v4[1] == 168, v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
		return "private"
	}
	return "public"
}

// egressIP 本机出网 IP（不真的发包，让内核选路）。
func egressIP() net.IP {
	c, err := net.Dial("udp4", "1.1.1.1:80")
	if err != nil {
		return nil
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP
	}
	return nil
}

// Probe 只做**单边本地预检**：UDP 出站能不能用、拿到什么公网映射、NAT 映射/过滤行为。
func Probe(servers []string, timeout time.Duration) Profile {
	if len(servers) == 0 {
		servers = DefaultSTUN
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	prof := Profile{ServersTried: len(servers), Servers: servers, MappingMethod: "multi-stun", FilteringMethod: "unsupported"}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		prof.Verdict = "unknown"
		prof.Advice = "无法创建 UDP socket：" + err.Error()
		return prof
	}
	defer conn.Close()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		prof.LocalPort = a.Port
	}
	if ip := egressIP(); ip != nil {
		prof.LocalIP = ip.String()
		prof.LocalAddrKind = hostAddrKind(ip)
	}

	mappedSeen := map[string]int{}
	var rfcServer string
	var rfcOther *net.UDPAddr
	for _, s := range servers {
		dst, err := ResolveSTUN(s)
		if err != nil {
			continue
		}
		rep, err := exchange(conn, dst, 0, false, timeout)
		if err != nil || rep.xorMapped == nil {
			continue
		}
		prof.ServersReached++
		m := rep.xorMapped.String()
		mappedSeen[m]++
		if prof.Mapped == "" {
			prof.Mapped = m
			prof.PublicIP = rep.xorMapped.IP.String()
		}
		if rep.other != nil && rfcServer == "" {
			rfcServer, rfcOther = s, rep.other
		}
	}

	direct := prof.PublicIP != "" && prof.PublicIP == prof.LocalIP
	if !direct && rfcServer != "" {
		if mapping, filtering, err := rfc5780(conn, rfcServer, rfcOther, timeout); err == nil {
			prof.MappingBehavior, prof.MappingMethod = mapping, "rfc5780"
			prof.FilteringBehavior, prof.FilteringMethod = filtering, "rfc5780"
			prof.RFC5780 = true
		}
	}
	if prof.MappingMethod != "rfc5780" {
		switch {
		case prof.ServersReached == 0:
			prof.MappingBehavior = "unknown"
		case direct:
			prof.MappingBehavior = "endpoint_independent"
		case prof.ServersReached < 2:
			prof.MappingBehavior = "unknown"
		case len(mappedSeen) == 1:
			prof.MappingBehavior = "endpoint_independent"
		default:
			prof.MappingBehavior = "address_and_port_dependent"
		}
	}

	switch {
	case prof.MappingBehavior == "unknown" && prof.ServersReached == 0:
		prof.Verdict = "blocked"
		prof.Advice = "所有 STUN 都没响应：UDP 出站可能被封（企业网常见）。直连不可行 —— 用客户自托管 TURN over TCP/TLS，或走中心搬运（master 代取字节）。"
	case direct:
		prof.Verdict = "direct"
		prof.Advice = "本机在公网上（映射等于本机 IP）：对端可直接连，打洞不必要。"
	case prof.MappingBehavior == "unknown":
		prof.Verdict = "unknown"
		prof.Advice = "只探到 1 台 STUN 且它不支持 RFC 5780，判不了映射行为：多配几台不同公网 IP 的 STUN 再测。"
	case prof.MappingBehavior == "address_and_port_dependent":
		prof.Verdict = "relay_likely"
		prof.Advice = "对称 NAT：只有对端是锥形且由对端发起时有机会；两端都对称基本只能 relay。请配 NCCR_P2P_TURN（客户自托管）。"
	case prof.MappingBehavior == "address_dependent":
		prof.Verdict = "likely_direct"
		prof.Advice = "地址相关映射：通常仍能打洞，但需要双方同时发起。用 `ncc registry p2p check --peer <对端映射地址>` 实测。"
	default:
		prof.Verdict = "likely_direct"
		advice := "锥形 NAT（端点无关映射"
		switch prof.FilteringBehavior {
		case "endpoint_independent":
			advice += "、端点无关过滤"
		case "address_dependent":
			advice += "、地址相关过滤"
		case "address_and_port_dependent":
			advice += "、地址端口相关过滤"
		}
		prof.Advice = advice + "）：与同为锥形的对端几乎必成；对方对称时需你主动先发。用 check 实测确认。"
	}
	if prof.LocalAddrKind == "cgnat" {
		prof.Advice += "（本机在 100.64/10，属运营商级 NAT：直连成功率低，优先 relay。）"
	}
	return prof
}

func rfc5780(conn *net.UDPConn, server string, other *net.UDPAddr, timeout time.Duration) (string, string, error) {
	primary, err := ResolveSTUN(server)
	if err != nil {
		return "", "", err
	}
	if other == nil || other.IP.To4() == nil {
		return "", "", errors.New("OTHER-ADDRESS 不可用")
	}
	m1, err := exchange(conn, primary, 0, false, timeout)
	if err != nil || m1.xorMapped == nil {
		return "", "", err
	}
	m2, err := exchange(conn, &net.UDPAddr{IP: other.IP, Port: primary.Port}, 0, false, timeout)
	if err != nil {
		return "", "", err
	}
	mapping := ""
	switch {
	case m2.xorMapped != nil && m2.xorMapped.String() == m1.xorMapped.String():
		mapping = "endpoint_independent"
	default:
		m3, err := exchange(conn, other, 0, false, timeout)
		if err != nil {
			return "", "", err
		}
		if m3.xorMapped != nil && m2.xorMapped != nil && m3.xorMapped.String() == m2.xorMapped.String() {
			mapping = "address_dependent"
		} else {
			mapping = "address_and_port_dependent"
		}
	}
	// 过滤：能收到来自另一个地址的响应 = 端点无关过滤。
	if _, err := exchange(conn, primary, changeIPPort, true, timeout); err == nil {
		return mapping, "endpoint_independent", nil
	}
	if _, err := exchange(conn, primary, changePort, true, timeout); err == nil {
		return mapping, "address_dependent", nil
	}
	return mapping, "address_and_port_dependent", nil
}

/* ---------------- ② check：真实连通性检查 ---------------- */

// CheckResult 一次打洞检查的结果。
type CheckResult struct {
	OK            bool   `json:"ok"`
	MyMapped      string `json:"myMapped"`
	PeerMapped    string `json:"peerMapped"`
	RTTms         int64  `json:"rttMs"`
	PeerRequests  int    `json:"peerRequestsSeen"`
	PeerResponses int    `json:"peerResponsesSeen"`
	Reason        string `json:"reason,omitempty"`
	Advice        string `json:"advice,omitempty"`
	STUN          string `json:"stunUsed,omitempty"`
}

// DiscoverMapping 从一个已绑定的 UDP socket 上探自己的公网映射（打洞前必须先知道这个）。
func DiscoverMapping(conn *net.UDPConn, servers []string, timeout time.Duration) (*net.UDPAddr, string, error) {
	if len(servers) == 0 {
		servers = DefaultSTUN
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		for _, s := range servers {
			dst, err := ResolveSTUN(s)
			if err != nil {
				lastErr = err
				continue
			}
			rep, err := exchange(conn, dst, 0, false, timeout)
			if err != nil || rep.xorMapped == nil {
				if err != nil {
					lastErr = err
				}
				continue
			}
			return rep.xorMapped, s, nil
		}
		time.Sleep(600 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("所有 STUN 都无响应")
	}
	return nil, "", lastErr
}

// Check 与一个已知的映射地址做**双向对打**：我发 Binding 请求，同时回答对方发来的请求。
// 收到对方的任何 UDP 包即证明「这条路径的 NAT 允许入向」—— 这就是 ICE connectivity check。
//
// 用法：两端同时发起（各自 Check 对方），或一端 Check、另一端开着 Responder。
func Check(ctx context.Context, peer *net.UDPAddr, servers []string, wait, timeout time.Duration) CheckResult {
	res := CheckResult{PeerMapped: peer.String()}
	if wait <= 0 {
		wait = 10 * time.Second
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		res.Reason = "无法创建 UDP socket：" + err.Error()
		return res
	}
	defer conn.Close()
	mapped, used, err := DiscoverMapping(conn, servers, timeout)
	if err != nil {
		res.Reason = "拿不到自己的公网映射：" + err.Error() + "（UDP 出站可能被封；先看 p2p self 的结论）"
		res.Advice = "先跑 `ncc registry p2p self` 看 NAT 画像；企业网禁 UDP 时只能用客户自托管 TURN 或中心搬运。"
		return res
	}
	res.MyMapped = mapped.String()
	res.STUN = used

	done := make(chan struct{})
	go func() { // 对打：每 300ms 发一个 Binding 请求
		defer close(done)
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = conn.WriteToUDP(bindingRequest(newTxID(), 0, false), peer)
			}
		}
	}()

	deadline := time.Now().Add(wait)
	buf := make([]byte, 1500)
	var lastSent time.Time
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if from.IP.Equal(peer.IP) && from.Port == peer.Port {
			if n >= 20 {
				switch binary.BigEndian.Uint16(buf[0:2]) {
				case bindingReq:
					res.PeerRequests++
					if reply := bindingSuccess(buf[8:20], from); reply != nil {
						_, _ = conn.WriteToUDP(reply, from)
					}
					res.OK = true
				case bindingOK:
					res.PeerResponses++
					if res.RTTms == 0 {
						res.RTTms = time.Since(lastSent).Milliseconds()
					}
					res.OK = true
				}
			}
		}
		if (res.PeerRequests > 0 || res.PeerResponses > 0) && res.RTTms > 0 {
			break
		}
		if time.Since(lastSent) >= 300*time.Millisecond {
			_, _ = conn.WriteToUDP(bindingRequest(newTxID(), 0, false), peer)
			lastSent = time.Now()
		}
	}
	<-done
	if !res.OK {
		res.Reason = "对端没有任何回包"
		res.Advice = "常见原因：①对端没在跑（check 或 p2p serve）；②双方 NAT 不兼容（尤其对称 NAT）；③企业网禁 UDP。"
	}
	return res
}

/* ---------------- ③ responder：让本节点可被「打进来」 ---------------- */

// Responder 在后台回答 STUN Binding 请求，让别的节点/CLI 能打洞过来。
//
// ⚠️ 实测结论（别踩）：**被动应答只在「端点无关过滤」的 NAT 上够用**。
// 若本机 NAT 是 address/port-dependent filtering（常见：家用与企业网都可能是），
// 它会丢掉「我没先发过的对端」发来的包 —— 于是入口一个包都收不到（实测“已应答 0 次”）。
// 解法就是打洞的本质：**双方同时向对方的映射地址发包**。所以下面带了 Peers：
// 已知对端映射时，入口会主动反向发给它，两边同时开孔，包就能互相通过。
//
// 这也是**显式开关**（NCCR_P2P_SERVE=1 或管理接口打开）：它确实对外暴露一个 UDP 入口。
type Responder struct {
	conn    *net.UDPConn
	cancel  context.CancelFunc
	mu      sync.Mutex
	mapped  *net.UDPAddr
	peers   []*net.UDPAddr // 反向打洞对端（对端的映射地址）
	reqs    atomic.Int64
	servers []string
	timeout time.Duration
	resps   atomic.Int64
}

// StartResponder 绑定一个 UDP 端口并开始应答；同时探出自己的公网映射（供对端使用）。
func StartResponder(servers []string, timeout time.Duration) (*Responder, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Responder{conn: conn, cancel: cancel, servers: servers, timeout: timeout}
	if mapped, _, err := DiscoverMapping(conn, servers, timeout); err == nil {
		r.mapped = mapped
	}
	go func() {
		buf := make([]byte, 1500)
		lastPunch := time.Now()
		for {
			if ctx.Err() != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, from, err := conn.ReadFromUDP(buf)
			if err == nil {
				if n >= 20 && binary.BigEndian.Uint16(buf[0:2]) == bindingReq {
					r.reqs.Add(1)
					if reply := bindingSuccess(buf[8:20], from); reply != nil {
						_, _ = conn.WriteToUDP(reply, from)
					}
				} else if n >= 20 && binary.BigEndian.Uint16(buf[0:2]) == bindingOK {
					r.resps.Add(1) // 反向打洞的对方回了我们（说明这条路径真通了）
				}
			}
			// 反向打洞：每 300ms 给已知对端的映射发一个 Binding 请求，
			// 好让本机 NAT 为它开一个过滤孔（这就是 hole punching 的另一半）。
			if time.Since(lastPunch) >= 300*time.Millisecond {
				lastPunch = time.Now()
				for _, p := range r.Peers() {
					_, _ = conn.WriteToUDP(bindingRequest(newTxID(), 0, false), p)
				}
			}
		}
	}()
	return r, nil
}

// Close 停止应答并释放端口。
func (r *Responder) Close() {
	if r == nil {
		return
	}
	r.cancel()
	_ = r.conn.Close()
}

// Addr 本地监听地址（`ip:port`）。
func (r *Responder) Addr() string {
	if r == nil || r.conn == nil {
		return ""
	}
	return r.conn.LocalAddr().String()
}

// MappedAddr 对端应当发往的地址（公网映射）；探不到时退回空串。
func (r *Responder) MappedAddr() string {
	if r == nil || r.mapped == nil {
		return ""
	}
	return r.mapped.String()
}

// Requests 已经应答过多少次打洞请求（运维观测用）。
func (r *Responder) Requests() int64 {
	if r == nil {
		return 0
	}
	return r.reqs.Load()
}

// Responses 反向打洞时收到过多少次对端回包（>0 表示这条路径真通了）。
func (r *Responder) Responses() int64 {
	if r == nil {
		return 0
	}
	return r.resps.Load()
}

// SetPeers 设置「反向打洞」的对端映射地址（对端 `p2p serve` 报出的 mapped）。
func (r *Responder) SetPeers(peers []*net.UDPAddr) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.peers = peers
	r.mu.Unlock()
}

// Peers 当前的反向打洞对端。
func (r *Responder) Peers() []*net.UDPAddr {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*net.UDPAddr, len(r.peers))
	copy(out, r.peers)
	return out
}

// Reload 重新探一次映射（换网络、重启路由后 NAT 会变）。
func (r *Responder) Reload() (string, error) {
	if r == nil {
		return "", errors.New("responder 未启动")
	}
	mapped, _, err := DiscoverMapping(r.conn, r.servers, r.timeout)
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	r.mapped = mapped
	r.mu.Unlock()
	return mapped.String(), nil
}

// ParsePeerAddr 解析对端映射地址（支持 `ip:port` 与 `host:port`）。
func ParsePeerAddr(s string) (*net.UDPAddr, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return nil, errors.New("对端地址为空（形如 1.2.3.4:5678）")
	}
	if strings.Count(raw, ":") == 0 {
		return nil, fmt.Errorf("对端地址要带端口：%q", s)
	}
	return net.ResolveUDPAddr("udp4", raw)
}
