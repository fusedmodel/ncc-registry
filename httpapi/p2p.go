// 节点的 P2P 面：判断「这台机器能不能打洞」并可选地开一个可被打进来的入口。
//
// 与云端 ncc-platform 的 `/api/p2p/*` 是**互补**关系，不是同一件事：
//
//	ncc-platform（hub） 信令 + 票据 + ICE 配置 —— 帮两端**找到彼此**
//	本节点（node）      自己的 NAT 画像 + 真实对打 —— 回答**这台机器打不打得到**
//
// 之所以放在节点侧：NAT 状况是每台机器的事（内网节点的出口常跟开发者笔记本完全不同），
// 而且纯内网/跨网场景下两端可能都不方便走云端信令。红线不变：
// **只做判断与 STUN 探测，不搬运业务字节**；TURN 由客户自托管。
package httpapi

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/fusedmodel/ncc-registry/internal/p2p"
)

// p2pSelf GET /api/p2p/self —— 本节点的打洞条件画像（含是否开了可被打洞入口）。
func (s *Server) p2pSelf(c *gin.Context) {
	servers := s.Cfg.P2PSTUN
	if len(servers) == 0 {
		servers = p2p.DefaultSTUN
	}
	prof := p2p.Probe(servers, 3*time.Second)
	out := gin.H{
		"node":    gin.H{"id": s.Cfg.NodeID, "name": s.Cfg.NodeName, "role": s.Cfg.Role, "region": s.Cfg.NodeRegion},
		"profile": prof,
		"serve":   s.p2pServeState(),
		"ice": gin.H{
			"stun": servers,
			"turn": s.Cfg.P2PTURN,
			"note": "TURN 必须由客户自托管；无 TURN 且打洞失败时应明确报错，不降级为中心中转",
		},
	}
	ok(c, 200, out)
}

// p2pCheck POST /api/p2p/check {peer, waitSec} —— 与一个已知映射地址做真实对打。
func (s *Server) p2pCheck(c *gin.Context) {
	var body struct {
		Peer    string `json:"peer"` // 对端映射地址 ip:port（由对端 /api/p2p/self 或 /api/p2p/serve 报出）
		WaitSec int    `json:"waitSec"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	peer, err := p2p.ParsePeerAddr(body.Peer)
	if err != nil {
		fail(c, 400, "bad_request", err.Error())
		return
	}
	wait := time.Duration(body.WaitSec) * time.Second
	if wait <= 0 {
		wait = 10 * time.Second
	}
	if wait > 60*time.Second {
		fail(c, 400, "bad_request", "waitSec 最长 60 秒")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), wait+2*time.Second)
	defer cancel()

	res := p2p.Check(ctx, peer, s.Cfg.P2PSTUN, wait, 3*time.Second)
	// 只记日志，不写治理审计：审计是**管理员动作**的账（谁改了用户/节点/服务），
	// 而「谁跟谁试过打洞」属于运行观测，别把它混进治理面。
	logf("p2p.check peer=%s ok=%v rtt=%dms mine=%s", body.Peer, res.OK, res.RTTms, res.MyMapped)
	if !res.OK && res.MyMapped == "" {
		// 连自己的映射都拿不到 = 本地出站就废了，与「对端不通」要分开报。
		fail(c, 503, "p2p_probe_failed", res.Reason)
		return
	}
	ok(c, 200, gin.H{"result": res})
}

// p2pServe GET /api/p2p/serve —— 看可被打洞入口的状态。
func (s *Server) p2pServeGet(c *gin.Context) {
	ok(c, 200, gin.H{"serve": s.p2pServeState()})
}

// p2pServeSet POST /api/p2p/serve {on, peer} —— 开/关可被打洞入口，可选指定反向打洞对端。
//
// 为什么要 peer：本机 NAT 若是 address/port-dependent filtering（常见），
// **纯被动应答收不到第一个包** —— 必须双方同时向对方映射发包。peer 就是「对端的映射地址」
// （对端 `ncc registry p2p serve` 或 `p2p self` 里报出的 mapped），给了它本机就会主动反向发。
//
// 这是**显式动作**：开了之后本节点会对外应答 STUN Binding 请求（只回一行映射信息，
// 不碰业务字节），等于告诉别人「这台机器在这儿」。所以要登录 + 作用域。
func (s *Server) p2pServeSet(c *gin.Context) {
	var body struct {
		On   *bool  `json:"on"`
		Peer string `json:"peer"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.On == nil {
		fail(c, 400, "bad_request", "请求体需要 {on: true|false, peer?: \"ip:port\"}")
		return
	}
	var peers []*net.UDPAddr
	for _, raw := range strings.Split(body.Peer, ",") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		p, err := p2p.ParsePeerAddr(raw)
		if err != nil {
			fail(c, 400, "bad_request", "peer 格式不对："+err.Error())
			return
		}
		peers = append(peers, p)
	}

	s.p2pMu.Lock()
	defer s.p2pMu.Unlock()
	if *body.On {
		if s.p2pResponder == nil {
			r, err := p2p.StartResponder(s.Cfg.P2PSTUN, 3*time.Second)
			if err != nil {
				fail(c, 500, "internal", "启动打洞入口失败："+err.Error())
				return
			}
			s.p2pResponder = r
			logf("p2p.serve 已开启 listen=%s mapped=%s", r.Addr(), r.MappedAddr())
		}
		// 只有显式给了非空 peer 才覆盖，避免单纯的 --on 把已配的对端抹掉。
		if len(peers) > 0 {
			s.p2pResponder.SetPeers(peers)
		}
	} else {
		if s.p2pResponder != nil {
			s.p2pResponder.Close()
			s.p2pResponder = nil
			logf("p2p.serve 已关闭")
		}
	}
	ok(c, 200, gin.H{"serve": serveStateOf(s.p2pResponder)})
}

// p2pServeState 入口状态（未开时也给一句怎么开）。
// 注意：调用方若已持有 s.p2pMu，请直接用 serveStateOf，别再走这里（同把锁会自锁死）。
func (s *Server) p2pServeState() gin.H {
	s.p2pMu.Lock()
	r := s.p2pResponder
	s.p2pMu.Unlock()
	return serveStateOf(r)
}

// serveStateOf 只读一个 responder 快照，不碰 Server 的锁。
func serveStateOf(r *p2p.Responder) gin.H {
	if r == nil {
		return gin.H{
			"on": false,
			"hint": "要让别人能打洞过来：NCCR_P2P_SERVE=1 起服务，或 `ncc registry p2p serve --on`" +
				"（只应答 STUN，不接收业务字节）",
		}
	}
	return gin.H{
		"on":            true,
		"listen":        r.Addr(),
		"mapped":        r.MappedAddr(), // 对端应该发往这个地址
		"requestsTaken": r.Requests(),
		"responsesSeen": r.Responses(),
		"peers":         peerStrings(r.Peers()),
		"note":          "NAT 过滤若是 address/port-dependent（常见），只被动应答收不到第一个包：必须双方同时向对方映射发包（用 peer 指定对端）。",
	}
}

func peerStrings(peers []*net.UDPAddr) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.String())
	}
	return out
}

// auditP2P 已删除：P2P 检查走日志（见 p2pCheck 里的说明）。
