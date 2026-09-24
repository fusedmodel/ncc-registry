package httpapi

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/fusedmodel/ncc-registry/model"
	"github.com/fusedmodel/ncc-registry/store"
)

// 接入票据：把「一个内网 registry」加进 Agent 的两种方式，用的是同一张票据。
//
//	key + secret  手工填（key 短、可念；secret 只显示一次，库里只存哈希）
//	接入短链      <publicURL>/j/<key>#<secret> —— secret 放 fragment，
//	              不进服务端日志、不进 Referer，点开/粘贴即可接入
//
// 兑换（redeem）拿到的是一枚**节点令牌**：只能做票据给的事（默认：上报自己的心跳 +
// 读公开制品），不能发布、不能改别人的东西。票据可限次、可过期、可停用。

/* ---------------- 参数 ---------------- */

type ticketCreateReq struct {
	Label         string   `json:"label"`
	Uses          int64    `json:"uses"`          // 0 = 不限次
	ExpiresInDays int64    `json:"expiresInDays"` // 0 = 不过期
	Scopes        []string `json:"scopes"`        // 缺省 = NodeTicketScopes
	Namespace     string   `json:"namespace"`     // 缺省 = 创建者的个人命名空间
}

type ticketNodeReq struct {
	Name         string   `json:"name"`
	Slug         string   `json:"slug"`
	Kind         string   `json:"kind"`
	Region       string   `json:"region"`
	URL          string   `json:"url"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	Version      string   `json:"version"`
	Agent        string   `json:"agent"`
	Capabilities []string `json:"capabilities"`
}

type redeemReq struct {
	Key    string         `json:"key"`
	Secret string         `json:"secret"`
	Node   *ticketNodeReq `json:"node"` // 可选：兑换的同时把本机作为一个节点托管进来
}

/* ---------------- 票据管理（需登录 + keys:write） ---------------- */

// createTicket POST /api/access/tickets
//
// 签发凭据属于敏感动作，沿用 keys:write 作用域（默认不发给普通 API-Key）。
func (s *Server) createTicket(c *gin.Context) {
	a := authOf(c)
	var body ticketCreateReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	scopes := make([]string, 0, len(body.Scopes))
	for _, sc := range body.Scopes {
		if ValidScope(sc) {
			scopes = append(scopes, sc)
		}
	}
	if len(scopes) == 0 {
		scopes = append(scopes, NodeTicketScopes...)
	}

	ns, err := s.ticketNamespace(a.UserID, body.Namespace)
	if err != nil {
		fail(c, errStatus(err), errCode(err), err.Error())
		return
	}

	var expiresAt *time.Time
	if body.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, int(body.ExpiresInDays))
		expiresAt = &t
	}
	if body.Uses < 0 {
		body.Uses = 0
	}
	label := strings.TrimSpace(body.Label)
	if len([]rune(label)) > 60 {
		label = string([]rune(label)[:60])
	}

	key, secret := store.NewTicketKey(), store.NewTicketSecret()
	tk, err := s.St.CreateAccessTicket(key, secret, label, scopes, ns.ID, a.UserID, body.Uses, expiresAt)
	if err != nil {
		fail(c, 500, "internal", "签发接入票据失败")
		return
	}
	ok(c, 201, gin.H{
		"ticket": s.ticketJSON(tk, ns.Slug),
		"secret": secret, // 仅此一次返回
		"link":   s.ticketLink(tk.Key, secret),
		"howto": gin.H{
			"link":   "把 link 发给对方：粘贴到 Agent 插件里，或 ncc registry add <link>",
			"manual": "或把 key/secret 分开给：ncc registry add --base " + s.Cfg.PublicURL + " --key " + tk.Key + " --secret <secret>",
		},
	})
}

// listTickets GET /api/access/tickets
func (s *Server) listTickets(c *gin.Context) {
	a := authOf(c)
	rows, err := s.St.ListTickets(a.UserID)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	slugs := map[string]string{}
	for i := range rows {
		if rows[i].NamespaceID != "" {
			if ns, err := s.St.FindNamespaceByID(rows[i].NamespaceID); err == nil {
				slugs[ns.ID] = ns.Slug
			}
		}
	}
	list := make([]gin.H, 0, len(rows))
	for i := range rows {
		list = append(list, s.ticketJSON(&rows[i], slugs[rows[i].NamespaceID]))
	}
	ok(c, 200, gin.H{"tickets": list, "total": len(list)})
}

// deleteTicket DELETE /api/access/tickets/:id —— 停用即失效（已兑换的令牌到期前仍有效，
// 但节点令牌的 TTL 由票据决定，重新签发一次即可收缩窗口）。
func (s *Server) deleteTicket(c *gin.Context) {
	a := authOf(c)
	if err := s.St.DeleteTicket(c.Param("id"), a.UserID); err != nil {
		fail(c, 500, "internal", "删除失败")
		return
	}
	ok(c, 200, gin.H{"ok": true})
}

// ticketInfo GET /api/access/tickets/:key —— 公开的票据概要（不含 secret），
// 接入页与 CLI 用它先确认「这是谁的内网 registry、票据还能用几次」。
func (s *Server) ticketInfo(c *gin.Context) {
	tk, err := s.St.FindTicketByKey(c.Param("key"))
	if err != nil {
		fail(c, 404, "not_found", "票据不存在")
		return
	}
	nsSlug := ""
	if ns, err := s.St.FindNamespaceByID(tk.NamespaceID); err == nil {
		nsSlug = ns.Slug
	}
	out := s.ticketJSON(tk, nsSlug)
	out["usable"] = tk.Usable(time.Now())
	out["registry"] = s.registryBlock()
	ok(c, 200, gin.H{"ticket": out, "registry": s.registryBlock()})
}

/* ---------------- 兑换（公开：key + secret） ---------------- */

// redeem POST /api/access/redeem
//
// 客户端（CLI / Agent 插件 / 接入页）拿 key+secret 换一枚节点令牌。
// 带上 node 字段就同时把本机托管进来 —— 「用一条短链加进内网 registry」就是这一步。
func (s *Server) redeem(c *gin.Context) {
	var body redeemReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	tk, err := s.St.FindTicketByKey(body.Key)
	if err != nil {
		fail(c, 404, "ticket_not_found", "key 不存在（票据可能已被删除）")
		return
	}
	if store.HashSecret(strings.TrimSpace(body.Secret)) != tk.SecretHash {
		fail(c, 401, "bad_secret", "secret 不正确")
		return
	}
	if !tk.Usable(time.Now()) {
		fail(c, 403, "ticket_unusable", "票据已停用、已过期或次数用尽")
		return
	}
	var creator *model.User
	if u, err := s.St.FindUserByID(tk.CreatedBy); err == nil {
		creator = u
	} else {
		fail(c, 403, "ticket_unusable", "票据签发者已不存在")
		return
	}
	ns, err := s.ticketNamespace(creator.ID, "")
	if tk.NamespaceID != "" {
		if n, err2 := s.St.FindNamespaceByID(tk.NamespaceID); err2 == nil {
			ns = n
		}
	}
	if ns == nil {
		fail(c, 500, "internal", "票据没有可用命名空间")
		return
	}

	scopes := store.ParseList(tk.Scopes)
	if len(scopes) == 0 {
		scopes = append(scopes, NodeTicketScopes...)
	}

	// 可选：兑换即入网（注册 + 首次心跳）
	nodeOut := gin.H(nil)
	nodeID := ""
	if body.Node != nil && strings.TrimSpace(body.Node.Name) != "" {
		row, created, err := s.St.UpsertHostedNode(store.UpsertNodeInput{
			NamespaceID: ns.ID, Name: strings.TrimSpace(body.Node.Name),
			Slug:   store.Slugify(firstNonEmpty(body.Node.Slug, body.Node.Name)),
			Kind:   body.Node.Kind,
			Region: strings.TrimSpace(body.Node.Region),
			URL:    strings.TrimSpace(body.Node.URL),
			OS:     body.Node.OS, Arch: body.Node.Arch, Version: body.Node.Version,
			Agent: body.Node.Agent, Capabilities: body.Node.Capabilities,
			Visibility: "public",
		})
		if err != nil {
			fail(c, 500, "internal", "入网注册失败")
			return
		}
		nodeID = row.ID
		if full, err := s.St.FindNodeRow(row.ID, creator.ID); err == nil {
			nodeOut = nodeJSON(full, s.Cfg.NodeTTL)
		}
		nodeOut["created"] = created
	}

	ttl := s.Cfg.AccessTTL
	if tk.ExpiresAt != nil {
		if left := time.Until(*tk.ExpiresAt); left > 0 && left < ttl {
			ttl = left
		}
	}
	token := signClaims(s.Cfg.JWTSecret, tokenClaims{
		Sub: creator.ID, Kind: "node", Node: nodeID, Scope: scopes,
	}, ttl)
	if token == "" {
		fail(c, 500, "internal", "签发令牌失败")
		return
	}
	_ = s.St.MarkTicketUsed(tk.ID)

	ok(c, 200, gin.H{
		"token":     token,
		"expiresAt": time.Now().Add(ttl),
		"scopes":    scopes,
		"node":      nodeOut,
		"registry":  s.registryBlock(),
		"ticket":    gin.H{"id": tk.ID, "key": tk.Key, "label": tk.Label},
		"owner":     gin.H{"id": creator.ID, "name": creator.Name, "namespace": ns.Slug},
	})
}

/* ---------------- 接入页（短链落地页） ---------------- */

// joinPage GET /j/:key —— 短链的可读落地页。
//
// secret 在 fragment（#）里，浏览器不会把它发给服务端；页面用 JS 读出来，
// 生成可复制的 CLI 命令，并提供「在这个浏览器里接入」按钮。
func (s *Server) joinPage(c *gin.Context) {
	key := c.Param("key")
	tk, err := s.St.FindTicketByKey(key)
	if err != nil {
		c.Data(404, "text/html; charset=utf-8", []byte(joinPageHTML(key, "票据不存在（可能已被删除）", false, s.Cfg.PublicURL, "")))
		return
	}
	nsSlug := ""
	if ns, err := s.St.FindNamespaceByID(tk.NamespaceID); err == nil {
		nsSlug = ns.Slug
	}
	usable := tk.Usable(time.Now())
	note := "票据有效"
	if !usable {
		note = "票据已停用、已过期或次数用尽"
	}
	c.Data(200, "text/html; charset=utf-8", []byte(joinPageHTML(tk.Key, note, usable, s.Cfg.PublicURL, nsSlug)))
}

/* ---------------- 工具 ---------------- */

// ticketNamespace 解析票据落到哪个命名空间（为空 = 创建者的个人空间）。
func (s *Server) ticketNamespace(userID, slug string) (*model.Namespace, error) {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		ns, err := s.St.PersonalNamespace(userID)
		if err != nil {
			return nil, errWith(400, "bad_request", "当前账号没有个人命名空间，请重新注册")
		}
		return ns, nil
	}
	ns, err := s.St.FindNamespaceBySlug(slug)
	if err != nil {
		return nil, errWith(400, "bad_request", "namespace "+slug+" 不存在")
	}
	if !s.canManage(ns.ID, userID) {
		return nil, errWith(403, "forbidden", "你不是该 namespace 的 owner/成员")
	}
	return ns, nil
}

// ticketLink 接入短链：secret 放 fragment。
func (s *Server) ticketLink(key, secret string) string {
	return strings.TrimRight(s.Cfg.PublicURL, "/") + "/j/" + key + "#" + secret
}

func (s *Server) ticketJSON(t *model.AccessTicket, nsSlug string) gin.H {
	out := gin.H{
		"id": t.ID, "key": t.Key, "label": t.Label,
		"scopes":    store.ParseList(t.Scopes),
		"uses":      gin.H{"max": t.MaxUses, "used": t.UsedCount},
		"namespace": gin.H{"id": t.NamespaceID, "slug": nsSlug},
		"expiresAt": t.ExpiresAt, "disabled": t.Disabled,
		"lastUsedAt": t.LastUsedAt, "createdAt": t.CreatedAt,
		"usable": t.Usable(time.Now()),
		// 短链本身不带 secret（secret 只在创建时返回一次），这里给的是「补上 secret 后的样子」。
		"linkPattern": strings.TrimRight(s.Cfg.PublicURL, "/") + "/j/" + t.Key + "#<secret>",
	}
	return out
}

// registryBlock 「这个内网 registry 是什么」—— 接入前后都用同一段信息。
func (s *Server) registryBlock() gin.H {
	artifacts, nodes, users := s.Counts()
	return gin.H{
		"base": s.Cfg.PublicURL, "role": s.Cfg.Role,
		"nodeId": s.Cfg.NodeID, "nodeName": s.Cfg.NodeName,
		"region": s.Cfg.NodeRegion, "version": Version,
		"console": s.Cfg.PublicURL + "/",
		"counts":  gin.H{"artifacts": artifacts, "hostedNodes": nodes, "users": users},
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
