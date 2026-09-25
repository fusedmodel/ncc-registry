package httpapi

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/fusedmodel/ncc-registry/model"
	"github.com/fusedmodel/ncc-registry/store"
)

/* ---------------- 提供能力（offers） ---------------- */

// nodeOffers GET /api/nodes/offers —— 节点「提供能力」词表。
//
// 与 /api/nodes/kinds 并列：kinds 回答「它是什么」（service / agent / assigned），
// offers 回答「它能提供什么」（跑什么、有没有出口、托管什么）。
// 检索入口：/api/nodes/discover?can=run:wasm&can=egress:llm（**全都要**）。
func (s *Server) nodeOffers(c *gin.Context) {
	list := make([]gin.H, 0, len(model.NodeOffers))
	for _, o := range model.NodeOffers {
		list = append(list, gin.H{
			"id": o.ID, "zh": o.Zh, "en": o.En, "descZh": o.Desc, "descEn": o.DescEn,
		})
	}
	aliases := model.OfferAliases()
	aliasOut := make([]gin.H, 0, len(aliases))
	for _, a := range aliases {
		aliasOut = append(aliasOut, gin.H{"from": a.From, "to": a.To})
	}
	ok(c, 200, gin.H{
		"offers": list, "total": len(list), "aliases": aliasOut,
		"note": "上报：ncc living --name x --kind service --capabilities run:wasm,egress:llm；" +
			"历史短名（mcp / api / wasm / llm …）会被归一成规范 id；不在词表里的 id 原样保留。" +
			"检索 ?can= 是「全都要」；未在词表里的 id 也照旧能精确搜到。" +
			"另可在 id 后加 @verified（如 can=run:wasm@verified）——只要**自证**具备该能力的节点；" +
			"自证同样比声明强：can=X 也匹配只把 X 放在自证里的节点。",
	})
}

// offerEcho 把解析后的条件还原成 `id` / `id@verified`，用于响应回显。
func offerEcho(qs []model.OfferQuery) []string {
	out := make([]string, 0, len(qs))
	for _, q := range qs {
		if q.VerifiedOnly {
			out = append(out, q.ID+"@verified")
			continue
		}
		out = append(out, q.ID)
	}
	return out
}

// offerQuery 解析 `?can=`：可重复传，也可用逗号分隔。
// 语法 `<id>`（声明或自证）或 `<id>@verified`（只要自证的），见 model.ParseOfferQuery。
func offerQuery(c *gin.Context) []model.OfferQuery {
	var out []model.OfferQuery
	seen := map[string]bool{}
	for _, raw := range c.QueryArray("can") {
		for _, part := range strings.Split(raw, ",") {
			q := model.ParseOfferQuery(part)
			if q.ID == "" {
				continue
			}
			key := fmt.Sprintf("%s|%v", q.ID, q.VerifiedOnly)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, q)
		}
	}
	return out
}

// hasAllOffers 节点是否同时满足每一条：`<id>` = 声明**或**自证里有；`<id>@verified` = 自证里才有。
func hasAllOffers(caps, verified string, want []model.OfferQuery) bool {
	if len(want) == 0 {
		return true
	}
	set := func(csv string) map[string]bool {
		m := map[string]bool{}
		for _, v := range model.NormalizeOffers(store.ParseList(csv)) {
			m[v] = true
		}
		return m
	}
	declared, proved := set(caps), set(verified)
	for _, w := range want {
		if w.VerifiedOnly {
			if !proved[w.ID] {
				return false
			}
			continue
		}
		if !declared[w.ID] && !proved[w.ID] {
			return false
		}
	}
	return true
}

/* ---------------- 节点上报（注册 + 心跳合并） ---------------- */

type nodeHeartbeatReq struct {
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
	// OffersVerified 本机**自证**的提供能力（客户端由硬事实推导出来的，不是运营者自选）。
	// 服务端只如实收下并按 `?can=<id>@verified` 检索，不做任何验证 ——
	// 「自证」的含义是「节点自己声称有硬证据」，不是「NCC 校验过」。
	OffersVerified []string `json:"offersVerified"`
	Visibility     string   `json:"visibility"`
	// Namespace 目标命名空间 slug（缺省 = 个人命名空间）。
	Namespace string `json:"namespace"`
}

// nodeHeartbeat POST /api/nodes/heartbeat（别名 POST /api/namespaces/living）
//
// 节点自己声明它是什么：service / agent / assigned。注册与心跳是同一件事 ——
// 第一次上报即注册，之后每次上报续租 LastSeen。
func (s *Server) nodeHeartbeat(c *gin.Context) {
	a := authOf(c)
	var body nodeHeartbeatReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		fail(c, 400, "bad_request", "name 不能为空")
		return
	}
	if body.Kind != "" && !model.ValidNodeKind(body.Kind) {
		fail(c, 400, "bad_request", "kind 只能是 service/agent/assigned")
		return
	}

	// 节点令牌（由接入票据兑换）只能续租自己被签发的那个节点：
	// 不能拿一张票据往别人的命名空间里塞任意节点。
	if a.Kind == "node" && a.NodeID != "" {
		bound, err := s.St.FindNodeRow(a.NodeID, a.UserID)
		if err != nil {
			fail(c, 403, "forbidden", "节点令牌只允许上报自己被签发的节点")
			return
		}
		body.Namespace = bound.NsSlug
		body.Slug = bound.Slug
		if strings.TrimSpace(body.Name) == "" {
			body.Name = bound.Name
		}
	}

	ns, err := s.targetNamespace(a.UserID, body.Namespace)
	if err != nil {
		fail(c, 400, "bad_request", err.Error())
		return
	}

	slug := store.Slugify(body.Slug)
	if strings.TrimSpace(body.Slug) == "" || slug == "x" {
		slug = store.Slugify(body.Name)
	}
	if slug == "x" {
		slug = "node-" + store.RandHex(3)
	}

	row, created, err := s.St.UpsertHostedNode(store.UpsertNodeInput{
		NamespaceID: ns.ID, Name: strings.TrimSpace(body.Name), Slug: slug,
		Kind: body.Kind, Region: strings.TrimSpace(body.Region), URL: strings.TrimSpace(body.URL),
		OS: body.OS, Arch: body.Arch, Version: body.Version, Agent: body.Agent,
		Capabilities: body.Capabilities, OffersVerified: body.OffersVerified, Visibility: body.Visibility,
	})
	if err != nil {
		fail(c, 500, "internal", "节点上报失败")
		return
	}
	node, err := s.St.FindNodeByNsSlug(ns.Slug, row.Slug, a.UserID)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	status := 200
	if created {
		status = 201
	}
	ok(c, status, gin.H{
		"node":    nodeJSON(node, s.Cfg.NodeTTL),
		"created": created,
		"registry": gin.H{
			"id": s.Cfg.NodeID, "name": s.Cfg.NodeName, "role": s.Cfg.Role, "url": s.Cfg.PublicURL,
		},
	})
}

// targetNamespace 解析目标命名空间并校验写权限。
func (s *Server) targetNamespace(userID, slug string) (*model.Namespace, error) {
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

// deleteNode DELETE /api/nodes/:id —— 主动下线（下次心跳会重新注册）。
func (s *Server) deleteNode(c *gin.Context) {
	a := authOf(c)
	row, err := s.St.FindNodeRow(c.Param("id"), a.UserID)
	if err != nil {
		fail(c, 404, "not_found", "节点不存在")
		return
	}
	if !s.canManage(row.NamespaceID, a.UserID) {
		fail(c, 403, "forbidden", "你不是该节点的 owner/成员")
		return
	}
	if err := s.St.DeleteHostedNode(row.ID, row.NamespaceID); err != nil {
		fail(c, 500, "internal", "下线失败")
		return
	}
	ok(c, 200, gin.H{"ok": true, "id": row.ID})
}

/* ---------------- 我的节点 / 连接表 / 发现 ---------------- */

// listNodes GET /api/nodes —— 我的节点 + 我连接的节点。
func (s *Server) listNodes(c *gin.Context) {
	a := authOf(c)
	want := offerQuery(c)
	nss, err := s.St.NamespacesOfUser(a.UserID)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	ids := make([]string, 0, len(nss))
	for i := range nss {
		ids = append(ids, nss[i].ID)
	}

	mine := []gin.H{}
	if len(ids) > 0 {
		rows, err := s.St.ListNodesOfNamespaces(a.UserID, ids)
		if err != nil {
			fail(c, 500, "internal", "服务内部错误")
			return
		}
		for i := range rows {
			if !hasAllOffers(rows[i].Capabilities, rows[i].OffersVerified, want) {
				continue
			}
			mine = append(mine, nodeJSON(&rows[i], s.Cfg.NodeTTL))
		}
	}
	linked := []gin.H{}
	rows, err := s.St.ListLinkedNodes(a.UserID)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	for i := range rows {
		if !hasAllOffers(rows[i].Capabilities, rows[i].OffersVerified, want) {
			continue
		}
		linked = append(linked, nodeJSON(&rows[i], s.Cfg.NodeTTL))
	}

	online := 0
	for _, n := range append(append([]gin.H{}, mine...), linked...) {
		if n["online"] == true {
			online++
		}
	}
	ok(c, 200, gin.H{
		"nodes": mine, "linked": linked,
		"mine": len(mine), "total": len(mine) + len(linked), "online": online,
		"ttlSec": int64(s.Cfg.NodeTTL.Seconds()),
	})
}

// nodeKinds GET /api/nodes/kinds
func (s *Server) nodeKinds(c *gin.Context) {
	labels := map[string][2]string{
		model.NodeService:  {"服务", "对外提供能力的服务（API / MCP / 网关 / 数据源）"},
		model.NodeAgent:    {"为人服务的 Agent", "某个人自己的 Agent"},
		model.NodeAssigned: {"被分配的 Agent", "被指派给某个任务/团队/客户的 Agent"},
	}
	list := make([]gin.H, 0, len(model.NodeKinds))
	for _, k := range model.NodeKinds {
		l, d := labels[k][0], labels[k][1]
		list = append(list, gin.H{"kind": k, "label": l, "desc": d})
	}
	ok(c, 200, gin.H{"kinds": list, "total": len(list)})
}

// discoverNodes GET /api/nodes/discover —— 本实例上可连接的公开节点。
//
// can 可以重复传（或逗号分隔），语义是「**同时具备**这些提供能力」。
func (s *Server) discoverNodes(c *gin.Context) {
	a := authOf(c)
	uid := ""
	if a != nil {
		uid = a.UserID
	}
	want := offerQuery(c)
	rows, err := s.St.ListPublicNodes(uid, s.grantedOwners(uid), c.Query("kind"), c.Query("region"), c.Query("q"), want, 100)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	list := make([]gin.H, 0, len(rows))
	for i := range rows {
		list = append(list, nodeJSON(&rows[i], s.Cfg.NodeTTL))
	}
	ok(c, 200, gin.H{"nodes": list, "total": len(list), "can": offerEcho(want)})
}

// nodeRegions GET /api/nodes/regions —— 区域覆盖（Agent 面：按区域找节点）。
func (s *Server) nodeRegions(c *gin.Context) {
	counts, err := s.St.RegionCounts(s.Cfg.NodeTTL)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	list := make([]gin.H, 0, len(counts))
	for _, c := range counts {
		list = append(list, gin.H{"region": c.Region, "total": c.Total, "online": c.Online})
	}
	ok(c, 200, gin.H{"regions": list, "ttlSec": int64(s.Cfg.NodeTTL.Seconds())})
}

/* ---------------- 连接（我这边的一份清单，不需要对方审批） ---------------- */

// linkNode POST /api/nodes/links —— body: {node: "@ns/slug" 或 id, label, note}
func (s *Server) linkNode(c *gin.Context) {
	a := authOf(c)
	var body struct {
		Node  string `json:"node"`
		Label string `json:"label"`
		Note  string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	row, err := s.resolveNode(a.UserID, body.Node)
	if err != nil {
		fail(c, errStatus(err), errCode(err), err.Error())
		return
	}
	if row.OwnerID == a.UserID {
		fail(c, 400, "bad_request", "这是你自己的节点，不需要连接")
		return
	}
	if !s.canSeeNode(row, a.UserID) {
		fail(c, 403, "grant_required", "该节点不是公开节点；需要对方用 ncc grant set --user @你 --kind node 授权")
		return
	}
	if existing, err := s.St.FindLink(a.UserID, row.ID); err == nil {
		_ = s.St.UpdateLink(existing.ID, a.UserID, strings.TrimSpace(body.Label), strings.TrimSpace(body.Note))
		ok(c, 200, gin.H{"link": gin.H{"id": existing.ID, "nodeId": row.ID, "label": body.Label, "note": body.Note}, "created": false})
		return
	}
	link, err := s.St.LinkNode(a.UserID, row.ID, row.OwnerID, strings.TrimSpace(body.Label), strings.TrimSpace(body.Note))
	if err != nil {
		fail(c, 500, "internal", "连接失败")
		return
	}
	ok(c, 201, gin.H{"link": gin.H{"id": link.ID, "nodeId": row.ID, "label": link.Label, "note": link.Note}, "created": true})
}

// patchNodeLink PATCH /api/nodes/links/:id
func (s *Server) patchNodeLink(c *gin.Context) {
	a := authOf(c)
	var body struct {
		Label *string `json:"label"`
		Note  *string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	link, err := s.St.FindLinkByID(c.Param("id"), a.UserID)
	if err != nil {
		fail(c, 404, "not_found", "连接不存在")
		return
	}
	label, note := link.Label, link.Note
	if body.Label != nil {
		label = strings.TrimSpace(*body.Label)
	}
	if body.Note != nil {
		note = strings.TrimSpace(*body.Note)
	}
	if err := s.St.UpdateLink(link.ID, a.UserID, label, note); err != nil {
		fail(c, 500, "internal", "更新失败")
		return
	}
	ok(c, 200, gin.H{"link": gin.H{"id": link.ID, "nodeId": link.NodeID, "label": label, "note": note}})
}

// deleteNodeLink DELETE /api/nodes/links/:id
func (s *Server) deleteNodeLink(c *gin.Context) {
	a := authOf(c)
	if err := s.St.UnlinkNode(c.Param("id"), a.UserID); err != nil {
		fail(c, 500, "internal", "断开失败")
		return
	}
	ok(c, 200, gin.H{"ok": true})
}

// resolveNode 解析节点引用：@ns/slug 或 ND-… id。
func (s *Server) resolveNode(ownerID, ref string) (*store.NodeRow, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errNodeNotFound
	}
	if strings.HasPrefix(ref, "@") {
		body := strings.TrimPrefix(ref, "@")
		if i := strings.Index(body, "/"); i > 0 {
			return s.St.FindNodeByNsSlug(body[:i], body[i+1:], ownerID)
		}
		return nil, errNodeNotFound
	}
	return s.St.FindNodeRow(ref, ownerID)
}

var (
	errNodeNotFound  = errWith(404, "not_found", "节点不存在")
	errNodeForbidden = errWith(403, "forbidden", "无权访问该节点")
)
