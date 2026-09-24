package httpapi

import (
	"crypto/rand"
	"math/big"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/fusedmodel/ncc-registry/model"
	"github.com/fusedmodel/ncc-registry/store"
)

// 节点治理面（/api/admin/*）：用户 / 节点 / 服务的查看与处理，每个动作都写审计。
//
// 两种凭据都能进：
//
//	人    本节点管理员账号的会话（User.IsAdmin —— 第一个注册用户自动获得）
//	机器  X-NCC-Admin-Key + X-NCC-Admin-Secret（AK-… + secret），给 CI / 运维脚本
//
// 机器凭据刻意**不并进 authMiddleware**：治理权（管人、管节点）与资产权（看/发制品、
// 上报心跳）权限面完全不同，混在一条判定链上，迟早出「一个漏判放行全站」的事故。
// 所以 admin 路由只认 requireAdmin 这一道门。

type adminActor struct {
	Kind string // user | admin_key
	ID   string
	Name string
}

const adminCtxKey = "nccr:admin"

// requireAdmin 管理员门禁。会话管理员与 admin key/secret 等价。
func (s *Server) requireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if a := authOf(c); a != nil && a.Session {
			if u, err := s.St.FindUserByID(a.UserID); err == nil && u.IsAdmin && !u.Disabled {
				c.Set(adminCtxKey, &adminActor{Kind: model.ActorUser, ID: u.ID, Name: u.Email})
				c.Next()
				return
			}
			fail(c, 403, "admin_required", "本账号不是节点管理员")
			c.Abort()
			return
		}
		key := strings.TrimSpace(c.GetHeader("X-NCC-Admin-Key"))
		secret := strings.TrimSpace(c.GetHeader("X-NCC-Admin-Secret"))
		if key != "" || secret != "" {
			if key == "" || secret == "" {
				fail(c, 400, "bad_request", "admin key 与 secret 必须同时提供")
				c.Abort()
				return
			}
			k, err := s.St.FindAdminKey(key)
			if err != nil || !k.Active() || store.HashSecret(secret) != k.SecretHash {
				fail(c, 401, "admin_credentials_invalid", "admin key/secret 不正确或已被轮换")
				c.Abort()
				return
			}
			_ = s.St.TouchAdminKey(k.ID)
			c.Set(adminCtxKey, &adminActor{Kind: model.ActorAdminKey, ID: k.Key, Name: firstNonEmpty(k.Label, k.Key)})
			c.Next()
			return
		}
		fail(c, 403, "admin_required", "需要节点管理员身份：管理员账号登录，或带 admin key/secret")
		c.Abort()
	}
}

func adminOf(c *gin.Context) *adminActor {
	if v, ok := c.Get(adminCtxKey); ok {
		if a, ok := v.(*adminActor); ok {
			return a
		}
	}
	return nil
}

// audit 记一条管理动作。失败只记日志 —— 审计写不进去不该让业务操作回滚，
// 但一定要在服务端留下痕迹（否则就是「悄悄丢失的审计」）。
func (s *Server) audit(c *gin.Context, action, target, targetName, summary string, detail gin.H) {
	a := adminOf(c)
	if a == nil {
		return
	}
	raw := ""
	if len(detail) > 0 {
		if b, err := jsonMarshal(detail); err == nil {
			raw = string(b)
		}
	}
	if raw == "" {
		raw = "{}"
	}
	entry := &model.AuditLog{
		ActorKind: a.Kind, ActorID: a.ID, ActorName: a.Name,
		Action: action, Target: target, TargetName: targetName,
		Summary: summary, Detail: raw, IP: c.ClientIP(),
	}
	if err := s.St.AppendAudit(entry); err != nil {
		logf("审计写入失败 action=%s target=%s: %v", action, target, err)
	}
}

func auditJSON(l *model.AuditLog) gin.H {
	return gin.H{
		"id": l.ID, "actor": gin.H{"kind": l.ActorKind, "id": l.ActorID, "name": l.ActorName},
		"action": l.Action, "target": l.Target, "targetName": l.TargetName,
		"summary": l.Summary, "detail": parseJSONAny(l.Detail), "ip": l.IP,
		"createdAt": l.CreatedAt,
	}
}

/* ---------------- 概览 ---------------- */

// adminOverview GET /api/admin/overview
func (s *Server) adminOverview(c *gin.Context) {
	users, _ := s.St.CountUsersFiltered("")
	admins, _ := s.St.CountAdmins()
	nodes, _ := s.St.CountAllNodes("", "", "")
	kinds, _ := s.St.NodeKindCounts()
	services, _ := s.St.CountServiceArtifacts("", "")
	artifacts, _ := s.St.CountArtifacts()
	configs, _ := s.St.CountConfigs()
	shares, _ := s.St.CountShares("")
	activeShares, _ := s.St.CountActiveShares()
	actions, _ := s.St.CountAudit("")
	ok(c, 200, gin.H{
		"node": s.registryBlock(),
		"counts": gin.H{
			"users": users, "admins": admins,
			"nodes": nodes, "nodeKinds": kinds,
			"services":     gin.H{"hostedNodes": kinds[model.NodeService], "artifacts": services},
			"artifacts":    artifacts,
			"configs":      configs,
			"shares":       shares,
			"activeShares": activeShares,
			"auditActions": actions,
		},
		"credential": gin.H{
			"kind": adminOf(c).Kind, "name": adminOf(c).Name,
		},
	})
}

/* ---------------- 用户 ---------------- */

func adminUserJSON(r *store.AdminUserRow) gin.H {
	return gin.H{
		"id": r.ID, "email": r.Email, "name": r.Name, "plan": r.Plan,
		"isAdmin": r.IsAdmin, "disabled": r.Disabled, "disabledAt": r.DisabledAt,
		"adminNote": r.AdminNote, "lastLoginAt": r.LastLoginAt, "createdAt": r.CreatedAt,
		"stats": gin.H{"nodes": r.Nodes, "artifacts": r.Artifacts},
	}
}

// adminListUsers GET /api/admin/users?q=&limit=&offset=
func (s *Server) adminListUsers(c *gin.Context) {
	q := c.Query("q")
	limit, offset := pageParams(c)
	rows, err := s.St.ListUsers(q, limit, offset)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	total, _ := s.St.CountUsersFiltered(q)
	list := make([]gin.H, 0, len(rows))
	for i := range rows {
		list = append(list, adminUserJSON(&rows[i]))
	}
	ok(c, 200, gin.H{"users": list, "total": total, "limit": limit, "offset": offset})
}

type adminUserPatchReq struct {
	Disabled  *bool   `json:"disabled"`
	AdminNote *string `json:"adminNote"`
}

// adminPatchUser PATCH /api/admin/users/:id —— 禁用 / 启用 + 备注。
//
// 两条硬规则：
//   - 不能禁用最后一个可用管理员（否则这台节点再也没人能管）；
//   - 不能禁用自己的账号（避免「点了就自锁」）。
func (s *Server) adminPatchUser(c *gin.Context) {
	id := c.Param("id")
	target, err := s.St.FindUserByID(id)
	if err != nil {
		fail(c, 404, "not_found", "用户不存在")
		return
	}
	var body adminUserPatchReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	me := adminOf(c)
	if body.Disabled != nil {
		next := *body.Disabled
		if next != target.Disabled {
			// 「不能禁自己」只对人说的：admin key 不是账号，禁不到它头上。
			if next && me.Kind == model.ActorUser && target.ID == me.ID {
				fail(c, 400, "bad_request", "不能禁用自己的账号")
				return
			}
			if next && target.IsAdmin {
				if n, _ := s.St.CountAdmins(); n <= 1 {
					fail(c, 400, "last_admin", "这是最后一个可用管理员，不能禁用")
					return
				}
			}
			note := ""
			if body.AdminNote != nil {
				note = *body.AdminNote
			}
			if err := s.St.SetUserDisabled(target.ID, next, note); err != nil {
				fail(c, 500, "internal", "更新失败")
				return
			}
			action, summary := model.ActUserDisable, "禁用账号"
			if !next {
				action, summary = model.ActUserEnable, "启用账号"
			}
			s.audit(c, action, target.ID, target.Email, summary, gin.H{"note": note})
			target.Disabled = next
		} else if body.AdminNote != nil {
			if err := s.St.SetUserDisabled(target.ID, target.Disabled, *body.AdminNote); err != nil {
				fail(c, 500, "internal", "更新失败")
				return
			}
			s.audit(c, model.ActUserEnable, target.ID, target.Email, "更新备注", gin.H{"note": *body.AdminNote})
		}
	}
	// 回读一次，保证响应是库里的真实状态。
	if fresh, err := s.St.FindUserByID(target.ID); err == nil {
		target = fresh
	}
	ok(c, 200, gin.H{"user": gin.H{
		"id": target.ID, "email": target.Email, "name": target.Name,
		"isAdmin": target.IsAdmin, "disabled": target.Disabled,
		"disabledAt": target.DisabledAt, "adminNote": target.AdminNote,
	}})
}

type adminPassReq struct {
	Password string `json:"password"` // 缺省 = 服务端随机生成一个
}

// adminResetPassword POST /api/admin/users/:id/password —— 重置密码并返回新值（仅此一次）。
//
// 内网里没有邮件通道，所以「重置」必须是「管理员拿到临时密码再当面/内网告诉本人」。
func (s *Server) adminResetPassword(c *gin.Context) {
	target, err := s.St.FindUserByID(c.Param("id"))
	if err != nil {
		fail(c, 404, "not_found", "用户不存在")
		return
	}
	var body adminPassReq
	_ = c.ShouldBindJSON(&body)
	pw := strings.TrimSpace(body.Password)
	generated := false
	if pw == "" {
		pw = randomPassword(12)
		generated = true
	}
	if len(pw) < 6 {
		fail(c, 400, "bad_request", "密码至少 6 位")
		return
	}
	hash, err := hashPassword(pw)
	if err != nil {
		fail(c, 500, "internal", "密码处理失败")
		return
	}
	if err := s.St.UpdateUserPass(target.ID, hash); err != nil {
		fail(c, 500, "internal", "重置失败")
		return
	}
	s.audit(c, model.ActUserPasswd, target.ID, target.Email,
		"重置密码", gin.H{"generated": generated, "by": adminOf(c).Name})
	ok(c, 200, gin.H{
		"ok": true, "userId": target.ID, "email": target.Email,
		"password": pw, "generated": generated,
		"note": "这个密码只在这里显示一次，请立刻告知本人并让其自行修改",
	})
}

/* ---------------- 节点 ---------------- */

// adminListNodes GET /api/admin/nodes?kind=&region=&q=
func (s *Server) adminListNodes(c *gin.Context) {
	kind, region, q := c.Query("kind"), c.Query("region"), c.Query("q")
	limit, offset := pageParams(c)
	rows, err := s.St.ListAllNodes(kind, region, q, limit, offset)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	total, _ := s.St.CountAllNodes(kind, region, q)
	list := make([]gin.H, 0, len(rows))
	for i := range rows {
		out := nodeJSON(&rows[i], s.Cfg.NodeTTL)
		// 管理面要多一眼「是谁的节点」：给邮箱（name 只是昵称，找人不方便）。
		out["ownerEmail"] = rows[i].OwnerEmail
		list = append(list, out)
	}
	ok(c, 200, gin.H{"nodes": list, "total": total, "limit": limit, "offset": offset})
}

// adminDeleteNode DELETE /api/admin/nodes/:id —— 摘除节点（不论归属），并清掉指向它的连接。
func (s *Server) adminDeleteNode(c *gin.Context) {
	id := c.Param("id")
	row, err := s.St.FindNodeRow(id, "")
	if err != nil {
		fail(c, 404, "not_found", "节点不存在")
		return
	}
	if err := s.St.DeleteHostedNodeAsAdmin(id); err != nil {
		fail(c, 500, "internal", "摘除失败")
		return
	}
	s.audit(c, model.ActNodeDelete, row.ID, row.Name, "摘除托管节点",
		gin.H{"kind": row.Kind, "namespace": row.NsSlug, "owner": row.OwnerName, "visibility": row.Visibility})
	ok(c, 200, gin.H{"ok": true})
}

/* ---------------- 服务 ---------------- */

// adminListServices GET /api/admin/services?source=node|artifact|all&kind=&q=
//
// 「服务」在 ncc-registry 里有两个落点，管理台必须一次看全：
//
//	node      托管节点里 kind=service 的节点（正在跑的服务）
//	artifact  制品里 kind=api 的条目（被声明/交付的服务接口）
func (s *Server) adminListServices(c *gin.Context) {
	source := firstNonEmpty(c.Query("source"), "all")
	q := c.Query("q")
	limit, offset := pageParams(c)

	out := gin.H{"source": source, "nodeServices": []gin.H{}, "apiArtifacts": []gin.H{}, "total": gin.H{}}
	var nodeTotal, artTotal int64

	if source == "all" || source == "node" {
		rows, err := s.St.ListAllNodes(model.NodeService, "", q, limit, offset)
		if err != nil {
			fail(c, 500, "internal", "服务内部错误")
			return
		}
		list := make([]gin.H, 0, len(rows))
		for i := range rows {
			out0 := nodeJSON(&rows[i], s.Cfg.NodeTTL)
			out0["source"] = "node"
			out0["ownerEmail"] = rows[i].OwnerEmail
			list = append(list, out0)
		}
		out["nodeServices"] = list
		nodeTotal, _ = s.St.CountAllNodes(model.NodeService, "", q)
	}

	if source == "all" || source == "artifact" {
		kind := ""
		if source == "artifact" {
			kind = c.Query("kind") // 只在单看制品侧时才允许换 kind（默认 kind=api）
		}
		rows, err := s.St.ListServiceArtifacts(kind, q, limit, offset)
		if err != nil {
			fail(c, 500, "internal", "服务内部错误")
			return
		}
		list := make([]gin.H, 0, len(rows))
		for i := range rows {
			out0 := artifactJSON(&rows[i])
			out0["source"] = "artifact"
			list = append(list, out0)
		}
		out["apiArtifacts"] = list
		artTotal, _ = s.St.CountServiceArtifacts(kind, q)
	}

	out["total"] = gin.H{"nodeServices": nodeTotal, "apiArtifacts": artTotal, "all": nodeTotal + artTotal}
	out["limit"], out["offset"] = limit, offset
	ok(c, 200, out)
}

// adminArchiveService DELETE /api/admin/services/:ref
//
// ref 两种形态，处理方式不同（这是刻意的）：
//
//	ND-…        托管节点 → **摘除**（服务已不在跑）
//	@ns/slug    制品     → **归档**（从目录消失，字节保留，是否删除交给条目所属者）
func (s *Server) adminArchiveService(c *gin.Context) {
	ref := c.Param("ref")
	if c.Param("slug") != "" {
		ref = ref + "/" + c.Param("slug")
	}
	// 节点侧：ND-… 或 @ns/slug（节点与制品都可能是 @ns/slug，所以先按节点找一次）
	if strings.HasPrefix(ref, "ND-") {
		row, err := s.St.FindNodeRow(ref, "")
		if err != nil {
			fail(c, 404, "not_found", "节点不存在")
			return
		}
		if err := s.St.DeleteHostedNodeAsAdmin(row.ID); err != nil {
			fail(c, 500, "internal", "摘除失败")
			return
		}
		s.audit(c, model.ActServiceDelete, row.ID, row.Name, "摘除服务节点",
			gin.H{"kind": row.Kind, "owner": row.OwnerName})
		ok(c, 200, gin.H{"ok": true, "target": "node", "id": row.ID})
		return
	}
	if strings.HasPrefix(ref, "@") {
		row, err := s.findByRef(ref)
		if err != nil {
			// 也可能是一条托管节点（@ns/slug 形式）——管理台列表里两处都用了这个引用。
			if n, nerr := s.St.FindNodeByNsSlug(strings.SplitN(ref, "/", 2)[0], strings.SplitN(ref, "/", 2)[1], ""); nerr == nil {
				if err := s.St.DeleteHostedNodeAsAdmin(n.ID); err != nil {
					fail(c, 500, "internal", "摘除失败")
					return
				}
				s.audit(c, model.ActServiceDelete, n.ID, n.Name, "摘除服务节点",
					gin.H{"kind": n.Kind, "owner": n.OwnerName, "ref": ref})
				ok(c, 200, gin.H{"ok": true, "target": "node", "id": n.ID})
				return
			}
			fail(c, 404, "not_found", "服务不存在")
			return
		}
		if err := s.St.ArchiveArtifact(row.ID); err != nil {
			fail(c, 500, "internal", "归档失败")
			return
		}
		s.audit(c, model.ActServiceArchive, ref, row.Name, "归档服务条目",
			gin.H{"kind": row.Kind, "namespace": row.NsSlug, "before": row.Status})
		ok(c, 200, gin.H{"ok": true, "target": "artifact", "id": row.ID, "status": "archived"})
		return
	}
	if row, err := s.St.FindNodeRow(ref, ""); err == nil {
		if err := s.St.DeleteHostedNodeAsAdmin(row.ID); err != nil {
			fail(c, 500, "internal", "摘除失败")
			return
		}
		s.audit(c, model.ActServiceDelete, row.ID, row.Name, "摘除服务节点", gin.H{"kind": row.Kind})
		ok(c, 200, gin.H{"ok": true, "target": "node", "id": row.ID})
		return
	}
	fail(c, 404, "not_found", "服务不存在（用 ND-… 节点 id 或 @命名空间/slug）")
}

/* ---------------- 审计与凭据 ---------------- */

// adminListAudit GET /api/admin/audit?action=&limit=&offset=
func (s *Server) adminListAudit(c *gin.Context) {
	action := c.Query("action")
	limit, offset := pageParams(c)
	rows, err := s.St.ListAudit(action, limit, offset)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	total, _ := s.St.CountAudit(action)
	list := make([]gin.H, 0, len(rows))
	for i := range rows {
		list = append(list, auditJSON(&rows[i]))
	}
	ok(c, 200, gin.H{"audit": list, "total": total, "limit": limit, "offset": offset})
}

// adminListKeys GET /api/admin/keys —— 机器管理凭据（只有前缀，secret 不可见）。
func (s *Server) adminListKeys(c *gin.Context) {
	rows, err := s.St.ListAdminKeys()
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	list := make([]gin.H, 0, len(rows))
	for i := range rows {
		k := rows[i]
		list = append(list, gin.H{
			"id": k.ID, "key": k.Key, "label": k.Label, "active": k.Active(),
			"createdAt": k.CreatedAt, "lastUsedAt": k.LastUsedAt, "revokedAt": k.RevokedAt,
		})
	}
	ok(c, 200, gin.H{"keys": list, "total": len(list)})
}

// adminRotateKey POST /api/admin/keys/rotate —— 签发新的 admin key/secret 并撤销旧的。
//
// 返回的 secret 只出现这一次；轮换后旧 secret 立即失效（revoked_at 一写就 Active=false）。
func (s *Server) adminRotateKey(c *gin.Context) {
	label := firstNonEmpty(c.Query("label"), "rotated")
	creator := adminOf(c).ID
	if k, secret, err := s.St.CreateAdminKey(label, creator); err == nil {
		revoked, _ := s.St.RevokeAdminKeys(k.ID)
		s.audit(c, model.ActKeyRotate, k.Key, label,
			"轮换节点管理凭据", gin.H{"revoked": revoked, "by": adminOf(c).Name})
		ok(c, 201, gin.H{
			"key":     gin.H{"id": k.ID, "key": k.Key, "label": k.Label, "createdAt": k.CreatedAt},
			"secret":  secret,
			"revoked": revoked,
			"howto": gin.H{
				"cli":  "ncc registry admin login --key " + k.Key + " --secret <secret>",
				"note": "secret 只显示这一次；用上面的命令写进本机配置后即可管理本节点",
			},
		})
		return
	}
	fail(c, 500, "internal", "签发失败")
}

/* ---------------- 工具 ---------------- */

// pageParams 分页参数（limit/offset，带上限，避免一次把全表拉出来）。
func pageParams(c *gin.Context) (limit, offset int) {
	limit = atoiDefault(c.Query("limit"), 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset = atoiDefault(c.Query("offset"), 0)
	if offset < 0 {
		offset = 0
	}
	return
}

func atoiDefault(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return def
		}
		n = n*10 + int(r-'0')
		if n > 1_000_000 {
			return def
		}
	}
	return n
}

// randomPassword 生成临时密码：去掉容易看错的 0/O/1/l/I，方便电话里念。
func randomPassword(n int) string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return store.RandHex(n)[:n]
		}
		out = append(out, alphabet[v.Int64()])
	}
	return string(out)
}
