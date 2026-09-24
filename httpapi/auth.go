package httpapi

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/fusedmodel/ncc-registry/store"
)

type credReq struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	Name       string `json:"name"`
	InviteCode string `json:"inviteCode"`
}

// authMeta GET /api/auth/meta —— 公开前置信息（前端/CLI 据此决定要不要邀请码）。
func (s *Server) authMeta(c *gin.Context) {
	ok(c, 200, gin.H{
		"inviteRequired": s.Cfg.InviteRequired(),
		"node": gin.H{
			"id": s.Cfg.NodeID, "name": s.Cfg.NodeName, "role": s.Cfg.Role,
			"url": s.Cfg.PublicURL, "region": s.Cfg.NodeRegion,
		},
	})
}

// register POST /api/auth/register —— 注册即开通个人命名空间。
func (s *Server) register(c *gin.Context) {
	var body credReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	if !s.Cfg.InviteAllows(body.InviteCode) {
		if strings.TrimSpace(body.InviteCode) == "" {
			fail(c, 403, "invite_required", "本节点需要邀请码才能注册")
		} else {
			fail(c, 403, "invite_invalid", "邀请码不正确")
		}
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	if !emailRe.MatchString(body.Email) {
		fail(c, 400, "bad_request", "邮箱格式不正确")
		return
	}
	if len(body.Password) < 6 {
		fail(c, 400, "bad_request", "密码至少 6 位")
		return
	}
	if _, err := s.St.FindUserByEmail(body.Email); err == nil {
		fail(c, 409, "conflict", "该邮箱已注册")
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = strings.SplitN(body.Email, "@", 2)[0]
	}
	if len([]rune(name)) > 40 {
		name = string([]rune(name)[:40])
	}
	hash, err := hashPassword(body.Password)
	if err != nil {
		fail(c, 500, "internal", "密码处理失败")
		return
	}
	u, err := s.St.CreateUser(name, body.Email, hash)
	if err != nil {
		if isConflict(err) {
			fail(c, 409, "conflict", "该邮箱已注册")
		} else {
			fail(c, 500, "internal", "创建用户失败")
		}
		return
	}
	// 个人命名空间：取邮箱前缀做 slug，冲突时加随机后缀。
	if _, err := s.St.CreateAccountNamespace(u.ID, u.Name, strings.SplitN(body.Email, "@", 2)[0]); err != nil {
		fail(c, 500, "internal", "创建个人命名空间失败")
		return
	}
	token := signJWT(s.Cfg.JWTSecret, u.ID, u.Email, s.Cfg.JWTTTL)
	resp := gin.H{"token": token, "user": userJSON(u)}
	// 第一个注册的用户就是这台节点的管理员；顺手给机器一把管理凭据
	// （secret 只在这里返回一次，之后要用 `ncc registry admin rotate` 轮换）。
	if u.IsAdmin {
		if k, secret, err := s.St.CreateAdminKey("bootstrap", u.ID); err == nil {
			resp["admin"] = gin.H{
				"isAdmin": true, "key": k.Key, "secret": secret,
				"howto": gin.H{
					"cli":  "ncc registry admin login --key " + k.Key + " --secret <secret>",
					"note": "你是本节点的第一个账号，自动成为管理员；secret 只显示这一次",
				},
			}
		} else {
			logf("首个管理员已创建，但 admin key 签发失败: %v", err)
		}
	}
	ok(c, 201, resp)
}

// login POST /api/auth/login
func (s *Server) login(c *gin.Context) {
	var body credReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	u, err := s.St.FindUserByEmail(body.Email)
	if err != nil || !verifyPassword(body.Password, u.PassHash) {
		fail(c, 401, "unauthorized", "邮箱或密码不正确")
		return
	}
	// 被禁用的账号连登录也不给（禁用前已发出的令牌在 authMiddleware 里拦）。
	if u.Disabled {
		fail(c, 403, "account_disabled", "该账号已被节点管理员禁用"+disabledNote(u.AdminNote))
		return
	}
	_ = s.St.TouchUserLogin(u.ID)
	token := signJWT(s.Cfg.JWTSecret, u.ID, u.Email, s.Cfg.JWTTTL)
	ok(c, 200, gin.H{"token": token, "user": userJSON(u)})
}

// disabledNote 把管理员的禁用备注带一句出来（内网里「找谁问」很重要）。
func disabledNote(note string) string {
	if strings.TrimSpace(note) == "" {
		return ""
	}
	return "（原因：" + strings.TrimSpace(note) + "）"
}

// me GET /api/auth/me —— 当前身份 + 命名空间 + 凭据能力（CLI 据此判断能做什么）。
//
// 节点令牌（接入票据兑换的）只返回缩减视图：它不该看到签发者的邮箱与命名空间清单。
func (s *Server) me(c *gin.Context) {
	a := authOf(c)
	u, err := s.St.FindUserByID(a.UserID)
	if err != nil {
		fail(c, 404, "not_found", "用户不存在")
		return
	}
	if a.Kind == "node" {
		nodeOut := gin.H(nil)
		if a.NodeID != "" {
			if row, err := s.St.FindNodeRow(a.NodeID, a.UserID); err == nil {
				nodeOut = nodeJSON(row, s.Cfg.NodeTTL)
			}
		}
		ok(c, 200, gin.H{
			"user":       gin.H{"id": u.ID, "name": u.Name},
			"namespaces": []gin.H{},
			"credential": gin.H{"kind": "node", "scopes": a.Scopes, "session": false, "nodeId": a.NodeID},
			"node":       nodeOut,
			"registry":   s.registryBlock(),
		})
		return
	}
	nss, err := s.St.NamespacesOfUser(u.ID)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	list := make([]gin.H, 0, len(nss))
	for i := range nss {
		list = append(list, nsJSON(&nss[i], nss[i].OwnerID == u.ID))
	}
	scopes := DefaultScopes
	if !a.Session {
		scopes = a.Scopes
	}
	ok(c, 200, gin.H{
		"user": userJSON(u), "namespaces": list,
		"credential": gin.H{"kind": a.Kind, "scopes": scopes, "session": a.Session},
		"admin":      gin.H{"isAdmin": u.IsAdmin},
		"node": gin.H{
			"id": s.Cfg.NodeID, "name": s.Cfg.NodeName, "role": s.Cfg.Role,
			"url": s.Cfg.PublicURL, "region": s.Cfg.NodeRegion, "version": Version,
		},
	})
}

// myNamespaces GET /api/namespaces/mine
func (s *Server) myNamespaces(c *gin.Context) {
	a := authOf(c)
	nss, err := s.St.NamespacesOfUser(a.UserID)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	list := make([]gin.H, 0, len(nss))
	for i := range nss {
		list = append(list, nsJSON(&nss[i], nss[i].OwnerID == a.UserID))
	}
	ok(c, 200, gin.H{"namespaces": list})
}

// createNamespace POST /api/namespaces —— 建组织命名空间（内网版不收钱）。
func (s *Server) createNamespace(c *gin.Context) {
	a := authOf(c)
	var body struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	raw := strings.TrimSpace(body.Slug)
	if raw == "" {
		raw = strings.TrimSpace(body.Name)
	}
	if raw == "" {
		fail(c, 400, "bad_request", "slug 不能为空")
		return
	}
	slug := store.Slugify(raw)
	if slug == "x" {
		slug = "org-" + store.RandHex(3)
	}
	if _, err := s.St.FindNamespaceBySlug(slug); err == nil {
		fail(c, 409, "conflict", "namespace "+slug+" 已存在")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = slug
	}
	ns, err := s.St.CreateOrgNamespace(a.UserID, slug, name)
	if err != nil {
		fail(c, 500, "internal", "创建失败")
		return
	}
	ok(c, 201, nsJSON(ns, true))
}

/* ---------------- API-Key ---------------- */

func (s *Server) listKeys(c *gin.Context) {
	a := authOf(c)
	keys, err := s.St.ListApiKeys(a.UserID)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	list := make([]gin.H, 0, len(keys))
	for i := range keys {
		k := keys[i]
		list = append(list, gin.H{
			"id": k.ID, "label": k.Label, "prefix": k.Prefix,
			"scopes": store.ParseList(k.Scopes), "createdAt": k.CreatedAt, "lastUsedAt": k.LastUsedAt,
		})
	}
	ok(c, 200, gin.H{"keys": list})
}

func (s *Server) keyScopes(c *gin.Context) {
	ok(c, 200, gin.H{"scopes": AllScopes, "default": DefaultScopes})
}

func (s *Server) createKey(c *gin.Context) {
	a := authOf(c)
	var body struct {
		Label  string   `json:"label"`
		Scopes []string `json:"scopes"`
	}
	_ = c.ShouldBindJSON(&body)
	scopes := make([]string, 0, len(body.Scopes))
	for _, sc := range body.Scopes {
		if ValidScope(sc) {
			scopes = append(scopes, sc)
		}
	}
	if len(scopes) == 0 {
		scopes = append(scopes, DefaultScopes...)
	}
	if len([]rune(body.Label)) > 60 {
		body.Label = string([]rune(body.Label)[:60])
	}
	k, secret, err := s.St.CreateApiKey(a.UserID, body.Label, scopes)
	if err != nil {
		fail(c, 500, "internal", "创建失败")
		return
	}
	ok(c, 201, gin.H{
		"id": k.ID, "label": k.Label, "prefix": k.Prefix,
		"scopes": scopes, "createdAt": k.CreatedAt, "secret": secret,
	})
}

func (s *Server) deleteKey(c *gin.Context) {
	a := authOf(c)
	if err := s.St.DeleteApiKey(c.Param("id"), a.UserID); err != nil {
		fail(c, 500, "internal", "删除失败")
		return
	}
	ok(c, 200, gin.H{"ok": true})
}

// patchMe PATCH /api/auth/me —— 改名 / 改密。
func (s *Server) patchMe(c *gin.Context) {
	a := authOf(c)
	u, err := s.St.FindUserByID(a.UserID)
	if err != nil {
		fail(c, 404, "not_found", "用户不存在")
		return
	}
	var body struct {
		Name            *string `json:"name"`
		CurrentPassword string  `json:"currentPassword"`
		NewPassword     string  `json:"newPassword"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	if body.Name != nil && strings.TrimSpace(*body.Name) != "" {
		name := strings.TrimSpace(*body.Name)
		if len([]rune(name)) > 40 {
			name = string([]rune(name)[:40])
		}
		if err := s.St.UpdateUserName(u.ID, name); err != nil {
			fail(c, 500, "internal", "更新失败")
			return
		}
	}
	if body.NewPassword != "" {
		if !verifyPassword(body.CurrentPassword, u.PassHash) {
			fail(c, 401, "unauthorized", "当前密码不正确")
			return
		}
		if len(body.NewPassword) < 6 {
			fail(c, 400, "bad_request", "新密码至少 6 位")
			return
		}
		h, err := hashPassword(body.NewPassword)
		if err != nil {
			fail(c, 500, "internal", "密码处理失败")
			return
		}
		if err := s.St.UpdateUserPass(u.ID, h); err != nil {
			fail(c, 500, "internal", "更新失败")
			return
		}
	}
	fresh, err := s.St.FindUserByID(u.ID)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	ok(c, 200, gin.H{"user": userJSON(fresh)})
}

// authMe GET /api/namespaces/living —— 与平台一致：列出我命名空间下的托管节点。
func (s *Server) myNodes(c *gin.Context) {
	a := authOf(c)
	nss, err := s.St.NamespacesOfUser(a.UserID)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	ids := make([]string, 0, len(nss))
	for i := range nss {
		ids = append(ids, nss[i].ID)
	}
	if len(ids) == 0 {
		ok(c, 200, gin.H{"nodes": []gin.H{}})
		return
	}
	rows, err := s.St.ListNodesOfNamespaces(a.UserID, ids)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	list := make([]gin.H, 0, len(rows))
	for i := range rows {
		list = append(list, nodeJSON(&rows[i], s.Cfg.NodeTTL))
	}
	ok(c, 200, gin.H{"nodes": list})
}
