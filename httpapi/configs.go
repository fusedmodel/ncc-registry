package httpapi

// NCC Config：团队的网络 / 基础设施 / Agent 配置托管。
//
// 与制品（artifact.go）的分工，别混：
//
//	制品   可分发的能力包：字节进 blob 存储，可 fan-out 到 worker、公开即可匿名下载。
//	配置   团队的权威数据：默认**私有**，就地改、每次写入留一版历史、可回滚，
//	       不参与 fan-out（只在被指向的那个节点上维护）。
//
// 三条判定，缺一不可（这是本文件最容易写错的地方）：
//
//	读公开配置       -> 谁都能读（visibility=public 且 status=active）
//	读非公开配置     -> 需要 config:read 作用域 **且**（命名空间成员 **或** 拿到 config 授权）
//	写（含改内容）   -> 需要 config:write 作用域 **且** 是命名空间成员
//
// 敏感值：`secret=true` 的配置内容落库前加密（见 internal/secretbox），
// 读取默认只回 checksum / size（打码），要明文必须显式 `?reveal=1` —— 且 secret
// 配置强制私有（公开一条加密配置没有意义，只会让人误以为它是安全的）。

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/fusedmodel/ncc-registry/model"
	"github.com/fusedmodel/ncc-registry/store"
)

const (
	configMaxPerNamespace = 500
	maxConfigTags         = 12
	maxConfigTagLen       = 24
)

/* ---------------- 序列化 ---------------- */

// configKindCatalog GET /api/configs/kinds —— 配置类型 / 格式 / 环境目录（公开）。
func (s *Server) configKindCatalog(c *gin.Context) {
	counts, _ := s.St.ConfigKindCounts()
	kinds := make([]gin.H, 0, len(model.ConfigKinds))
	for _, k := range model.ConfigKinds {
		meta := model.ConfigKindMeta[k]
		kinds = append(kinds, gin.H{
			"kind": k, "label": meta[0], "en": meta[1], "desc": meta[2], "descEn": meta[3],
			"count": counts[k],
		})
	}
	envCounts, _ := s.St.ConfigEnvCounts()
	publics, _ := s.St.CountPublicConfigs()
	ok(c, 200, gin.H{
		"kinds": kinds, "formats": model.ConfigFormats, "envs": model.ConfigEnvs,
		"envCounts": envCounts, "public": publics,
		// 计数口径写清楚：下面这些数字都是**公开且 active** 的配置，不含私有/归档。
		"countScope": "public+active",
		"limits":     gin.H{"perNamespace": configMaxPerNamespace, "bytes": model.ConfigMaxBytes, "tags": maxConfigTags},
		"access": gin.H{
			"readPublic":      "公开且 active 的配置谁都能读",
			"readPrivate":     "非公开配置需要 config:read 作用域，且是命名空间成员或拿到 config 授权",
			"write":           "写入需要 config:write 作用域，且是命名空间成员",
			"secretAtRest":    "secret=true 的内容在本节点静态加密（AES-256-GCM），读取默认打码",
			"grantKindHint":   "授权：ncc grant set --user @某人 --kind config [--ns @团队]",
			"ticketScopeHint": "给 Agent 的长效凭据：ncc registry ticket create --scopes config:read,config:write",
		},
	})
}

// configJSON 配置视图。
//
// reveal=false 时**绝不下发明文**（哪怕调用方有权限）：打码是默认，不是异常。
// reveal 由调用方显式给出：读接口看 `?reveal=1`，**写接口直接给 true** ——
// 写的人刚刚提供了内容，把回执打码只会让 CLI 无法回显「写进去的是什么」。
func (s *Server) configJSON(row *store.ConfigRow, canRead, canWrite, reveal bool) gin.H {
	out := gin.H{
		"id": row.ID, "slug": row.Slug, "ref": row.Ref(), "name": row.Name,
		"kind": row.Kind, "kindLabel": model.ConfigKindLabel(row.Kind, "zh"),
		"environment": row.Environment, "format": row.Format,
		"summary": row.Summary, "tags": store.ParseList(row.Tags),
		"visibility": row.Visibility, "status": row.Status,
		"secret": row.Secret, "encrypted": row.Secret,
		"revision": row.Revision, "checksum": row.Checksum, "size": row.Size,
		"namespace": gin.H{"id": row.NamespaceID, "slug": row.NsSlug, "name": row.NsName},
		"owner":     gin.H{"id": row.OwnerID, "name": row.OwnerName},
		"createdBy": row.CreatedBy, "updatedBy": row.UpdatedBy,
		"createdAt": row.CreatedAt, "updatedAt": row.UpdatedAt,
		"canRead": canRead, "canWrite": canWrite,
	}
	if !canRead {
		return out
	}
	if !reveal {
		out["masked"] = true
		out["content"] = nil
		out["hint"] = "内容默认打码：加 ?reveal=1（CLI: --reveal）取明文"
		return out
	}
	plain, err := s.openConfigContent(row.Content)
	if err != nil {
		out["masked"] = true
		out["content"] = nil
		out["error"] = err.Error()
		return out
	}
	out["masked"] = false
	out["content"] = plain
	// 校验和按**明文**算：Agent 拿到明文后可以自己复核「落地的就是服务端记录的那份」。
	out["contentChecksum"] = checksumOf(plain)
	return out
}

func checksumOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sealConfigContent 按需加密（secret=false 时原样存）。
func (s *Server) sealConfigContent(plain string, secret bool) (string, error) {
	if !secret {
		return plain, nil
	}
	if s.Box == nil {
		return "", errWith(500, "no_secret_key", "本节点没有可用的加密密钥，无法保存敏感配置")
	}
	return s.Box.Seal(plain)
}

// openConfigContent 解密（非密文原样返回，见 secretbox 的兼容说明）。
func (s *Server) openConfigContent(stored string) (string, error) {
	if s.Box == nil {
		return stored, nil
	}
	return s.Box.Open(stored)
}

/* ---------------- 权限判定 ---------------- */

// canReadConfig 读权限（作用域由路由层的 requireScope 管，这里只管「归属/授权」）。
func (s *Server) canReadConfig(row *store.ConfigRow, userID string) bool {
	if row.Visibility == model.ConfigPublic && row.Status == model.ConfigActive {
		return true
	}
	if userID == "" {
		return false
	}
	if s.canManage(row.NamespaceID, userID) {
		return true
	}
	// 归属者把「配置读取权」授给了这个人（可按命名空间限定）
	return s.St.HasGrant(row.OwnerID, userID, model.GrantConfig, row.NamespaceID)
}

// canWriteConfig 写权限 = 命名空间成员（配置是团队资产，写权限跟成员身份绑定，
// 外部只有「读」的授权，不给写）。
func (s *Server) canWriteConfig(row *store.ConfigRow, userID string) bool {
	return userID != "" && s.canManage(row.NamespaceID, userID)
}

// configRefFromParams 拼回引用（@ns/slug 落在两个路由参数上）。
func refFromConfigParams(c *gin.Context) string {
	id := c.Param("id")
	if slug := c.Param("slug"); slug != "" {
		return id + "/" + slug
	}
	return id
}

// findConfig 按引用取配置：C-… id 或 @ns/slug。
func (s *Server) findConfig(ref string) (*store.ConfigRow, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, gorm.ErrRecordNotFound
	}
	if strings.HasPrefix(ref, "@") {
		body := strings.TrimPrefix(ref, "@")
		if i := strings.Index(body, "/"); i > 0 {
			return s.St.FindConfigByNsSlug(body[:i], body[i+1:])
		}
		return nil, gorm.ErrRecordNotFound
	}
	return s.St.FindConfigByID(ref)
}

/* ---------------- 目录 ---------------- */

// listConfigs GET /api/configs?namespace=&kind=&env=&tag=&q=&mine=&status=&secrets=&page=&size=
//
// 可见性规则：匿名只看「公开 + active」；带凭据时额外看到
//  1. 我（owner/member）命名空间里的全部配置；
//  2. 把 config 授权给我的那些人所在命名空间的配置。
//
// 返回里每条都带 canRead/canWrite，前端不用猜。
func (s *Server) listConfigs(c *gin.Context) {
	a := authOf(c)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	opts := store.ConfigListOpts{
		NsSlug: c.Query("namespace"), Kind: c.Query("kind"),
		Env: c.Query("env"), Tag: c.Query("tag"), Q: c.Query("q"),
		Page: page, Size: size,
	}
	if opts.Kind != "" && !model.ValidConfigKind(opts.Kind) {
		fail(c, 400, "bad_request", "未知配置类型: "+opts.Kind)
		return
	}
	if opts.Env != "" && !model.ValidConfigEnv(opts.Env) {
		fail(c, 400, "bad_request", "未知环境: "+opts.Env+"（可选 any|dev|staging|prod）")
		return
	}
	if c.Query("secrets") == "1" {
		opts.SecretsOnly = true
	}

	mine := c.Query("mine") == "1"
	scoped := opts.NsSlug != "" && opts.NsSlug != "-"

	if mine {
		if a == nil {
			fail(c, 401, "unauthorized", "mine=1 需要登录或凭据")
			return
		}
		nss, err := s.St.NamespacesOfUser(a.UserID)
		if err != nil {
			fail(c, 500, "internal", "服务内部错误")
			return
		}
		for i := range nss {
			opts.NamespaceIDs = append(opts.NamespaceIDs, nss[i].ID)
		}
		if len(opts.NamespaceIDs) == 0 {
			ok(c, 200, gin.H{"configs": []gin.H{}, "total": 0, "page": page, "size": size, "canManage": false})
			return
		}
	} else if scoped {
		// 指定命名空间：给它一个统一的判定 —— 匿名与无权限者只看到公开配置
		ns, err := s.St.FindNamespaceBySlug(opts.NsSlug)
		if err != nil {
			fail(c, 404, "not_found", "命名空间不存在: "+opts.NsSlug)
			return
		}
		granted := false
		if a != nil && !s.canManage(ns.ID, a.UserID) {
			granted = s.St.HasGrant(ns.OwnerID, a.UserID, model.GrantConfig, ns.ID) ||
				s.St.HasGrant(ns.OwnerID, a.UserID, model.GrantConfig, "")
		}
		if !s.canManage(ns.ID, userIDOf(a)) && !granted {
			opts.PublicOnly = true
		}
	} else if a != nil {
		// 全局视图：公开 + 我的空间 + 被授权者
		opts.Visible = true
		if nss, err := s.St.NamespacesOfUser(a.UserID); err == nil {
			for i := range nss {
				opts.NamespaceIDs = append(opts.NamespaceIDs, nss[i].ID)
			}
		}
		if owners, err := s.St.GrantedOwners(a.UserID, model.GrantConfig); err == nil {
			opts.GrantedOwners = owners
		}
	} else {
		opts.PublicOnly = true
	}
	if ctx := strings.TrimSpace(c.Query("status")); ctx != "" {
		for _, st := range strings.Split(ctx, ",") {
			if model.ValidConfigStatus(strings.TrimSpace(st)) {
				opts.Statuses = append(opts.Statuses, strings.TrimSpace(st))
			}
		}
	}

	rows, total, err := s.St.ListConfigs(opts)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	uid := userIDOf(a)
	list := make([]gin.H, 0, len(rows))
	revealAsked := c.Query("reveal") == "1" || c.Query("reveal") == "true"
	for i := range rows {
		canRead := s.canReadConfig(&rows[i], uid)
		list = append(list, s.configJSON(&rows[i], canRead, s.canWriteConfig(&rows[i], uid), revealAsked))
	}
	kindCounts, _ := s.St.ConfigKindCounts()
	ok(c, 200, gin.H{
		"configs": list, "page": page, "size": size, "total": total,
		"kindCounts": kindCounts, "mine": mine,
	})
}

// getConfig GET /api/configs/:id[/:slug] —— ref 为 C-… id 或 @ns/slug。
// 非公开配置要求 config:read 作用域（节点令牌/API-Key 都按作用域判定）。
func (s *Server) getConfig(c *gin.Context) {
	a := authOf(c)
	row, err := s.findConfig(refFromConfigParams(c))
	if err != nil {
		fail(c, 404, "not_found", "配置不存在")
		return
	}
	uid := userIDOf(a)
	canRead := s.canReadConfig(row, uid)
	if !canRead {
		fail(c, 404, "not_found", "配置不存在或不可读（私有配置需要 config:read + 成员身份或 config 授权）")
		return
	}
	if row.Visibility != model.ConfigPublic && !allow(a, "config:read") {
		fail(c, 403, "scope_required", "读取非公开配置需要作用域 config:read")
		return
	}
	// 指定历史版本：只回那一版（同样受 reveal 约束）
	if rev := strings.TrimSpace(c.Query("revision")); rev != "" {
		n, err := strconv.ParseInt(rev, 10, 64)
		if err != nil {
			fail(c, 400, "bad_request", "revision 需要是数字")
			return
		}
		r, err := s.St.FindConfigRevision(row.ID, n)
		if err != nil {
			fail(c, 404, "not_found", "该版本不存在")
			return
		}
		out := s.configJSON(row, canRead, s.canWriteConfig(row, uid), c.Query("reveal") == "1" || c.Query("reveal") == "true")
		out["revisionRequested"] = n
		out["revisionMeta"] = gin.H{
			"revision": r.Revision, "note": r.Note, "authorName": r.AuthorName,
			"createdAt": r.CreatedAt, "checksum": r.Checksum, "size": r.Size,
		}
		if c.Query("reveal") == "1" || c.Query("reveal") == "true" {
			plain, err := s.openConfigContent(r.Content)
			if err != nil {
				out["error"] = err.Error()
			} else {
				out["content"] = plain
				out["masked"] = false
				out["contentChecksum"] = checksumOf(plain)
			}
		} else {
			out["content"] = nil
			out["masked"] = true
		}
		ok(c, 200, gin.H{"config": out})
		return
	}
	ok(c, 200, gin.H{"config": s.configJSON(row, canRead, s.canWriteConfig(row, uid), c.Query("reveal") == "1" || c.Query("reveal") == "true")})
}

/* ---------------- 写 ---------------- */

type configBody struct {
	Namespace   string   `json:"namespace"`
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Environment string   `json:"environment"`
	Format      string   `json:"format"`
	Summary     string   `json:"summary"`
	Tags        []string `json:"tags"`
	Visibility  string   `json:"visibility"`
	Status      string   `json:"status"`
	Secret      bool     `json:"secret"`
	Content     string   `json:"content"`
	Note        string   `json:"note"`
}

// normalizeConfigBody 校验并补齐默认值；返回错误消息（空 = 通过）。
func normalizeConfigBody(in configBody) (configBody, string) {
	in.Slug = strings.ToLower(strings.TrimSpace(in.Slug))
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		in.Name = in.Slug
	}
	if !validConfigSlug(in.Slug) {
		return in, "配置 slug 需为 2-48 位小写字母、数字或连字符"
	}
	if len([]rune(in.Name)) > 80 {
		in.Name = string([]rune(in.Name)[:80])
	}
	in.Kind = strings.TrimSpace(in.Kind)
	if in.Kind == "" {
		in.Kind = "other"
	}
	if !model.ValidConfigKind(in.Kind) {
		return in, "未知配置类型: " + in.Kind
	}
	in.Environment = strings.TrimSpace(in.Environment)
	if in.Environment == "" {
		in.Environment = "any"
	}
	if !model.ValidConfigEnv(in.Environment) {
		return in, "未知环境: " + in.Environment + "（可选 any|dev|staging|prod）"
	}
	in.Format = strings.TrimSpace(in.Format)
	if in.Format == "" {
		in.Format = "text"
	}
	if !model.ValidConfigFormat(in.Format) {
		return in, "未知格式: " + in.Format
	}
	in.Visibility = strings.TrimSpace(in.Visibility)
	if in.Visibility == "" {
		in.Visibility = model.ConfigPrivate
	}
	if in.Visibility != model.ConfigPrivate && in.Visibility != model.ConfigPublic {
		return in, "可见性只能是 private 或 public"
	}
	in.Status = strings.TrimSpace(in.Status)
	if in.Status == "" {
		in.Status = model.ConfigActive
	}
	if !model.ValidConfigStatus(in.Status) {
		return in, "状态只能是 active 或 archived"
	}
	if in.Secret && in.Visibility == model.ConfigPublic {
		return in, "含敏感值的配置不能公开（去掉 public，或把 secret 关掉）"
	}
	if len([]rune(in.Summary)) > 200 {
		in.Summary = string([]rune(in.Summary)[:200])
	}
	if len([]rune(in.Note)) > 200 {
		in.Note = string([]rune(in.Note)[:200])
	}
	if len(in.Content) > model.ConfigMaxBytes {
		return in, "配置内容超过上限（" + strconv.Itoa(model.ConfigMaxBytes/1024) + " KB）"
	}
	tags := make([]string, 0, len(in.Tags))
	for _, t := range in.Tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len([]rune(t)) > maxConfigTagLen {
			t = string([]rune(t)[:maxConfigTagLen])
		}
		if len(tags) >= maxConfigTags {
			break
		}
		tags = append(tags, t)
	}
	in.Tags = tags
	return in, ""
}

// validConfigSlug 与制品 slug 同族（引用写作 @ns/slug，别引入第二套规则）。
func validConfigSlug(s string) bool {
	if len(s) < 2 || len(s) > 48 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}

// createConfig POST /api/configs（需要 config:write + 命名空间成员身份）
func (s *Server) createConfig(c *gin.Context) {
	a := authOf(c)
	var body configBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	body, msg := normalizeConfigBody(body)
	if msg != "" {
		fail(c, 400, "bad_request", msg)
		return
	}
	ns, err := s.ticketNamespace(a.UserID, body.Namespace)
	if err != nil {
		failErr(c, err)
		return
	}
	if n, _ := s.St.CountConfigsInNamespace(ns.ID); n >= configMaxPerNamespace {
		fail(c, 400, "bad_request", "该命名空间的配置数量已达上限")
		return
	}
	if exists, _ := s.St.ConfigSlugExists(ns.ID, body.Slug); exists {
		fail(c, 409, "conflict", "配置 @"+ns.Slug+"/"+body.Slug+" 已存在（改 slug，或直接 PATCH 更新它）")
		return
	}
	sealed, err := s.sealConfigContent(body.Content, body.Secret)
	if err != nil {
		failErr(c, err)
		return
	}
	row, err := s.St.CreateConfig(store.ConfigInput{
		NamespaceID: ns.ID, Slug: body.Slug, Name: body.Name, Kind: body.Kind,
		Environment: body.Environment, Format: body.Format, Summary: body.Summary,
		Tags: body.Tags, Visibility: body.Visibility, Status: body.Status,
		Secret: body.Secret, Content: sealed, Checksum: checksumOf(body.Content),
		Size: int64(len(body.Content)), Note: body.Note,
		AuthorID: a.UserID, AuthorName: a.Email,
	})
	if err != nil {
		if isConflict(err) {
			fail(c, 409, "conflict", "配置已存在")
			return
		}
		fail(c, 500, "internal", "创建配置失败")
		return
	}
	full, err := s.St.FindConfigByID(row.ID)
	if err != nil {
		fail(c, 500, "internal", "创建配置失败")
		return
	}
	ok(c, 201, gin.H{"config": s.configJSON(full, true, true, true), "created": true})
}

// configPatchBody PATCH 的请求体。
//
// 刻意不内嵌 configBody：`secret` 与 `content` 都要能区分「没传」与「传了假值」，
// 所以用指针。共用一套 struct 会让「只想改标签」的请求意外把 secret 关掉。
type configPatchBody struct {
	Name        *string   `json:"name"`
	Kind        *string   `json:"kind"`
	Environment *string   `json:"environment"`
	Format      *string   `json:"format"`
	Summary     *string   `json:"summary"`
	Tags        *[]string `json:"tags"`
	Visibility  *string   `json:"visibility"`
	Status      *string   `json:"status"`
	Secret      *bool     `json:"secret"`
	Content     *string   `json:"content"`
	Note        *string   `json:"note"`
}

// updateConfig PATCH /api/configs/:id[/:slug]
//
// 带 content 的更新会**追加一个版本**；只改元数据（标签 / 归档 / 可见性）不加版本 ——
// 这样「历史」记录的才是真正的内容变化。
func (s *Server) updateConfig(c *gin.Context) {
	a := authOf(c)
	row, err := s.findConfig(refFromConfigParams(c))
	if err != nil {
		fail(c, 404, "not_found", "配置不存在")
		return
	}
	if !s.canWriteConfig(row, a.UserID) {
		fail(c, 403, "forbidden", "你不是该命名空间的成员，无法修改配置")
		return
	}
	var b configPatchBody
	if err := c.ShouldBindJSON(&b); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	// 用现有值补齐，再整体校验一遍（避免「只传一个字段」绕过合法性检查）
	merged := configBody{
		Slug: row.Slug, Name: row.Name, Kind: row.Kind, Environment: row.Environment,
		Format: row.Format, Summary: row.Summary, Tags: store.ParseList(row.Tags),
		Visibility: row.Visibility, Status: row.Status, Secret: row.Secret,
	}
	if b.Name != nil {
		merged.Name = *b.Name
	}
	if b.Kind != nil {
		merged.Kind = *b.Kind
	}
	if b.Environment != nil {
		merged.Environment = *b.Environment
	}
	if b.Format != nil {
		merged.Format = *b.Format
	}
	if b.Summary != nil {
		merged.Summary = *b.Summary
	}
	if b.Tags != nil {
		merged.Tags = *b.Tags
	}
	if b.Visibility != nil {
		merged.Visibility = *b.Visibility
	}
	if b.Status != nil {
		merged.Status = *b.Status
	}
	if b.Note != nil {
		merged.Note = *b.Note
	}
	if b.Secret != nil {
		merged.Secret = *b.Secret
	}
	merged, msg := normalizeConfigBody(merged)
	if msg != "" {
		fail(c, 400, "bad_request", msg)
		return
	}

	contentChanged := b.Content != nil
	if !contentChanged {
		// 只改元数据：不动内容，也不加版本
		fields := map[string]any{
			"name": merged.Name, "kind": merged.Kind, "environment": merged.Environment,
			"format": merged.Format, "summary": merged.Summary, "tags": mustTags(merged.Tags),
			"visibility": merged.Visibility, "status": merged.Status,
			"updated_by": a.UserID,
		}
		if b.Secret != nil {
			// 打开 secret 时把现有明文重新加密；关掉时保留原文（解密后原样存回）
			plain, err := s.openConfigContent(row.Content)
			if err != nil {
				failErr(c, err)
				return
			}
			sealed, err := s.sealConfigContent(plain, merged.Secret)
			if err != nil {
				failErr(c, err)
				return
			}
			fields["secret"] = merged.Secret
			fields["content"] = sealed
		}
		if err := s.St.PatchConfig(row.ID, fields); err != nil {
			fail(c, 500, "internal", "更新失败")
			return
		}
		fresh, _ := s.St.FindConfigByID(row.ID)
		ok(c, 200, gin.H{"config": s.configJSON(fresh, true, true, true), "revisionAdded": false})
		return
	}

	plain := *b.Content
	if len(plain) > model.ConfigMaxBytes {
		fail(c, 400, "bad_request", "配置内容超过上限（128 KB）")
		return
	}
	sealed, err := s.sealConfigContent(plain, merged.Secret)
	if err != nil {
		failErr(c, err)
		return
	}
	upd, err := s.St.UpdateConfig(row.ID, store.ConfigInput{
		NamespaceID: row.NamespaceID, Slug: merged.Slug, Name: merged.Name,
		Kind: merged.Kind, Environment: merged.Environment, Format: merged.Format,
		Summary: merged.Summary, Tags: merged.Tags,
		Visibility: merged.Visibility, Status: merged.Status, Secret: merged.Secret,
		Content: sealed, Checksum: checksumOf(plain), Size: int64(len(plain)),
		Note: merged.Note, AuthorID: a.UserID, AuthorName: a.Email,
	})
	if err != nil {
		fail(c, 500, "internal", "更新失败")
		return
	}
	fresh, _ := s.St.FindConfigByID(upd.ID)
	ok(c, 200, gin.H{"config": s.configJSON(fresh, true, true, true), "revisionAdded": true})
}

// deleteConfig DELETE /api/configs/:id[/:slug] —— 连同历史一起删（需要成员身份）。
func (s *Server) deleteConfig(c *gin.Context) {
	a := authOf(c)
	row, err := s.findConfig(refFromConfigParams(c))
	if err != nil {
		fail(c, 404, "not_found", "配置不存在")
		return
	}
	if !s.canWriteConfig(row, a.UserID) {
		fail(c, 403, "forbidden", "你不是该命名空间的成员，无法删除配置")
		return
	}
	if err := s.St.DeleteConfig(row.ID); err != nil {
		fail(c, 500, "internal", "删除失败")
		return
	}
	ok(c, 200, gin.H{"ok": true, "ref": row.Ref()})
}

/* ---------------- 版本 ---------------- */

// configRevisions GET /api/configs/:id[/:slug]/revisions —— 版本历史（不含内容）。
func (s *Server) configRevisions(c *gin.Context) {
	a := authOf(c)
	row, err := s.findConfig(refFromConfigParams(c))
	if err != nil {
		fail(c, 404, "not_found", "配置不存在")
		return
	}
	if !s.canReadConfig(row, userIDOf(a)) {
		fail(c, 404, "not_found", "配置不存在或不可读")
		return
	}
	if row.Visibility != model.ConfigPublic && !allow(a, "config:read") {
		fail(c, 403, "scope_required", "读取非公开配置需要作用域 config:read")
		return
	}
	rows, err := s.St.ListConfigRevisions(row.ID)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	list := make([]gin.H, 0, len(rows))
	for i := range rows {
		list = append(list, gin.H{
			"revision": rows[i].Revision, "checksum": rows[i].Checksum,
			"size": rows[i].Size, "secret": rows[i].Secret,
			"note": rows[i].Note, "authorName": rows[i].AuthorName,
			"createdAt": rows[i].CreatedAt, "current": rows[i].Revision == row.Revision,
		})
	}
	ok(c, 200, gin.H{"ref": row.Ref(), "current": row.Revision, "revisions": list})
}

// rollbackConfig POST /api/configs/:id[/:slug]/rollback  body: {revision, note}
//
// 回滚不重写历史：把旧版本的内容**作为新版本**写回去（revision+1），
// 于是「谁在什么时候回滚过」同样留痕，历史永远只增不改。
func (s *Server) rollbackConfig(c *gin.Context) {
	a := authOf(c)
	row, err := s.findConfig(refFromConfigParams(c))
	if err != nil {
		fail(c, 404, "not_found", "配置不存在")
		return
	}
	if !s.canWriteConfig(row, a.UserID) {
		fail(c, 403, "forbidden", "你不是该命名空间的成员，无法回滚配置")
		return
	}
	var body struct {
		Revision int64  `json:"revision"`
		Note     string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Revision <= 0 {
		fail(c, 400, "bad_request", "需要 revision（见 /revisions）")
		return
	}
	rev, err := s.St.FindConfigRevision(row.ID, body.Revision)
	if err != nil {
		fail(c, 404, "not_found", "该版本不存在")
		return
	}
	note := strings.TrimSpace(body.Note)
	if note == "" {
		note = "回滚到 v" + strconv.FormatInt(body.Revision, 10)
	}
	if len([]rune(note)) > 200 {
		note = string([]rune(note)[:200])
	}
	upd, err := s.St.UpdateConfig(row.ID, store.ConfigInput{
		NamespaceID: row.NamespaceID, Slug: row.Slug, Name: row.Name, Kind: row.Kind,
		Environment: row.Environment, Format: row.Format, Summary: row.Summary,
		Tags: store.ParseList(row.Tags), Visibility: row.Visibility, Status: row.Status,
		Secret: rev.Secret, Content: rev.Content, Checksum: rev.Checksum, Size: rev.Size,
		Note: note, AuthorID: a.UserID, AuthorName: a.Email,
	})
	if err != nil {
		fail(c, 500, "internal", "回滚失败")
		return
	}
	fresh, _ := s.St.FindConfigByID(upd.ID)
	out := s.configJSON(fresh, true, true, true)
	out["rolledBackTo"] = body.Revision
	ok(c, 200, gin.H{"config": out})
}

/* ---------------- 成组拉取（Agent 的主入口） ---------------- */

// configBundle GET /api/configs/bundle?namespace=@team&env=prod&kind=&tag=&secrets=1&reveal=1
//
// 「把这一套配置一次拉全」是 Agent 落地基础设施的第一步：一条命令拿到该环境所有
// 生效配置（含 any 通用项），每份都带校验和与建议文件名（CLI 直接落盘）。
//
// 默认**跳过 secret 配置**：一次把凭据全下到磁盘不是好默认；需要时显式 secrets=1。
func (s *Server) configBundle(c *gin.Context) {
	a := authOf(c)
	nsSlug := strings.TrimSpace(c.Query("namespace"))
	if nsSlug == "" {
		fail(c, 400, "bad_request", "需要 namespace（如 @team）")
		return
	}
	nsSlug = strings.TrimPrefix(nsSlug, "@")
	row, err := s.St.FindNamespaceBySlug(nsSlug)
	if err != nil {
		fail(c, 404, "not_found", "命名空间不存在: @"+nsSlug)
		return
	}
	uid := userIDOf(a)
	member := s.canManage(row.ID, uid)
	granted := false
	if !member && uid != "" {
		granted = s.St.HasGrant(row.OwnerID, uid, model.GrantConfig, row.ID) ||
			s.St.HasGrant(row.OwnerID, uid, model.GrantConfig, "")
	}
	if !member && !granted {
		fail(c, 403, "forbidden", "需要是該命名空间成员，或拿到 config 授权（ncc grant set --user @你 --kind config）")
		return
	}
	if !allow(a, "config:read") {
		fail(c, 403, "scope_required", "拉取配置需要作用域 config:read")
		return
	}

	env := strings.TrimSpace(c.Query("env"))
	if env != "" && !model.ValidConfigEnv(env) {
		fail(c, 400, "bad_request", "未知环境: "+env)
		return
	}
	opts := store.ConfigListOpts{
		NamespaceIDs: []string{row.ID},
		Env:          env, Kind: strings.TrimSpace(c.Query("kind")), Tag: strings.TrimSpace(c.Query("tag")),
		Statuses: []string{model.ConfigActive}, Limit: 200,
	}
	includeSecrets := c.Query("secrets") == "1"
	if !includeSecrets {
		opts.NoSecrets = true
	}
	rows, _, err := s.St.ListConfigs(opts)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	reveal := c.Query("reveal") == "1" || c.Query("reveal") == "true"

	items := make([]gin.H, 0, len(rows))
	skipped := 0
	for i := range rows {
		r := &rows[i]
		if !s.canReadConfig(r, uid) {
			skipped++
			continue
		}
		item := s.configJSON(r, true, s.canWriteConfig(r, uid), reveal)
		item["filename"] = bundleFilename(r, env)
		if !reveal {
			item["content"] = nil
			item["masked"] = true
		}
		if r.Secret && reveal {
			if plain, err := s.openConfigContent(r.Content); err == nil {
				item["content"] = plain
				item["masked"] = false
			} else {
				item["content"] = nil
				item["masked"] = true
				item["error"] = err.Error()
			}
		}
		items = append(items, item)
	}
	ok(c, 200, gin.H{
		"namespace": gin.H{"slug": "@" + row.Slug, "name": row.Name},
		"env":       env, "count": len(items), "skipped": skipped,
		"secretsIncluded": includeSecrets, "revealed": reveal,
		"configs": items,
		"howto":   "CLI: ncc registry config bundle --ns @" + row.Slug + " [--env " + env + "] [--secrets --reveal] --out ./conf",
	})
}

// bundleFilename 建议落盘名：@team/network + prod → team-network.prod.yaml
func bundleFilename(r *store.ConfigRow, env string) string {
	base := r.NsSlug + "-" + r.Slug
	if r.Environment != "" && r.Environment != "any" {
		base += "." + r.Environment
	} else if env != "" {
		base += "." + env
	}
	return base + model.ConfigFormatExt(r.Format)
}

func mustTags(tags []string) string {
	if len(tags) == 0 {
		return "[]"
	}
	b, err := jsonMarshal(tags)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func userIDOf(a *AuthInfo) string {
	if a == nil {
		return ""
	}
	return a.UserID
}
