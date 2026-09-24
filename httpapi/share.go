package httpapi

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/fusedmodel/ncc-registry/model"
	"github.com/fusedmodel/ncc-registry/store"
)

// 制品分享链接：把一条制品用**临时下载地址**发给别人 —— 对方不用登录、不用装 CLI。
//
//	token   32 位随机串，库里只存 sha256
//	链接    <publicURL>/s/<token>      落地页（给人看：这是什么、还能用几次）
//	        <publicURL>/s/<token>/raw  直接下发字节（给 curl / Agent；**只有这个计数**）
//
// 与「授权」的分界（重要）：
//
//	Grant  长期、按人、可撤销，进门后能继续用普通命令；
//	Share  临时、按链接、可限次/限时，拿到字节即结束，不改制品可见性。
//
// 所以创建分享**不**需要 grants:write；但必须本来就能读到这条制品（不能拿分享当提权工具）。

/* ---------------- 创建 / 列表 / 撤销（需登录） ---------------- */

type shareCreateReq struct {
	Ref           string `json:"ref"`
	Label         string `json:"label"`
	Uses          int64  `json:"uses"`          // 0 = 不限次
	ExpiresInDays int64  `json:"expiresInDays"` // 0 = 不过期
}

// createShare POST /api/shares
func (s *Server) createShare(c *gin.Context) {
	a := authOf(c)
	var body shareCreateReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	ref := strings.TrimSpace(body.Ref)
	if ref == "" {
		fail(c, 400, "bad_request", "缺少 ref（@命名空间/slug 或 A-… id）")
		return
	}
	row, err := s.findByRef(ref)
	if err != nil {
		fail(c, 404, "not_found", "制品不存在")
		return
	}
	// 只能分享「我本来就能读」的制品：否则分享链接就成了绕过授权的通道。
	if !s.canReadArtifact(row, a.UserID) {
		fail(c, 403, "forbidden", "你没有这条制品的读取权限，不能分享它")
		return
	}
	if body.Uses < 0 {
		body.Uses = 0
	}
	var expiresAt *time.Time
	if body.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, int(body.ExpiresInDays))
		expiresAt = &t
	}
	sh, token, err := s.St.CreateShare(row.ID, row.NamespaceID, a.UserID, body.Label, body.Uses, expiresAt)
	if err != nil {
		fail(c, 500, "internal", "创建分享失败")
		return
	}
	// 如果创建者是管理员，把管理员身份放进 ctx，这条动作就进审计
	// （普通用户分享自己的制品不进审计 —— 审计记的是治理动作）。
	s.ensureAdmin(c)
	s.audit(c, model.ActShareCreate, ref, row.Name, "创建分享链接",
		gin.H{"shareId": sh.ID, "uses": body.Uses, "expiresAt": expiresAt})
	ok(c, 201, gin.H{
		"share":   s.shareJSON(sh, row, ""),
		"token":   token, // 仅此一次
		"link":    s.shareLink(token),
		"rawLink": s.shareLink(token) + "/raw",
		"howto": gin.H{
			"human": "把 link 发给对方：浏览器打开是说明页，点按钮即可下载",
			"agent": "把 " + s.shareLink(token) + "/raw 交给 Agent：curl -OJ 即可拿到字节（不用登录）",
			"note":  "分享是临时放行：对方拿到字节即结束，不等于给他长期授权（那要 ncc grant）",
		},
	})
}

// listShares GET /api/shares?mine=1|all=1
func (s *Server) listShares(c *gin.Context) {
	a := authOf(c)
	createdBy := ""
	if a != nil {
		createdBy = a.UserID
	}
	if c.Query("all") == "1" {
		// 「看全部」是治理动作：要么是这个节点上的管理员账号，要么带 admin key/secret。
		if !s.ensureAdmin(c) {
			fail(c, 403, "admin_required", "查看全部分享需要节点管理员身份")
			return
		}
		createdBy = ""
	} else if a == nil {
		fail(c, 401, "unauthorized", "未认证或凭据无效（先 ncc login 或带 API-KEY）")
		return
	}
	limit, offset := pageParams(c)
	rows, err := s.St.ListShares(createdBy, limit, offset)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	total, _ := s.St.CountShares(createdBy)
	list := make([]gin.H, 0, len(rows))
	for i := range rows {
		list = append(list, s.shareRowJSON(&rows[i]))
	}
	ok(c, 200, gin.H{"shares": list, "total": total, "limit": limit, "offset": offset})
}

// deleteShare DELETE /api/shares/:id —— 撤自己的；管理员可撤任意（留审计）。
func (s *Server) deleteShare(c *gin.Context) {
	a := authOf(c)
	id := c.Param("id")
	sh, err := s.St.FindShareByID(id)
	if err != nil {
		fail(c, 404, "not_found", "分享不存在")
		return
	}
	isAdmin := s.ensureAdmin(c)
	if a == nil && !isAdmin {
		fail(c, 401, "unauthorized", "未认证或凭据无效（先 ncc login 或带 API-Key）")
		return
	}
	if !isAdmin && sh.CreatedBy != a.UserID {
		fail(c, 403, "forbidden", "只能撤销自己创建的分享")
		return
	}
	if err := s.St.RevokeShare(id, ""); err != nil {
		fail(c, 500, "internal", "撤销失败")
		return
	}
	s.audit(c, model.ActShareRevoke, sh.ID, sh.Label, "撤销分享链接",
		gin.H{"artifact": sh.ArtifactID, "byAdmin": isAdmin})
	ok(c, 200, gin.H{"ok": true})
}

/* ---------------- 领取（公开，不需登录） ---------------- */

// sharePage GET /s/:token —— 落地页。
//
// 不计数：给人看的页面被打开多次不该消耗次数（次数是给**取字节**用的）。
func (s *Server) sharePage(c *gin.Context) {
	token := c.Param("token")
	sh, err := s.St.FindShareByToken(token)
	if err != nil {
		c.Data(404, "text/html; charset=utf-8", []byte(sharePageHTML("", "", "链接不存在（可能已被撤销或删除）", false, 0, 0, 0)))
		return
	}
	row, rerr := s.St.FindArtifactByID(sh.ArtifactID)
	if rerr != nil {
		c.Data(404, "text/html; charset=utf-8", []byte(sharePageHTML("", "", "制品已被删除", false, 0, 0, 0)))
		return
	}
	usable := sh.Usable(time.Now())
	note := "链接有效"
	if !usable {
		note = "链接已失效（已撤销、已过期或次数用尽）"
	}
	c.Data(200, "text/html; charset=utf-8", []byte(sharePageHTML(
		row.Name, refOf(row)+"@"+row.Version, note, usable,
		row.Size, sh.MaxUses, sh.RemainingUses(),
	)))
}

// shareRaw GET /s/:token/raw —— 直接下发字节（curl / Agent 用）。**只有这里计数。**
func (s *Server) shareRaw(c *gin.Context) {
	token := c.Param("token")
	sh, err := s.St.FindShareByToken(token)
	if err != nil {
		fail(c, 404, "not_found", "链接不存在")
		return
	}
	row, err := s.St.FindArtifactByID(sh.ArtifactID)
	if err != nil {
		fail(c, 404, "not_found", "制品已被删除")
		return
	}
	// ?meta=1 只取元数据、不下发字节，也不计数 —— Agent 先看一眼再决定要不要拉。
	if c.Query("meta") == "1" {
		ok(c, 200, gin.H{
			"share":  s.shareJSON(sh, row, ""),
			"usable": sh.Usable(time.Now()),
			"file": gin.H{
				"name": row.Slug, "kind": row.Kind, "version": row.Version,
				"sha256": row.SHA256, "size": row.Size, "ref": refOf(row),
			},
		})
		return
	}
	if !sh.Usable(time.Now()) {
		fail(c, 410, "share_expired", "链接已失效（已撤销、已过期或次数用尽）")
		return
	}
	_ = s.St.MarkShareUsed(sh.ID)
	_ = s.St.BumpDownloads(row.ID)
	c.Header("X-NCC-Share", sh.ID)
	if left := sh.RemainingUses(); left > 0 {
		c.Header("X-NCC-Share-Remaining", itoa(left-1))
	}
	s.writeLocalBytes(c, row)
}

// shareInfo GET /api/shares/info/:token —— 公开的链接概要（CLI/页面对账用；不消耗次数）。
func (s *Server) shareInfo(c *gin.Context) {
	sh, err := s.St.FindShareByToken(c.Param("token"))
	if err != nil {
		fail(c, 404, "not_found", "链接不存在")
		return
	}
	row, err := s.St.FindArtifactByID(sh.ArtifactID)
	if err != nil {
		fail(c, 404, "not_found", "制品已被删除")
		return
	}
	ok(c, 200, gin.H{"share": s.shareJSON(sh, row, ""), "usable": sh.Usable(time.Now())})
}

/* ---------------- 视图 ---------------- */

func (s *Server) shareLink(token string) string {
	return strings.TrimRight(s.Cfg.PublicURL, "/") + "/s/" + token
}

// shareJSON token 是明文（只在创建时返回），这里只给链接骨架。
func (s *Server) shareJSON(sh *model.ArtifactShare, row *store.ArtifactRow, link string) gin.H {
	out := gin.H{
		"id": sh.ID, "label": sh.Label, "hint": sh.TokenHint,
		"uses":      gin.H{"max": sh.MaxUses, "used": sh.UsedCount, "remaining": sh.RemainingUses()},
		"expiresAt": sh.ExpiresAt, "revokedAt": sh.RevokedAt,
		"lastUsedAt": sh.LastUsedAt, "createdAt": sh.CreatedAt,
		"usable": sh.Usable(time.Now()),
		"link":   firstNonEmpty(link, s.shareLink(sh.TokenHint+"…")),
	}
	if row != nil {
		out["artifact"] = gin.H{
			"id": row.ID, "name": row.Name, "slug": row.Slug, "kind": row.Kind,
			"version": row.Version, "ref": refOf(row), "sha256": row.SHA256,
			"size": row.Size, "status": row.Status, "visibility": row.Visibility,
			"namespace": gin.H{"slug": row.NsSlug, "name": row.NsName},
		}
	}
	return out
}

func (s *Server) shareRowJSON(r *store.ShareRow) gin.H {
	out := s.shareJSON(&r.ArtifactShare, nil, s.shareLink(r.TokenHint+"…"))
	out["artifact"] = gin.H{
		"id": r.ArtifactID, "name": r.ArtifactName, "slug": r.ArtifactSlug,
		"kind": r.ArtifactKind, "sha256": r.ArtifactSHA, "size": r.ArtifactSize,
		"status": r.ArtifactState, "ref": "@" + r.NsSlug + "/" + r.ArtifactSlug,
		"namespace": gin.H{"slug": r.NsSlug, "name": r.NsName},
	}
	out["createdBy"] = gin.H{"id": r.CreatedBy, "name": r.CreatedByName}
	return out
}

/* ---------------- 辅助 ---------------- */

// ensureAdmin 判断这次请求是否持有管理员身份，并把管理员身份放进 ctx（供 audit 用）：
// 会话管理员账号，或带正确 admin key/secret 的机器凭据。
//
// 分享列表 / 撤销挂在普通组下（普通用户也要能撤自己的分享），所以这里要自己判一次；
// 判定逻辑与 requireAdmin 完全一致 —— 改一个地方时务必同时改另一个。
func (s *Server) ensureAdmin(c *gin.Context) bool {
	if a := authOf(c); a != nil && a.Session {
		if u, err := s.St.FindUserByID(a.UserID); err == nil && u.IsAdmin && !u.Disabled {
			c.Set(adminCtxKey, &adminActor{Kind: model.ActorUser, ID: u.ID, Name: u.Email})
			return true
		}
	}
	key := strings.TrimSpace(c.GetHeader("X-NCC-Admin-Key"))
	secret := strings.TrimSpace(c.GetHeader("X-NCC-Admin-Secret"))
	if key == "" || secret == "" {
		return false
	}
	k, err := s.St.FindAdminKey(key)
	if err != nil || !k.Active() || store.HashSecret(secret) != k.SecretHash {
		return false
	}
	_ = s.St.TouchAdminKey(k.ID)
	c.Set(adminCtxKey, &adminActor{Kind: model.ActorAdminKey, ID: k.Key, Name: firstNonEmpty(k.Label, k.Key)})
	return true
}

func itoa(n int64) string {
	if n <= 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// sharePageHTML 分享落地页（单文件、无依赖，和接入页同一路子）。
func sharePageHTML(name, ref, note string, usable bool, size, max, left int64) string {
	title := name
	if title == "" {
		title = "分享链接"
	}
	state := "可下载"
	if !usable {
		state = "不可用"
	}
	btn := ""
	if usable {
		btn = `<a class="btn" href="raw">下载文件</a>
    <div class="cmd"><code>curl -OJ ` + "{{RAW}}" + `</code></div>`
	}
	sizeText := ""
	if size > 0 {
		sizeText = itoa(size) + " B"
	}
	usesText := "不限次"
	if max > 0 {
		usesText = itoa(left) + " / " + itoa(max) + " 次剩余"
	}
	html := `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + title + ` · NCC Share</title>
<style>
 :root{color-scheme:dark}
 body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1017;color:#e6edf3;
      font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,"PingFang SC","Microsoft YaHei",sans-serif}
 .card{width:min(560px,92vw);background:#121a24;border:1px solid #1f2937;border-radius:14px;padding:28px}
 .k{color:#7d8590;font-size:12px;letter-spacing:.08em;text-transform:uppercase}
 h1{margin:.2em 0 .1em;font-size:20px}
 .ref{color:#6ee7b7;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
 .note{margin:14px 0;padding:10px 12px;border-radius:9px;background:#0e1620;border:1px solid #1f2937;color:#9fb0c0}
 .btn{display:inline-block;margin-top:14px;padding:10px 18px;border-radius:9px;background:#2f81f7;color:#fff;
      text-decoration:none;font-weight:600}
 .cmd{margin-top:12px;padding:10px 12px;border-radius:9px;background:#0b1017;border:1px solid #1f2937;
      font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:#c9d1d9;overflow:auto}
 .meta{margin-top:16px;color:#7d8590;font-size:12.5px}
 .ok{color:#4ade80}.bad{color:#f87171}
</style></head><body><div class="card">
 <div class="k">NCC Registry · 分享</div>
 <h1>` + title + `</h1>
 <div class="ref">` + ref + `</div>
 <div class="note">` + note + ` —— <span class="` + map[bool]string{true: "ok", false: "bad"}[usable] + `">` + state + `</span></div>
 ` + btn + `
 <div class="meta">大小 ` + sizeText + ` · ` + usesText + `</div>
 <div class="meta">这条链接是临时放行：拿到字节即结束，不代表长期授权。</div>
</div>
<script>
 // 页面地址后面拼 /raw 即为直链（这里把当前地址补全给命令示例，避免硬编码 host）。
 var raw = location.href.replace(/#.*$/, '').replace(/\/+$/, '') + '/raw';
 document.querySelectorAll('.cmd code').forEach(function(el){ el.textContent = el.textContent.replace('{{RAW}}', raw); });
</script>
</body></html>`
	return html
}
