package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/fusedmodel/ncc-registry/model"
	"github.com/fusedmodel/ncc-registry/store"
)

/* ---------------- 目录 ---------------- */

// kinds GET /api/registry/kinds
func (s *Server) kinds(c *gin.Context) {
	counts, err := s.St.KindCounts()
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	list := make([]gin.H, 0, len(model.ArtifactKinds))
	for _, k := range model.ArtifactKinds {
		label, desc := k, ""
		if meta, hit := model.KindMeta[k]; hit {
			label, desc = meta[0], meta[1]
		}
		list = append(list, gin.H{"kind": k, "label": label, "desc": desc, "published": counts[k]})
	}
	ok(c, 200, gin.H{"kinds": list, "total": len(list)})
}

// listRegistry GET /api/registry?q&kind&tag&namespace&mine&page&size
func (s *Server) listRegistry(c *gin.Context) {
	a := authOf(c)
	mine := c.Query("mine") == "1" || c.Query("mine") == "true"
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))

	opts := store.ListOpts{
		Q: c.Query("q"), Kind: c.Query("kind"), Tag: c.Query("tag"),
		NsSlug: c.Query("namespace"), Page: page, Size: size, OrderBy: c.Query("sort"),
	}

	var nsMeta *model.Namespace
	canManage := false
	if opts.NsSlug != "" {
		if ns, err := s.St.FindNamespaceBySlug(opts.NsSlug); err == nil {
			nsMeta = ns
			if a != nil && s.canManage(ns.ID, a.UserID) {
				canManage = true
			}
		}
	}

	switch {
	case mine:
		if a == nil {
			fail(c, 403, "forbidden", "mine=1 需要登录")
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
		if qs := c.Query("status"); qs != "" {
			for _, st := range strings.Split(qs, ",") {
				if model.ValidStatus(strings.TrimSpace(st)) {
					opts.Statuses = append(opts.Statuses, strings.TrimSpace(st))
				}
			}
		}
	case canManage:
		// 可管理该命名空间：不过滤可见性/状态（私有与草稿都能看到）
	default:
		opts.PublicOnly = true
		opts.Statuses = []string{"published"}
	}

	res, err := s.St.ListArtifacts(opts)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	items := make([]gin.H, 0, len(res.Rows))
	for i := range res.Rows {
		items = append(items, artifactJSON(&res.Rows[i]))
	}
	out := gin.H{"items": items, "page": page, "size": size, "total": res.Total, "canManage": canManage}
	if nsMeta != nil {
		out["namespace"] = nsJSON(nsMeta, a != nil && nsMeta.OwnerID == a.UserID)
	}
	ok(c, 200, out)
}

/* ---------------- 详情 ---------------- */

// refFromParams 把路由参数拼回引用：@ns/slug 会落在 /:id/:slug 两个段上
// （gin 的单个 :param 不匹配斜杠），所以要拼回来。
func refFromParams(c *gin.Context) string {
	id := c.Param("id")
	if slug := c.Param("slug"); slug != "" {
		return id + "/" + slug
	}
	return id
}

// getItem GET /api/registry/:id[/:slug] —— ref 为 A-… id 或 @ns/slug。
func (s *Server) getItem(c *gin.Context) {
	row, err := s.findVisibleArtifact(c, refFromParams(c))
	if err != nil {
		failErr(c, err)
		return
	}
	ok(c, 200, gin.H{"item": artifactJSON(row)})
}

/* ---------------- 下载（含多节点路由） ---------------- */

// download GET /api/registry/:ref/download
//
// 这是「多节点」在数据面上的落点：master 上没有这份字节时，会告诉客户端去
// master 的 /bytes 端点取，master 再去持有该制品的 worker 拉回来 —— 客户端
// 只需要认识一个地址，节点增删对它透明。
func (s *Server) download(c *gin.Context) {
	ref := refFromParams(c)
	row, err := s.findVisibleArtifact(c, ref)
	if err == nil {
		_ = s.St.BumpDownloads(row.ID)
		out := gin.H{
			"id": row.ID, "name": row.Name, "version": row.Version,
			"namespaceSlug": row.NsSlug, "slug": row.Slug,
			"url": s.downloadURL(row), "provider": row.StorageProvider,
			"sha256": row.SHA256, "size": row.Size, "downloads": row.Downloads + 1,
			"via": gin.H{"role": "self", "nodeId": s.Cfg.NodeID},
		}
		ok(c, 200, out)
		return
	}

	// 本地没有 → 问集群目录（能力路由）。
	adv, werr := s.St.FindAdvertsByRef(ref)
	if werr != nil || len(adv) == 0 {
		fail(c, 404, "not_found", "制品不存在（本节点与集群目录里都没有）")
		return
	}
	pick := s.pickAdvert(adv)
	ok(c, 200, gin.H{
		"id": pick.Ref, "name": pick.Name, "version": pick.Version,
		"namespaceSlug": pick.NamespaceSlug, "slug": pick.Slug,
		"url":      s.Cfg.PublicURL + "/api/registry/" + pick.Ref + "/bytes",
		"provider": "cluster", "sha256": pick.SHA256, "size": pick.Size, "downloads": pick.Downloads,
		"via": gin.H{"role": "worker", "nodeId": pick.WorkerID, "nodeName": pick.WorkerName, "nodeUrl": pick.WorkerURL},
	})
}

// bytes GET /api/registry/:ref/bytes —— 真正的字节流：本节点有就直接发，没有就从 worker 代理。
//
// 授权两条路：
//  1. 带凭据（JWT / 节点令牌 / API-Key）且能读到该条目；
//  2. 带**签名地址**（见 signedBytesURL）—— 客户端拿到元数据时服务端临时签的，
//     因为 `ncc download` 拉字节时不会再带 Authorization，私有条目必须给一条能自证的 URL。
func (s *Server) bytes(c *gin.Context) {
	ref := refFromParams(c)
	if row, err := s.findByRef(ref); err == nil {
		uid := ""
		if a := authOf(c); a != nil {
			uid = a.UserID
		}
		if !s.canReadArtifact(row, uid) && !s.validBytesSig(ref, c.Query("exp"), c.Query("sig")) {
			fail(c, 404, "not_found", "制品不存在或不可见")
			return
		}
		s.writeLocalBytes(c, row)
		return
	}
	adv, err := s.St.FindAdvertsByRef(ref)
	if err != nil || len(adv) == 0 {
		fail(c, 404, "not_found", "字节不存在（本节点与集群目录里都没有）")
		return
	}
	pick := s.pickAdvert(adv)
	if pick.WorkerURL == "" {
		fail(c, 502, "worker_unreachable", "提供该制品的节点没有上报可用地址")
		return
	}
	target := strings.TrimRight(pick.WorkerURL, "/") + "/api/registry/" + pick.Ref + "/bytes"
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, target, nil)
	if err != nil {
		fail(c, 500, "internal", "构造代理请求失败")
		return
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		fail(c, 502, "worker_unreachable", "拉取节点 "+pick.WorkerName+" 的字节失败: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		fail(c, 502, "worker_error", fmt.Sprintf("节点 %s 返回 %d", pick.WorkerName, resp.StatusCode))
		return
	}
	c.Header("X-NCC-Via", pick.WorkerID)
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		c.Header("Content-Type", ct)
	} else {
		c.Header("Content-Type", "application/octet-stream")
	}
	c.Status(200)
	_, _ = io.Copy(c.Writer, resp.Body)
}

// writeLocalBytes 输出本节点持有的字节（BYO 直链则 302 过去）。
func (s *Server) writeLocalBytes(c *gin.Context, row *store.ArtifactRow) {
	if row.StorageProvider != "local" || row.BlobName == "" {
		c.Redirect(http.StatusFound, row.StorageURL)
		return
	}
	rc, size, err := s.Blob.Open(row.BlobName)
	if err != nil {
		fail(c, 404, "not_found", "字节已不在本节点（可能已被清理）")
		return
	}
	defer rc.Close()
	name := row.Slug
	if ext := path.Ext(row.BlobName); ext != "" {
		name += ext
	}
	if row.SHA256 != "" {
		c.Header("X-NCC-SHA256", row.SHA256)
	}
	c.Header("Content-Disposition", "attachment; filename=\""+name+"\"")
	c.DataFromReader(200, size, "application/octet-stream", rc, nil)
}

/* ---------------- 上传 / 创建 / 修改 / 删除 ---------------- */

// upload POST /api/registry/uploads —— raw body + X-Filename，响应与平台同形。
func (s *Server) upload(c *gin.Context) {
	a := authOf(c)
	filename := c.GetHeader("X-Filename")
	if filename == "" {
		filename = "upload.bin"
	}
	ext := path.Ext(filename)
	if len(ext) > 16 {
		ext = ext[:16]
	}
	shortID := a.UserID
	if len(shortID) > 6 {
		shortID = shortID[len(shortID)-6:]
	}
	name := fmt.Sprintf("%s-%s%s", shortID, store.RandHex(6), ext)

	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 256<<20+1))
	if err != nil || len(body) == 0 {
		fail(c, 400, "bad_request", "请求体为空或读取失败")
		return
	}
	if len(body) > 256<<20 {
		fail(c, 413, "payload_too_large", "请求体超过 256MB")
		return
	}
	url, err := s.Blob.Put(name, body)
	if err != nil {
		fail(c, 500, "internal", "写入制品字节失败")
		return
	}
	sum := sha256.Sum256(body)
	ok(c, 201, gin.H{
		"storageUrl": url, "filename": name,
		"size": len(body), "sha256": hex.EncodeToString(sum[:]),
	})
}

type createItemReq struct {
	Kind       string         `json:"kind"`
	Name       string         `json:"name"`
	Slug       string         `json:"slug"`
	Version    string         `json:"version"`
	Summary    string         `json:"summary"`
	Tags       []string       `json:"tags"`
	Status     string         `json:"status"`
	Visibility string         `json:"visibility"`
	Manifest   map[string]any `json:"manifest"`
	Namespace  string         `json:"namespaceId"`
	// Replicate 分发目标（可选）："all" 或 ["workerId"/"workerName", …]。
	// 缺省不分发（副本按需铺，不替用户做决定）。
	Replicate any `json:"replicate"`
	Storage   struct {
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"storage"`
}

// createItem POST /api/registry
func (s *Server) createItem(c *gin.Context) {
	a := authOf(c)
	var body createItemReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	body.Kind = strings.TrimSpace(body.Kind)
	body.Name = strings.TrimSpace(body.Name)
	if body.Kind == "" {
		fail(c, 400, "bad_request", "kind 不能为空")
		return
	}
	if !model.ValidKind(body.Kind) {
		fail(c, 400, "bad_request", "未知 kind "+body.Kind+"（可用 /api/registry/kinds 查看）")
		return
	}
	if body.Name == "" {
		fail(c, 400, "bad_request", "name 不能为空")
		return
	}
	if strings.TrimSpace(body.Storage.URL) == "" {
		fail(c, 400, "bad_request", "storage.url 不能为空（先 POST /api/registry/uploads，或提供自有直链）")
		return
	}

	nsID := strings.TrimSpace(body.Namespace)
	var ns *model.Namespace
	if nsID == "" {
		personal, err := s.St.PersonalNamespace(a.UserID)
		if err != nil {
			fail(c, 400, "bad_request", "当前账号没有个人命名空间，请重新注册")
			return
		}
		ns = personal
	} else {
		found, err := s.St.FindNamespaceByID(nsID)
		if err != nil {
			fail(c, 400, "bad_request", "namespace 不存在")
			return
		}
		ns = found
	}
	if !s.canManage(ns.ID, a.UserID) {
		fail(c, 403, "forbidden", "你不是该 namespace 的 owner/成员")
		return
	}

	slug := store.Slugify(body.Slug)
	if strings.TrimSpace(body.Slug) == "" || slug == "x" {
		slug = store.Slugify(body.Name)
	}
	if slug == "x" {
		slug = "item-" + store.RandHex(3)
	}
	if _, err := s.St.FindArtifactByNsSlug(ns.Slug, slug); err == nil {
		fail(c, 409, "conflict", fmt.Sprintf("该 namespace 下 slug「%s」已存在", slug))
		return
	}

	status := "draft"
	if body.Status == "published" {
		status = "published"
	}
	visibility := "public"
	if body.Visibility == "private" {
		visibility = "private"
	}
	version := strings.TrimSpace(body.Version)
	if version == "" {
		version = "1.0.0"
	}
	tags := body.Tags
	if tags == nil {
		tags = []string{}
	}
	if len(tags) > 20 {
		tags = tags[:20]
	}

	manifest := ""
	if len(body.Manifest) > 0 {
		b, err := jsonMarshal(body.Manifest)
		if err != nil {
			fail(c, 400, "bad_manifest", "manifest 无法序列化")
			return
		}
		manifest = string(b)
		if body.Kind == "harness" {
			hasLoader, hasEntry := false, false
			if h, ok := body.Manifest["harness"].(map[string]any); ok {
				if v, _ := h["loader"].(string); v != "" {
					hasLoader = true
				}
				if v, _ := h["entry"].(string); v != "" {
					hasEntry = true
				}
			}
			if !hasLoader && !hasEntry {
				fail(c, 400, "bad_contract", "kind=harness 的 manifest 需提供 harness.loader 或 harness.entry")
				return
			}
		}
	}

	provider := "byo"
	blobName := ""
	if n := s.blobNameFromURL(body.Storage.URL); n != "" {
		provider, blobName = "local", n
	}

	created, err := s.St.CreateArtifact(store.CreateArtifactInput{
		NamespaceID: ns.ID, Kind: body.Kind, Name: body.Name, Slug: slug,
		Version: version, Summary: body.Summary, Tags: tags,
		Visibility: visibility, Status: status, Manifest: manifest,
		Provider: provider, StorageURL: strings.TrimSpace(body.Storage.URL), BlobName: blobName,
		SHA256: body.Storage.SHA256, Size: body.Storage.Size, CreatedBy: a.UserID,
	})
	if err != nil {
		if isConflict(err) {
			fail(c, 409, "conflict", "唯一性冲突")
		} else {
			fail(c, 500, "internal", "创建失败")
		}
		return
	}
	row, err := s.St.FindArtifactByID(created.ID)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	out := gin.H{"item": artifactJSON(row)}

	// 分发：master 是发布入口；--replicate all / <worker> 让指定节点也持有副本。
	if spec, ok := body.Replicate, true; ok && spec != nil {
		targets, err := s.St.ListWorkers()
		if err == nil {
			if picked, perr := pickWorkers(targets, spec); perr == nil {
				out["replicated"] = s.fanout(c.Request.Context(), row, picked)
			} else {
				out["replicateError"] = perr.Error()
			}
		}
	}
	ok(c, 201, out)
}

// patchItem PATCH /api/registry/:id[/:slug]
func (s *Server) patchItem(c *gin.Context) {
	a := authOf(c)
	row, err := s.findByRef(refFromParams(c))
	if err != nil {
		fail(c, 404, "not_found", "条目不存在")
		return
	}
	if row.IsReplica() {
		fail(c, 403, "replica_readonly", "这是其它节点分发过来的副本，请到源头节点修改")
		return
	}
	if !s.canManage(row.NamespaceID, a.UserID) {
		fail(c, 403, "forbidden", "你不是该条目的 owner/成员")
		return
	}
	var body struct {
		Status      *string   `json:"status"`
		Visibility  *string   `json:"visibility"`
		Summary     *string   `json:"summary"`
		Name        *string   `json:"name"`
		Version     *string   `json:"version"`
		Tags        *[]string `json:"tags"`
		Description *string   `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	fields := map[string]any{}
	if body.Status != nil {
		if !model.ValidStatus(*body.Status) {
			fail(c, 400, "bad_request", "status 只能是 draft/published/archived")
			return
		}
		fields["status"] = *body.Status
	}
	if body.Visibility != nil {
		if *body.Visibility != "public" && *body.Visibility != "private" {
			fail(c, 400, "bad_request", "visibility 只能是 public/private")
			return
		}
		fields["visibility"] = *body.Visibility
	}
	if body.Summary != nil {
		fields["summary"] = *body.Summary
	}
	if body.Name != nil && strings.TrimSpace(*body.Name) != "" {
		fields["name"] = strings.TrimSpace(*body.Name)
	}
	if body.Version != nil && strings.TrimSpace(*body.Version) != "" {
		fields["version"] = strings.TrimSpace(*body.Version)
	}
	if body.Tags != nil {
		b, err := jsonMarshal(*body.Tags)
		if err != nil {
			fail(c, 400, "bad_request", "tags 无法序列化")
			return
		}
		fields["tags"] = string(b)
	}
	if len(fields) == 0 {
		fail(c, 400, "bad_request", "没有可更新的字段")
		return
	}
	if err := s.St.UpdateArtifactFields(row.ID, fields); err != nil {
		fail(c, 500, "internal", "更新失败")
		return
	}
	fresh, _ := s.St.FindArtifactByID(row.ID)
	ok(c, 200, gin.H{"item": artifactJSON(fresh)})
}

// deleteItem DELETE /api/registry/:id[/:slug]
//
// 下架同时**回收**：把变更广播给持有副本的节点（副本删掉，本节点自己发布的条目不受影响）。
func (s *Server) deleteItem(c *gin.Context) {
	a := authOf(c)
	row, err := s.findByRef(refFromParams(c))
	if err != nil {
		fail(c, 404, "not_found", "条目不存在")
		return
	}
	if row.IsReplica() {
		fail(c, 403, "replica_readonly", "这是其它节点分发过来的副本，请在源头节点下架（会连带回收）")
		return
	}
	if !s.canManage(row.NamespaceID, a.UserID) {
		fail(c, 403, "forbidden", "你不是该条目的 owner/成员")
		return
	}
	ref := refOf(row) + "@" + row.Version
	if row.StorageProvider == "local" && row.BlobName != "" {
		_ = s.Blob.Delete(row.BlobName)
	}
	if err := s.St.DeleteArtifact(row.ID); err != nil {
		fail(c, 500, "internal", "删除失败")
		return
	}
	revoked := s.revokeReplicas(c.Request.Context(), ref)
	ok(c, 200, gin.H{"ok": true, "ref": ref, "revoked": revoked})
}

/* ---------------- 内部工具 ---------------- */

// findByRef 按引用取制品（不判权限）。支持 A-… 形式的 id 与 @ns/slug。
func (s *Server) findByRef(ref string) (*store.ArtifactRow, error) {
	id, nsSlug, slug := parseArtifactRef(ref)
	if strings.HasPrefix(strings.TrimSpace(ref), "@") && nsSlug != "" && slug != "" {
		return s.St.FindArtifactByNsSlug(nsSlug, slug)
	}
	if id != "" {
		return s.St.FindArtifactByID(id)
	}
	return nil, gorm.ErrRecordNotFound
}

// findVisibleArtifact 按引用取制品并做可见性判断：
// 已发布的公开条目人人可见；其余要么是该命名空间成员，要么拿到发布者的 artifact 授权。
func (s *Server) findVisibleArtifact(c *gin.Context, ref string) (*store.ArtifactRow, error) {
	row, err := s.findByRef(ref)
	if err != nil {
		return nil, errArtifactMissing
	}
	uid := ""
	if a := authOf(c); a != nil {
		uid = a.UserID
	}
	if s.canReadArtifact(row, uid) {
		return row, nil
	}
	return nil, errArtifactHidden
}

var (
	errArtifactMissing = errWith(404, "not_found", "制品不存在")
	errArtifactHidden  = errWith(404, "not_found", "制品不存在或不可见（私有/草稿需要该命名空间成员身份）")
)

// canManage 命名空间写权限。
func (s *Server) canManage(nsID, userID string) bool {
	return s.St.IsOwner(nsID, userID) || s.St.IsMember(nsID, userID)
}

// blobNameFromURL 判断这个下载地址是不是本节点托管目录里的对象。
func (s *Server) blobNameFromURL(u string) string {
	prefix := s.Cfg.PublicURL + "/blobs/"
	if strings.HasPrefix(u, prefix) {
		return strings.TrimPrefix(u, prefix)
	}
	if i := strings.Index(u, "/blobs/"); i >= 0 {
		return u[i+len("/blobs/"):]
	}
	return ""
}

// downloadURL 本节点持有的制品一律走 /bytes（这样 master 也能代理到 worker，
// 客户端始终只认一个地址）；BYO 直链则原样返回。
//
// 公开条目给稳定地址（可缓存、可分享）；私有/草稿给**短时签名地址** —— 调用方此刻
// 已经通过可见性检查，这次拿到的 URL 就是它的通行证（客户端拉字节时不再带凭据）。
func (s *Server) downloadURL(row *store.ArtifactRow) string {
	if row.StorageProvider != "local" || row.BlobName == "" {
		return row.StorageURL
	}
	if row.Status == "published" && row.Visibility == "public" {
		return s.Cfg.PublicURL + "/api/registry/" + refOf(row) + "/bytes"
	}
	return s.signedBytesURL(row, 10*time.Minute)
}

// signedBytesURL 给一个短时有效的字节地址：HMAC(secret, ref|exp)。
func (s *Server) signedBytesURL(row *store.ArtifactRow, ttl time.Duration) string {
	exp := time.Now().Add(ttl).Unix()
	ref := refOf(row)
	sig := hmacSHA256(s.Cfg.JWTSecret, ref+"|"+strconv.FormatInt(exp, 10))
	return fmt.Sprintf("%s/api/registry/%s/bytes?exp=%d&sig=%s", s.Cfg.PublicURL, ref, exp, sig)
}

// validBytesSig 校验签名地址（过期或签名不对一律当无效）。
func (s *Server) validBytesSig(ref, exp, sig string) bool {
	n, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || n < time.Now().Unix() || sig == "" {
		return false
	}
	expect := hmacSHA256(s.Cfg.JWTSecret, ref+"|"+exp)
	return hmac.Equal([]byte(sig), []byte(expect))
}

// refOf 规范引用 @ns/slug（ns 与 slug 都是 URL 安全字符，不需要转义）。
func refOf(row *store.ArtifactRow) string { return "@" + row.NsSlug + "/" + row.Slug }

// pickAdvert 多个 worker 都持有同一个制品时，选心跳最新的那个。
func (s *Server) pickAdvert(adv []store.AdvertRow) store.AdvertRow {
	best := adv[0]
	for _, a := range adv[1:] {
		if a.SeenAt.After(best.SeenAt) {
			best = a
		}
	}
	return best
}
