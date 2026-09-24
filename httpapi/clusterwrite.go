package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/fusedmodel/ncc-registry/model"
	"github.com/fusedmodel/ncc-registry/store"
)

// 集群写路径：**发布分发（replicate）与下架回收（revoke）**。
//
// 语义（与「客户端只认 master 一个地址」一致）：
//   - 发布在 master 上发生（权威记录 + 字节都落 master）。
//   - 需要让内网某个/全部 worker 也**持有副本**时，master 把「条目 + 来源地址」推给 worker；
//     worker 自己去 master 的 /bytes 拉字节、校验 sha256，落成 Origin=replica 的副本。
//   - 下架时 master 把变更**广播**给持有副本的 worker，副本被删掉（本节点自己发布的条目不受影响）。
//
// 两个内部接口（节点间，走 NCCR_CLUSTER_TOKEN 鉴权）：
//
//	POST /api/cluster/ingest   {ref, …, sourceUrl}  → 落副本（幂等，同 ref 盖写）
//	POST /api/cluster/revoke   {ref}                → 回收副本

/* ---------------- 参数 ---------------- */

type ingestReq struct {
	Ref           string         `json:"ref"`
	NamespaceSlug string         `json:"namespaceSlug"`
	Slug          string         `json:"slug"`
	Kind          string         `json:"kind"`
	Name          string         `json:"name"`
	Version       string         `json:"version"`
	Summary       string         `json:"summary"`
	Tags          []string       `json:"tags"`
	Manifest      map[string]any `json:"manifest"`
	SHA256        string         `json:"sha256"`
	Size          int64          `json:"size"`
	SourceURL     string         `json:"sourceUrl"` // worker 从这里拉字节（master 的 /bytes）
}

/* ---------------- worker 侧：落副本 / 回收副本 ---------------- */

// clusterIngest POST /api/cluster/ingest
func (s *Server) clusterIngest(c *gin.Context) {
	if !s.checkClusterToken(c) {
		return
	}
	var body ingestReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	if body.Ref == "" || body.NamespaceSlug == "" || body.Slug == "" || body.SourceURL == "" {
		fail(c, 400, "bad_request", "ref / namespaceSlug / slug / sourceUrl 必填")
		return
	}
	if !model.ValidKind(body.Kind) {
		fail(c, 400, "bad_request", "未知 kind "+body.Kind)
		return
	}

	// 自己去来源拉字节（内部调用带集群 token；BYO 直链则由 http 客户端跟随重定向）
	data, err := s.fetchBlob(c.Request.Context(), body.SourceURL)
	if err != nil {
		fail(c, 502, "source_unreachable", "拉取来源字节失败: "+err.Error())
		return
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if body.SHA256 != "" && got != body.SHA256 {
		fail(c, 400, "digest_mismatch", fmt.Sprintf("字节校验不一致（期望 %s，实际 %s）", body.SHA256, got))
		return
	}

	ext := ""
	if i := strings.LastIndex(body.Slug, "."); i > 0 {
		ext = body.Slug[i:]
	}
	blobName := fmt.Sprintf("%s-%s%s", store.Slugify(body.NamespaceSlug), store.RandHex(6), ext)
	storageURL, err := s.Blob.Put(blobName, data)
	if err != nil {
		fail(c, 500, "internal", "写入副本字节失败")
		return
	}
	ns, err := s.St.EnsureMirrorNamespace(body.NamespaceSlug, body.NamespaceSlug)
	if err != nil {
		fail(c, 500, "internal", "创建镜像命名空间失败")
		return
	}
	manifest := ""
	if len(body.Manifest) > 0 {
		if b, err := jsonMarshal(body.Manifest); err == nil {
			manifest = string(b)
		}
	}
	row, err := s.St.UpsertReplica(ns.ID, store.CreateArtifactInput{
		NamespaceSlug: body.NamespaceSlug,
		Kind:          body.Kind, Name: body.Name, Slug: body.Slug, Version: body.Version,
		Summary: body.Summary, Tags: body.Tags, Manifest: manifest,
		Provider: "local", StorageURL: storageURL, BlobName: blobName,
		SHA256: got, Size: int64(len(data)),
		CreatedBy: model.MirrorOwner, OriginRef: body.Ref,
	})
	if err != nil {
		fail(c, 500, "internal", "落副本失败")
		return
	}
	logf("[cluster] 已接收副本 %s（%d 字节，sha256 %s）", body.Ref, len(data), got[:12])
	ok(c, 200, gin.H{
		"ok": true, "ref": body.Ref, "sha256": got, "size": len(data),
		"nodeId": s.Cfg.NodeID, "nodeName": s.Cfg.NodeName,
		"artifactId": row.ID, "storageUrl": row.StorageURL,
	})
}

// clusterRevoke POST /api/cluster/revoke —— 回收一份副本。
func (s *Server) clusterRevoke(c *gin.Context) {
	if !s.checkClusterToken(c) {
		return
	}
	var body struct {
		Ref string `json:"ref"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Ref) == "" {
		fail(c, 400, "bad_request", "需要 ref")
		return
	}
	id, blobName, removed, err := s.St.DeleteReplica(strings.TrimSpace(body.Ref))
	if err != nil {
		fail(c, 500, "internal", "回收副本失败")
		return
	}
	if removed && blobName != "" {
		_ = s.Blob.Delete(blobName)
	}
	if removed {
		logf("[cluster] 已回收副本 %s", body.Ref)
	}
	ok(c, 200, gin.H{
		"ok": true, "ref": body.Ref, "removed": removed, "artifactId": id,
		"nodeId": s.Cfg.NodeID, "nodeName": s.Cfg.NodeName,
	})
}

// fetchBlob 拉取来源字节（内部调用带集群 token）。
func (s *Server) fetchBlob(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if s.Cfg.ClusterToken != "" {
		req.Header.Set("X-NCC-Cluster-Token", s.Cfg.ClusterToken)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("来源返回 %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20+1))
}

/* ---------------- master 侧：分发 / 回收 ---------------- */

type replicateReq struct {
	Ref     string `json:"ref"`
	Targets any    `json:"targets"` // "all" 或 ["workerId"/"workerName", …]
}

// replicateArtifact POST /api/cluster/replicate —— 把已存在的制品分发到 worker。
func (s *Server) replicateArtifact(c *gin.Context) {
	a := authOf(c)
	var body replicateReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	row, err := s.findByRef(body.Ref)
	if err != nil {
		fail(c, 404, "not_found", "制品不存在")
		return
	}
	if !s.canManage(row.NamespaceID, a.UserID) {
		fail(c, 403, "forbidden", "你不是该条目的 owner/成员")
		return
	}
	if row.IsReplica() {
		fail(c, 400, "bad_request", "这是别人分发下来的副本，请到源头节点上操作")
		return
	}
	targets, err := s.St.ListWorkers()
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	picked, err := pickWorkers(targets, body.Targets)
	if err != nil {
		fail(c, 400, "bad_request", err.Error())
		return
	}
	results := s.fanout(c.Request.Context(), row, picked)
	ok(c, 200, gin.H{"ref": refOf(row), "results": results, "targets": len(picked)})
}

// pickWorkers 解析分发目标："all" / ["名称或 id"]；没给 targets 就报错（避免误分发）。
func pickWorkers(all []model.ClusterWorker, spec any) ([]model.ClusterWorker, error) {
	switch v := spec.(type) {
	case nil:
		return nil, fmt.Errorf("需要 targets（\"all\" 或 worker 名称/id 列表）")
	case string:
		if strings.EqualFold(strings.TrimSpace(v), "all") {
			return all, nil
		}
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("targets 不能为空")
		}
		return matchWorkers(all, []string{v})
	case []any:
		want := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				want = append(want, s)
			}
		}
		if len(want) == 0 {
			return nil, fmt.Errorf("targets 不能为空")
		}
		return matchWorkers(all, want)
	}
	return nil, fmt.Errorf("targets 格式不支持")
}

func matchWorkers(all []model.ClusterWorker, want []string) ([]model.ClusterWorker, error) {
	out := make([]model.ClusterWorker, 0, len(want))
	for _, w := range want {
		hit := false
		for _, c := range all {
			if strings.EqualFold(c.ID, w) || strings.EqualFold(c.Name, w) {
				out = append(out, c)
				hit = true
				break
			}
		}
		if !hit {
			return nil, fmt.Errorf("找不到 worker %q（用 /api/cluster/workers 看有哪些）", w)
		}
	}
	return out, nil
}

// fanout 把一份制品推给若干 worker：worker 自己去 sourceUrl 拉字节并校验。
func (s *Server) fanout(ctx context.Context, row *store.ArtifactRow, workers []model.ClusterWorker) []gin.H {
	results := make([]gin.H, 0, len(workers))
	if len(workers) == 0 {
		return results
	}
	ref := refOf(row) + "@" + row.Version
	payload, err := jsonMarshal(ingestReq{
		Ref:           ref,
		NamespaceSlug: row.NsSlug, Slug: row.Slug, Kind: row.Kind, Name: row.Name,
		Version: row.Version, Summary: row.Summary, Tags: store.ParseList(row.Tags),
		Manifest: parseManifestMap(row.Manifest), SHA256: row.SHA256, Size: row.Size,
		// 给 worker 一个短时签名地址：私有条目也能分发，且不必把集群 token 当作下载凭据。
		SourceURL: s.signedBytesURL(row, 30*time.Minute),
	})
	if err != nil {
		return append(results, gin.H{"nodeName": "-", "ok": false, "error": "序列化失败"})
	}

	for _, w := range workers {
		item := gin.H{"nodeId": w.ID, "nodeName": w.Name, "nodeUrl": w.URL, "ok": false}
		if !nodeOnline(w.LastSeen, s.Cfg.NodeTTL*4) {
			item["error"] = "节点离线（超过 TTL 没心跳）"
			results = append(results, item)
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimRight(w.URL, "/")+"/api/cluster/ingest", bytes.NewReader(payload))
		if err != nil {
			item["error"] = err.Error()
			results = append(results, item)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if s.Cfg.ClusterToken != "" {
			req.Header.Set("X-NCC-Cluster-Token", s.Cfg.ClusterToken)
		}
		resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
		if err != nil {
			item["error"] = "不可达：" + err.Error()
			results = append(results, item)
			continue
		}
		var out struct {
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
			Error  struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		derr := json.NewDecoder(resp.Body).Decode(&out)
		_ = resp.Body.Close()
		if resp.StatusCode >= 400 {
			msg := out.Error.Message
			if msg == "" && derr != nil {
				msg = fmt.Sprintf("返回 %d", resp.StatusCode)
			}
			item["error"] = msg
			results = append(results, item)
			continue
		}
		item["ok"] = true
		item["sha256"] = out.SHA256
		item["size"] = out.Size
		// 分发成功即记账：下架回收以这份记录为准，不依赖 worker 心跳是否已上报。
		_ = s.St.RecordReplicaTarget(ref, w.ID, w.Name, w.URL, out.SHA256, out.Size)
		results = append(results, item)
	}
	return results
}

// revokeReplicas 回收该 ref 在各节点上的副本。
//
// 目标来源：master 侧的分发记录（fanout 成功时写的）为主，worker 上报的目录（adverts）为兜底 ——
// 后者依赖心跳，可能滞后；只认它会让「刚分发完就下架」漏掉回收。
func (s *Server) revokeReplicas(ctx context.Context, ref string) []gin.H {
	targets := map[string]gin.H{} // workerID → {name, url}
	if rows, err := s.St.ListReplicaTargets(ref); err == nil {
		for _, t := range rows {
			targets[t.WorkerID] = gin.H{"name": t.WorkerName, "url": t.WorkerURL}
		}
	}
	if adv, err := s.St.FindAdvertsByRef(ref); err == nil {
		for i := range adv {
			a := adv[i]
			if a.WorkerID == "" || a.WorkerURL == "" {
				continue
			}
			if _, ok := targets[a.WorkerID]; !ok {
				targets[a.WorkerID] = gin.H{"name": a.WorkerName, "url": a.WorkerURL}
			}
		}
	}
	if len(targets) == 0 {
		return nil
	}

	results := make([]gin.H, 0, len(targets))
	allOK := true
	for id, meta := range targets {
		url, _ := meta["url"].(string)
		item := gin.H{"nodeId": id, "nodeName": meta["name"], "ok": false}
		payload, _ := jsonMarshal(gin.H{"ref": ref})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimRight(url, "/")+"/api/cluster/revoke", bytes.NewReader(payload))
		if err != nil {
			item["error"] = err.Error()
			allOK = false
			results = append(results, item)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if s.Cfg.ClusterToken != "" {
			req.Header.Set("X-NCC-Cluster-Token", s.Cfg.ClusterToken)
		}
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			item["error"] = "不可达：" + err.Error()
			allOK = false
			results = append(results, item)
			continue
		}
		var out struct {
			Removed bool `json:"removed"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		_ = resp.Body.Close()
		ok := resp.StatusCode < 400
		item["ok"] = ok
		item["removed"] = out.Removed
		if !ok {
			allOK = false
		}
		results = append(results, item)
	}
	// 全部回收成功才清账；否则留着，下次下架/重试还能找到这些节点。
	if allOK {
		_ = s.St.DeleteReplicaTargets(ref)
	}
	return results
}

// parseManifestMap 把存储的 manifest JSON 还原成对象（分发时原样带过去）。
func parseManifestMap(s string) map[string]any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	return v
}
