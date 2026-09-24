package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/fusedmodel/ncc-registry/config"
	"github.com/fusedmodel/ncc-registry/store"
)

// clusterHub 维护集群视角。
//
// master 侧：维护 worker 注册表（谁在线、提供什么），并把「目录聚合 + 能力路由」
// 做在自己这边（权威在 master，worker 只是边缘托管点）。
// worker 侧：启动即 join，之后按间隔心跳，把自己的目录清单一起报上去。
type clusterHub struct {
	cfg *config.Config
	st  *store.Store

	mu     sync.Mutex
	master *gin.H // worker 记住的 master 身份（/api/cluster 里回显）
	last   time.Time
	err    string

	// stop 关掉后，start() 起的后台循环退出。作为库被嵌入时这是必需的：
	// 进程退出时留几个协程无所谓，但反复 New/Close 就会一直漏。
	stop     chan struct{}
	stopOnce sync.Once
}

func newClusterHub(cfg *config.Config, st *store.Store) *clusterHub {
	return &clusterHub{cfg: cfg, st: st, stop: make(chan struct{})}
}

// Close 让 start() 起的后台循环退出。可重复调用。
func (h *clusterHub) Close() {
	h.stopOnce.Do(func() { close(h.stop) })
}

// sleep 等 d；hub 已关闭则返回 false，调用方直接退出循环。
func (h *clusterHub) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-h.stop:
		return false
	}
}

// start 后台循环：worker 心跳 / master 清理过期 worker。
func (h *clusterHub) start() {
	if h.cfg.Role == config.RoleWorker {
		go func() {
			if err := h.join(); err != nil {
				h.setErr(err)
				log.Printf("[cluster] 注册到 master 失败（会继续重试）: %v", err)
			}
			interval := h.cfg.HeartbeatEvery
			if interval < 3*time.Second {
				interval = 3 * time.Second
			}
			for {
				if !h.sleep(interval) {
					return
				}
				if err := h.heartbeat(); err != nil {
					h.setErr(err)
					log.Printf("[cluster] 心跳失败: %v", err)
					continue
				}
				h.setErr(nil)
			}
		}()
		return
	}

	// master：定期清掉长期没心跳的 worker，避免目录里挂着幽灵节点。
	go func() {
		for {
			if !h.sleep(30 * time.Second) {
				return
			}
			if n, err := h.st.PruneWorkers(h.cfg.NodeTTL * 4); err == nil && n > 0 {
				log.Printf("[cluster] 已清理 %d 个失联 worker（及其目录）", n)
			}
		}
	}()
}

func (h *clusterHub) setErr(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil {
		h.last = time.Now()
		h.err = ""
		return
	}
	h.err = err.Error()
}

// join POST <master>/api/cluster/join
func (h *clusterHub) join() error {
	out, err := h.post("/api/cluster/join", h.heartbeatBody())
	if err != nil {
		return err
	}
	h.rememberMaster(out)
	return nil
}

// heartbeat POST <master>/api/cluster/heartbeat
func (h *clusterHub) heartbeat() error {
	out, err := h.post("/api/cluster/heartbeat", h.heartbeatBody())
	if err != nil {
		return err
	}
	h.rememberMaster(out)
	return nil
}

// rememberMaster 记住 master 的身份（/api/cluster 里回显给 CLI/控制台）。
func (h *clusterHub) rememberMaster(out gin.H) {
	m, ok := out["master"]
	if !ok {
		return
	}
	mm, ok := m.(map[string]any)
	if !ok {
		return
	}
	block := gin.H(mm)
	h.mu.Lock()
	h.master = &block
	h.mu.Unlock()
}

func (h *clusterHub) post(path string, body gin.H) (gin.H, error) {
	if h.cfg.MasterURL == "" {
		return nil, fmt.Errorf("未配置 master 地址")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, h.cfg.MasterURL+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.cfg.ClusterToken != "" {
		req.Header.Set("X-NCC-Cluster-Token", h.cfg.ClusterToken)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out gin.H
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("master 响应无法解析: %w", err)
	}
	if resp.StatusCode >= 400 {
		code, msg := "cluster_failed", fmt.Sprintf("master 返回 %d", resp.StatusCode)
		if e, ok := out["error"].(map[string]any); ok {
			if v, ok := e["code"].(string); ok {
				code = v
			}
			if v, ok := e["message"].(string); ok {
				msg = v
			}
		}
		return nil, fmt.Errorf("[%s] %s", code, msg)
	}
	return out, nil
}

// heartbeatBody 组装的注册/心跳体：我是谁 + 我这里有什么。
func (h *clusterHub) heartbeatBody() gin.H {
	artifacts, nodes, users := int64(0), int64(0), int64(0)
	rows, err := h.st.ListAdvertisableArtifacts(2000)
	if err != nil {
		log.Printf("[cluster] 读取本地目录失败: %v", err)
	}
	items := make([]gin.H, 0, len(rows))
	for i := range rows {
		r := rows[i]
		artifacts++
		items = append(items, gin.H{
			"ref":           "@" + r.NsSlug + "/" + r.Slug + "@" + r.Version,
			"namespaceSlug": r.NsSlug,
			"slug":          r.Slug,
			"kind":          r.Kind,
			"name":          r.Name,
			"version":       r.Version,
			"summary":       r.Summary,
			"tags":          store.ParseList(r.Tags),
			"sha256":        r.SHA256,
			"size":          r.Size,
			"downloads":     r.Downloads,
			"updatedAt":     r.UpdatedAt,
		})
	}
	nodes, _ = h.st.CountNodes()
	users, _ = h.st.CountUsers()

	return gin.H{
		"node": gin.H{
			"id": h.cfg.NodeID, "name": h.cfg.NodeName, "url": h.cfg.PublicURL,
			"version": Version, "region": h.cfg.NodeRegion,
			"capabilities": []string{"registry", "nodes", "artifacts"},
			"artifacts":    artifacts, "nodes": nodes, "users": users,
		},
		"artifacts": items,
	}
}

/* ---------------- master 侧接口 ---------------- */

type clusterJoinReq struct {
	Node struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		URL          string   `json:"url"`
		Version      string   `json:"version"`
		Region       string   `json:"region"`
		Capabilities []string `json:"capabilities"`
		Artifacts    int64    `json:"artifacts"`
		Nodes        int64    `json:"nodes"`
		Users        int64    `json:"users"`
	} `json:"node"`
	Artifacts []advertReq `json:"artifacts"`
}

type advertReq struct {
	Ref           string    `json:"ref"`
	NamespaceSlug string    `json:"namespaceSlug"`
	Slug          string    `json:"slug"`
	Kind          string    `json:"kind"`
	Name          string    `json:"name"`
	Version       string    `json:"version"`
	Summary       string    `json:"summary"`
	Tags          []string  `json:"tags"`
	SHA256        string    `json:"sha256"`
	Size          int64     `json:"size"`
	Downloads     int64     `json:"downloads"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// checkClusterToken 校验节点间的接入身份。
//
// 没配 NCCR_CLUSTER_TOKEN 时视为「内网开放集群」：任何能连上本节点的节点都放行
// （与单节点内网的信任模型一致）；配了就必须要带对 token。
func (s *Server) checkClusterToken(c *gin.Context) bool {
	if s.Cfg.ClusterToken == "" {
		return true
	}
	got := c.GetHeader("X-NCC-Cluster-Token")
	if got == "" {
		got = strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
	}
	if got != s.Cfg.ClusterToken {
		fail(c, 401, "cluster_token_invalid", "集群 token 不正确（对方配了 NCCR_CLUSTER_TOKEN）")
		return false
	}
	return true
}

// requireClusterMaster 只允许 worker 向 master 注册/心跳。
func (s *Server) requireClusterMaster(c *gin.Context) bool {
	if s.Cfg.Role != config.RoleMaster {
		fail(c, 400, "not_master", "本节点是 worker，不接受集群注册（请指向 master）")
		return false
	}
	return s.checkClusterToken(c)
}

// clusterJoin POST /api/cluster/join
func (s *Server) clusterJoin(c *gin.Context) {
	if !s.requireClusterMaster(c) {
		return
	}
	var body clusterJoinReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	if body.Node.ID == "" || body.Node.URL == "" {
		fail(c, 400, "bad_request", "node.id 与 node.url 必填")
		return
	}
	if body.Node.ID == s.Cfg.NodeID {
		fail(c, 400, "bad_request", "不能把自己注册成 worker")
		return
	}
	if err := s.St.UpsertWorker(store.WorkerInput{
		ID: body.Node.ID, Name: body.Node.Name, URL: body.Node.URL, Version: body.Node.Version,
		Region: body.Node.Region, Capabilities: body.Node.Capabilities,
		Artifacts: int64(len(body.Artifacts)), Nodes: body.Node.Nodes, Users: body.Node.Users,
	}); err != nil {
		fail(c, 500, "internal", "注册 worker 失败")
		return
	}
	if err := s.St.ReplaceAdverts(body.Node.ID, advertInputs(body.Artifacts)); err != nil {
		fail(c, 500, "internal", "同步目录失败")
		return
	}
	log.Printf("[cluster] worker 加入: %s (%s) 目录 %d 条", body.Node.Name, body.Node.URL, len(body.Artifacts))
	ok(c, 200, gin.H{"ok": true, "master": s.masterBlock(), "joined": body.Node.ID, "accepted": len(body.Artifacts)})
}

// clusterHeartbeat POST /api/cluster/heartbeat
func (s *Server) clusterHeartbeat(c *gin.Context) {
	if !s.requireClusterMaster(c) {
		return
	}
	var body clusterJoinReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, 400, "bad_request", "请求体格式错误")
		return
	}
	if body.Node.ID == "" {
		fail(c, 400, "bad_request", "node.id 必填")
		return
	}
	if err := s.St.UpsertWorker(store.WorkerInput{
		ID: body.Node.ID, Name: body.Node.Name, URL: body.Node.URL, Version: body.Node.Version,
		Region: body.Node.Region, Capabilities: body.Node.Capabilities,
		Artifacts: int64(len(body.Artifacts)), Nodes: body.Node.Nodes, Users: body.Node.Users,
	}); err != nil {
		fail(c, 500, "internal", "worker 心跳失败")
		return
	}
	if err := s.St.ReplaceAdverts(body.Node.ID, advertInputs(body.Artifacts)); err != nil {
		fail(c, 500, "internal", "同步目录失败")
		return
	}
	ok(c, 200, gin.H{"ok": true, "master": s.masterBlock(), "accepted": len(body.Artifacts), "time": timeNow()})
}

func advertInputs(in []advertReq) []store.AdvertInput {
	out := make([]store.AdvertInput, 0, len(in))
	for _, a := range in {
		out = append(out, store.AdvertInput{
			Ref: a.Ref, NamespaceSlug: a.NamespaceSlug, Slug: a.Slug, Kind: a.Kind, Name: a.Name,
			Version: a.Version, Summary: a.Summary, Tags: a.Tags, SHA256: a.SHA256,
			Size: a.Size, Downloads: a.Downloads, UpdatedAt: a.UpdatedAt,
		})
	}
	return out
}

// clusterView GET /api/cluster —— 集群总览（master 与 worker 都返回同一形状）。
func (s *Server) clusterView(c *gin.Context) {
	artifacts, nodes, users := s.Counts()
	self := s.selfNodeJSON(artifacts, nodes, users)

	workers, err := s.St.ListWorkers()
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	wlist := make([]gin.H, 0, len(workers))
	onlineWorkers := 0
	var workerArtifacts, workerNodes int64
	for i := range workers {
		w := workers[i]
		j := workerJSON(&w, s.Cfg.NodeTTL)
		if j["online"] == true {
			onlineWorkers++
		}
		workerArtifacts += w.Artifacts
		workerNodes += w.Nodes
		wlist = append(wlist, j)
	}

	out := gin.H{
		"role":    s.Cfg.Role,
		"self":    self,
		"workers": wlist,
		"totals": gin.H{
			"nodes": 1 + len(wlist), "workers": len(wlist), "workersOnline": onlineWorkers,
			"onlineNodes": 1 + onlineWorkers,
			"artifacts":   artifacts + workerArtifacts, "hostedNodes": nodes + workerNodes, "users": users,
		},
		"ttlSec":   int64(s.Cfg.NodeTTL.Seconds()),
		"everySec": int64(s.Cfg.HeartbeatEvery.Seconds()),
		"console":  s.Cfg.PublicURL + "/",
	}

	// worker 视角：回显自己认识的 master（没连上就是一次都没成功过）。
	if s.Cfg.Role == config.RoleWorker {
		s.hub.mu.Lock()
		master, last, lastErr := s.hub.master, s.hub.last, s.hub.err
		s.hub.mu.Unlock()
		block := gin.H{"url": s.Cfg.MasterURL, "online": false}
		if master != nil {
			for k, v := range *master {
				block[k] = v
			}
			block["online"] = lastErr == ""
		}
		if !last.IsZero() {
			out["lastHeartbeat"] = last
		}
		if lastErr != "" {
			out["lastError"] = lastErr
		}
		out["master"] = block
	}
	ok(c, 200, out)
}

// masterBlock master 侧向 worker 回报的身份 + 集群规模。
func (s *Server) masterBlock() gin.H {
	artifacts, nodes, users := s.Counts()
	workers, _ := s.St.ListWorkers()
	return gin.H{
		"id": s.Cfg.NodeID, "name": s.Cfg.NodeName, "url": s.Cfg.PublicURL,
		"role": config.RoleMaster, "version": Version, "region": s.Cfg.NodeRegion,
		"online": true, "lastSeen": time.Now(),
		"cluster": gin.H{
			"workers": len(workers), "artifacts": artifacts, "hostedNodes": nodes, "users": users,
		},
	}
}

// clusterDirectory GET /api/cluster/directory —— 聚合目录（master 本地 + 各 worker 上报）。
func (s *Server) clusterDirectory(c *gin.Context) {
	q, kind, tag := c.Query("q"), c.Query("kind"), c.Query("tag")

	res, err := s.St.ListArtifacts(store.ListOpts{
		Q: q, Kind: kind, Tag: tag, PublicOnly: true, Statuses: []string{"published"},
		Page: 1, Size: 100, OrderBy: c.Query("sort"),
	})
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	items := make([]gin.H, 0, len(res.Rows))
	seen := map[string]bool{}
	replicas, _ := s.St.ReplicaTargetsByRef()
	for i := range res.Rows {
		row := res.Rows[i]
		ref := "@" + row.NsSlug + "/" + row.Slug
		seen[ref] = true
		j := artifactJSON(&row)
		j["via"] = gin.H{"role": "self", "nodeId": s.Cfg.NodeID, "nodeName": s.Cfg.NodeName}
		// 本地条目：标出已分发到哪些 worker（副本），便于判断“就近可拉”。
		if rows := replicas[ref+"@"+row.Version]; len(rows) > 0 {
			list := make([]gin.H, 0, len(rows))
			for _, rt := range rows {
				list = append(list, gin.H{"nodeId": rt.WorkerID, "nodeName": rt.WorkerName, "size": rt.Size})
			}
			j["replicas"] = list
		}
		items = append(items, j)
	}

	adv, err := s.St.ListAdverts(q, kind, tag, 300)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	remote := 0
	for i := range adv {
		a := adv[i]
		ref := "@" + a.NamespaceSlug + "/" + a.Slug
		if seen[ref] {
			continue // master 本地有同一份，以本地为准
		}
		seen[ref] = true
		remote++
		items = append(items, gin.H{
			"id": a.ID, "kind": a.Kind, "name": a.Name, "slug": a.Slug, "version": a.Version,
			"summary": a.Summary, "tags": store.ParseList(a.Tags),
			"visibility": "public", "status": "published",
			"storage":   gin.H{"provider": "cluster", "url": "", "sha256": a.SHA256, "size": a.Size},
			"downloads": a.Downloads,
			"namespace": gin.H{"slug": a.NamespaceSlug, "name": a.NamespaceSlug},
			"ref":       a.Ref,
			"via":       gin.H{"role": "worker", "nodeId": a.WorkerID, "nodeName": a.WorkerName, "nodeUrl": a.WorkerURL},
			"updatedAt": a.UpdatedAt,
		})
	}
	ok(c, 200, gin.H{
		"items": items, "total": len(items), "local": len(res.Rows), "remote": remote,
		"role": s.Cfg.Role,
	})
}

// clusterRoute GET /api/nodes/route?ref=@ns/slug
//
// 「这个能力该找谁」：master 先看自己有没有，再看哪个 worker 有。
// 这是内网 Router（聚合入口 + 能力路由）在最小可用形态下的落点。
func (s *Server) clusterRoute(c *gin.Context) {
	ref := strings.TrimSpace(c.Query("ref"))
	if ref == "" {
		fail(c, 400, "bad_request", "需要 ref（@命名空间/slug 或 A-… id）")
		return
	}
	candidates := []gin.H{}

	if row, err := s.findByRef(ref); err == nil && row.Status == "published" && row.Visibility == "public" {
		candidates = append(candidates, gin.H{
			"role": "self", "nodeId": s.Cfg.NodeID, "nodeName": s.Cfg.NodeName, "nodeUrl": s.Cfg.PublicURL,
			"ref":    "@" + row.NsSlug + "/" + row.Slug + "@" + row.Version,
			"sha256": row.SHA256, "size": row.Size,
			"download": s.Cfg.PublicURL + "/api/registry/" + refOf(row) + "/bytes",
		})
	}
	adv, err := s.St.FindAdvertsByRef(ref)
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	for i := range adv {
		a := adv[i]
		candidates = append(candidates, gin.H{
			"role": "worker", "nodeId": a.WorkerID, "nodeName": a.WorkerName, "nodeUrl": a.WorkerURL,
			"ref": a.Ref, "sha256": a.SHA256, "size": a.Size,
			"download": strings.TrimRight(a.WorkerURL, "/") + "/api/registry/" + a.Ref + "/bytes",
			"online":   nodeOnline(a.SeenAt, s.Cfg.NodeTTL*4),
		})
	}
	resolved := len(candidates) > 0
	out := gin.H{
		"ref": ref, "resolved": resolved, "candidates": candidates,
		"count": len(candidates), "role": s.Cfg.Role,
	}
	if resolved {
		out["preferred"] = s.preferCandidate(candidates)
		// 客户端只要认这一个地址即可：master 会代理到真正的持有者。
		out["download"] = s.Cfg.PublicURL + "/api/registry/" + ref + "/bytes"
	}
	ok(c, 200, out)
}

// preferCandidate 优先本节点，其次心跳最新的 worker。
func (s *Server) preferCandidate(list []gin.H) gin.H {
	for _, c := range list {
		if c["role"] == "self" {
			return c
		}
	}
	return list[0]
}

// clusterWorkers GET /api/cluster/workers
func (s *Server) clusterWorkers(c *gin.Context) {
	workers, err := s.St.ListWorkers()
	if err != nil {
		fail(c, 500, "internal", "服务内部错误")
		return
	}
	list := make([]gin.H, 0, len(workers))
	for i := range workers {
		list = append(list, workerJSON(&workers[i], s.Cfg.NodeTTL))
	}
	ok(c, 200, gin.H{"workers": list, "total": len(list), "ttlSec": int64(s.Cfg.NodeTTL.Seconds())})
}
