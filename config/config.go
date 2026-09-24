// Package config 读取 ncc-registry（内网托管节点）的配置。
//
// 环境变量前缀统一用 NCCR_（NCC Registry node），与平台的 NCC_ 前缀区分开：
// 两者可以同时跑在同一台机器上而互不干扰。所有配置都有可用默认值 ——
// 裸跑 `ncc-registry` 就是一个可用的单节点内网 Registry。
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 节点角色。
const (
	RoleMaster = "master" // 权威节点：用户/制品/节点目录的唯一权威 + 集群聚合视图
	RoleWorker = "worker" // 边缘节点：自己也托管制品与节点，同时向 master 注册 + 心跳
)

// ValidRole 校验角色取值。
func ValidRole(r string) bool { return r == RoleMaster || r == RoleWorker }

// Config 服务配置。
type Config struct {
	Role      string // master（默认）| worker
	Port      int
	Addr      string
	DataDir   string
	BlobDir   string // 制品字节（上传落盘 / 下载读取）的本地目录
	DBPath    string // SQLite 库文件（可与 DataDir 分开，比如库存本地 SSD、字节放 NAS）
	PublicURL string // 别人怎么访问本节点（集群路由与下载 URL 都用它）
	Console   bool   // 是否托管内置 Web 控制台

	NodeID     string // 本节点 id（NCCR_NODE_ID，缺省持久化到 <data>/node-id）
	NodeName   string // 本节点名（NCCR_NODE_NAME，缺省主机名）
	NodeRegion string // 本节点所在区域（NCCR_NODE_REGION，如 上海-内网/机房A）
	NodeRand   string // 生成的短标识，便于同名多机区分

	JWTSecret string
	JWTTTL    time.Duration

	// AccessTTL 接入票据兑换出的节点令牌有效期（默认 30 天；票据带过期时间时取更短的那个）。
	AccessTTL time.Duration

	// 集群：worker 向 master 注册 + 心跳；master 校验 join token。
	MasterURL      string
	ClusterToken   string
	HeartbeatEvery time.Duration
	NodeTTL        time.Duration

	// 注册门禁：留空 = 内网开放注册（默认）；设了值 = 必须带邀请码。
	InviteCode string

	// P2P：跨局域网直连的**判断与被打洞**（不搬运业务字节；见平台 prd/ncc-p2p-data.md）。
	// STUN 可以多台（判 NAT 映射行为要靠「同一本地端口对不同目标是否一致」）；
	// TURN 必须是客户自托管的（NCC 不提供默认数据面 relay）。
	P2PSTUN  []string
	P2PTURN  []string
	P2PServe bool // 开一个 UDP 入口应答打洞请求（等别人打进来）

	CORSOrigins string
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if n, err := strconv.Atoi(v); err == nil { // 纯数字 = 秒
			return time.Duration(n) * time.Second
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

// envList 逗号分隔列表（去空、去空白）；未设置时返回 nil。
func envList(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Load 读取配置。会确保各目录存在，并落盘 node-id / jwt-secret，
// 这样节点重启后身份与登录态都还在。
//
// 目录全都能单独指定（内网部署常见诉求：字节放 NAS/独立盘，库存本地 SSD）：
//
//	NCCR_DATA_DIR  数据根（默认 ./data）—— 身份/密钥/库/字节的默认落脚点
//	NCCR_DB_PATH   SQLite 库文件（默认 <data>/ncc-registry.db）
//	NCCR_BLOB_DIR  制品字节目录（默认 <data>/blobs）—— 上传写这里，下载从这里读
//
// 相对路径一律按数据根解析（不是按当前工作目录），这样换个目录启动也不会忽地换地方。
func Load() (*Config, error) {
	role := strings.ToLower(envOr("NCCR_ROLE", RoleMaster))
	if !ValidRole(role) {
		return nil, fmt.Errorf("NCCR_ROLE 必须是 master 或 worker，收到 %q", role)
	}
	port := envInt("NCCR_PORT", 8282)
	dataDir, err := resolveDir("", envOr("NCCR_DATA_DIR", "./data"))
	if err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	blobDir, err := resolveDir(dataDir, envOr("NCCR_BLOB_DIR", "blobs"))
	if err != nil {
		return nil, fmt.Errorf("创建制品字节目录失败: %w", err)
	}
	dbPath, err := resolvePath(dataDir, envOr("NCCR_DB_PATH", "ncc-registry.db"))
	if err != nil {
		return nil, fmt.Errorf("解析库文件路径失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("创建库文件目录失败: %w", err)
	}

	name := envOr("NCCR_NODE_NAME", "")
	if name == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			name = h
		} else {
			name = fmt.Sprintf("ncc-node-%d", port)
		}
	}

	c := &Config{
		Role:      role,
		Port:      port,
		Addr:      fmt.Sprintf(":%d", port),
		DataDir:   dataDir,
		BlobDir:   blobDir,
		DBPath:    dbPath,
		PublicURL: strings.TrimRight(envOr("NCCR_PUBLIC_URL", fmt.Sprintf("http://localhost:%d", port)), "/"),
		Console:   envBool("NCCR_CONSOLE", true),

		NodeID:     strings.TrimSpace(os.Getenv("NCCR_NODE_ID")),
		NodeName:   name,
		NodeRegion: envOr("NCCR_NODE_REGION", ""),

		JWTSecret: envOr("NCCR_JWT_SECRET", ""),
		JWTTTL:    envDur("NCCR_JWT_TTL", 168*time.Hour),
		AccessTTL: envDur("NCCR_ACCESS_TTL", 720*time.Hour),

		MasterURL:      strings.TrimRight(envOr("NCCR_MASTER_URL", ""), "/"),
		ClusterToken:   os.Getenv("NCCR_CLUSTER_TOKEN"),
		HeartbeatEvery: envDur("NCCR_HEARTBEAT", 15*time.Second),
		NodeTTL:        envDur("NCCR_NODE_TTL", 60*time.Second),

		InviteCode:  strings.TrimSpace(os.Getenv("NCCR_INVITE_CODE")),
		CORSOrigins: os.Getenv("NCCR_CORS_ORIGINS"),

		P2PSTUN:  envList("NCCR_P2P_STUN"),
		P2PTURN:  envList("NCCR_P2P_TURN"),
		P2PServe: envBool("NCCR_P2P_SERVE", false),
	}

	// 身份与密钥：缺省落盘，保证重启后不变。
	c.NodeID = persistentSecret(c.NodeID, filepath.Join(dataDir, "node-id"), "ND", 12)
	c.NodeRand = short(c.NodeID)
	c.JWTSecret = persistentSecret(c.JWTSecret, filepath.Join(dataDir, "jwt-secret"), "", 32)

	if c.Role == RoleWorker && c.MasterURL == "" {
		return nil, fmt.Errorf("worker 节点必须配置 NCCR_MASTER_URL（master 地址，如 http://10.0.0.1:8282）")
	}
	return c, nil
}

// InviteRequired 是否需要邀请码。
func (c *Config) InviteRequired() bool { return c.InviteCode != "" }

// InviteAllows 邀请码是否匹配（未启用门禁时一律放行）。
func (c *Config) InviteAllows(code string) bool {
	if !c.InviteRequired() {
		return true
	}
	for _, want := range strings.Split(c.InviteCode, ",") {
		if strings.TrimSpace(want) == strings.TrimSpace(code) {
			return true
		}
	}
	return false
}

// resolvePath 把可能是相对的路径按 base 解析成绝对路径（base 为空则按当前工作目录）。
// 解析后统一转成绝对路径，启动日志里打的就是真正生效的路径。
func resolvePath(base, p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("路径不能为空")
	}
	if !filepath.IsAbs(p) && base != "" {
		p = filepath.Join(base, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// resolveDir 同 resolvePath，但顺带把目录建出来（数据根、字节目录都要能直接用）。
func resolveDir(base, p string) (string, error) {
	dir, err := resolvePath(base, p)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// persistentSecret 沿用传入值；为空则读文件；文件也没有就生成并写入。
func persistentSecret(cur, path, prefix string, n int) string {
	if cur != "" {
		return cur
	}
	if b, err := os.ReadFile(path); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v
		}
	}
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	v := hex.EncodeToString(buf)
	if prefix != "" {
		v = prefix + "-" + v
	}
	_ = os.WriteFile(path, []byte(v), 0o600)
	return v
}

func short(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[len(id)-8:]
}
