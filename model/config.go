// Package model：NCC Config —— 团队的网络 / 基础设施 / Agent 配置托管。
//
// 为什么配置要作为一等资源，而不是「再发布一个 kind=config 的制品」：
//
//	制品 Artifact   可分发的能力包：字节在 blob 存储，sha256 校验，可 fan-out 到各
//	                worker、可被判成公开后匿名下载。它的形态是「文件」。
//	配置 Config     团队的权威数据：网络段、网关、模型端点、CI 变量…… 形态是
//	                「一份会被反复修改、需要版本与回滚、默认不公开」的文档。
//
// 两者的关键差别：
//   - **默认私有**：基础设施配置默认 `private`（制品的默认是 public）—— 配置里常带
//     内网地址、账号名、甚至凭据，不能靠「记得设成私有」来兜底。
//   - **版本即历史**：每次写入都追加一个 revision，可查看、可比、可回滚；
//     制品靠「换 version 再发一版」实现迭代，配置靠「就地改 + 留痕」。
//   - **不参与 fan-out**：配置是权威数据，只在被指向的那个节点上维护（master）；
//     需要跨节点读，就让 Agent 指向 master（见 README 的 "Where the authoritative copy lives"）。
//   - **敏感值静态加密**：`secret=true` 的配置落库前用本节点密钥 AES-256-GCM 加密，
//     默认读取只回校验和与大小（打码），要明文必须显式 `--reveal`。
package model

import "time"

/* ---------------- 配置类型目录（封闭枚举） ---------------- */

// ConfigKindMeta 配置类型：id → [中文, 英文, 中文说明, 英文说明]。
//
// 类型是匹配与分组的坐标系（「这个团队的网络配置在哪」），自由表达交给 tags。
var ConfigKindMeta = map[string][4]string{
	"network": {
		"网络", "Network",
		"网段 / VLAN / 路由 / DNS / VPN / 防火墙策略",
		"Subnets, VLANs, routes, DNS, VPN, firewall policy",
	},
	"gateway": {
		"网关与入口", "Gateway & ingress",
		"反向代理 / 域名与证书 / 对外入口",
		"Reverse proxy, domains and certificates, public ingress",
	},
	"infra": {
		"基础设施", "Infrastructure",
		"主机 / 存储 / 集群 / 虚拟化参数",
		"Hosts, storage, clusters, virtualization parameters",
	},
	"registry": {
		"制品源与镜像", "Registries & mirrors",
		"镜像源 / 制品源 / 代理与上游",
		"Image and artifact registries, proxies, upstreams",
	},
	"agent": {
		"Agent 与模型", "Agents & models",
		"模型端点 / 工具清单 / 提示与人格参数",
		"Model endpoints, tool lists, prompt and persona settings",
	},
	"ci": {
		"流水线与构建", "CI & build",
		"流水线参数 / 构建与发布变量",
		"Pipeline parameters, build and release variables",
	},
	"observability": {
		"监控与告警", "Observability",
		"采集 / 看板 / 告警路由",
		"Collection, dashboards, alert routing",
	},
	"security": {
		"安全与凭据", "Security & credentials",
		"凭据 / 证书 / 访问策略（建议 --secret）",
		"Credentials, certificates, access policy (use --secret)",
	},
	"app": {
		"应用参数", "Application",
		"业务应用的运行参数",
		"Runtime settings for business applications",
	},
	"other": {
		"其他", "Other",
		"不属于以上分类的配置",
		"Anything else",
	},
}

// ConfigKinds 配置类型（顺序即展示顺序）。
var ConfigKinds = []string{
	"network", "gateway", "infra", "registry", "agent", "ci", "observability", "security", "app", "other",
}

// ValidConfigKind 校验配置类型。
func ValidConfigKind(k string) bool {
	_, hit := ConfigKindMeta[k]
	return hit
}

// ConfigKindLabel 取类型的中英标签。
func ConfigKindLabel(k, lang string) string {
	meta, hit := ConfigKindMeta[k]
	if !hit {
		return k
	}
	if lang == "en" {
		return meta[1]
	}
	return meta[0]
}

/* ---------------- 内容格式 ---------------- */

// ConfigFormats 允许的内容格式（决定 CLI 写文件时的扩展名与高亮）。
var ConfigFormats = []string{"json", "yaml", "toml", "env", "ini", "text", "shell"}

// ValidConfigFormat 校验格式。
func ValidConfigFormat(f string) bool {
	for _, v := range ConfigFormats {
		if v == f {
			return true
		}
	}
	return false
}

// ConfigFormatExt 格式对应的文件扩展名（bundle 落盘用）。
func ConfigFormatExt(f string) string {
	switch f {
	case "env":
		return ".env"
	case "text":
		return ".txt"
	case "shell":
		return ".sh"
	default:
		return "." + f
	}
}

/* ---------------- 环境 / 可见性 / 状态 ---------------- */

// ConfigEnvs 允许的环境标记。`any`（默认）表示与环境无关；
// bundle 拉取时 `--env prod` 会同时命中 `prod` 与 `any`。
var ConfigEnvs = []string{"any", "dev", "staging", "prod"}

// ValidConfigEnv 校验环境。
func ValidConfigEnv(e string) bool {
	for _, v := range ConfigEnvs {
		if v == e {
			return true
		}
	}
	return false
}

// 可见性：**默认 private**（与制品相反，理由见包注释）。
const (
	ConfigPrivate = "private"
	ConfigPublic  = "public"
)

// 状态：archived 的配置不再出现在 bundle 里，但历史仍可查。
const (
	ConfigActive   = "active"
	ConfigArchived = "archived"
)

// ValidConfigStatus 校验状态。
func ValidConfigStatus(s string) bool {
	return s == ConfigActive || s == ConfigArchived
}

// ConfigMaxBytes 单条配置的内容上限（配置是「小文档」；大文件请走制品）。
const ConfigMaxBytes = 128 * 1024

/* ---------------- 配置条目 ---------------- */

// ConfigEntry 一条被托管的配置。
//
// 引用写作 `@命名空间/slug`（与制品同一套写法，Agent 不用学两套），
// 环境与类型写在元数据里，便于按「prod 的全部网络配置」成组拉取。
type ConfigEntry struct {
	ID          string `gorm:"primaryKey"`
	NamespaceID string `gorm:"not null;index;uniqueIndex:idx_cfg_ns_slug"`
	Slug        string `gorm:"not null;uniqueIndex:idx_cfg_ns_slug"`
	Name        string `gorm:"not null"`
	Kind        string `gorm:"not null;default:other;index"`
	Environment string `gorm:"not null;default:any;index"`
	Format      string `gorm:"not null;default:text"`
	Summary     string `gorm:"not null;default:''"`
	Tags        string `gorm:"not null;default:[]"`
	Visibility  string `gorm:"not null;default:private;index"`
	Status      string `gorm:"not null;default:active;index"`
	// Secret=true 的配置内容在库里是密文；默认读取只回校验和与大小。
	Secret   bool   `gorm:"not null;default:false"`
	Revision int64  `gorm:"not null;default:1"`
	Content  string `gorm:"not null;default:''"`
	Checksum string `gorm:"not null;default:''"`
	Size     int64  `gorm:"not null;default:0"`

	CreatedBy string    `gorm:"not null;index"`
	UpdatedBy string    `gorm:"not null;default:''"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

func (ConfigEntry) TableName() string { return "config_entries" }

// IsPublic 是否公开可读。
func (c *ConfigEntry) IsPublic() bool { return c.Visibility == ConfigPublic }

// ConfigRevision 一条版本历史。每次写入（含回滚）追加一行，永不改写历史。
type ConfigRevision struct {
	ID         string    `gorm:"primaryKey"`
	ConfigID   string    `gorm:"not null;index;uniqueIndex:idx_cfg_rev_uk"`
	Revision   int64     `gorm:"not null;uniqueIndex:idx_cfg_rev_uk"`
	Content    string    `gorm:"not null;default:''"`
	Checksum   string    `gorm:"not null;default:''"`
	Size       int64     `gorm:"not null;default:0"`
	Secret     bool      `gorm:"not null;default:false"`
	Note       string    `gorm:"not null;default:''"`
	AuthorID   string    `gorm:"not null;default:''"`
	AuthorName string    `gorm:"not null;default:''"`
	CreatedAt  time.Time `gorm:"autoCreateTime"`
}

func (ConfigRevision) TableName() string { return "config_revisions" }
