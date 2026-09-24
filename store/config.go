package store

import (
	"encoding/json"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/fusedmodel/ncc-registry/model"
)

/* ---------------- NCC Config：配置托管的数据访问 ----------------
   配置与制品共用「引用 = @命名空间/slug」的写法，但读写路径不同：
   制品走字节存储（blob / BYO 直链），配置就只有一份内容列 + 版本历史。
*/

// ConfigRow 配置 + 命名空间/归属者摘要（列表一次 join 出，避免 N+1）。
type ConfigRow struct {
	model.ConfigEntry
	NsSlug    string `gorm:"column:ns_slug"`
	NsName    string `gorm:"column:ns_name"`
	OwnerID   string `gorm:"column:owner_id"`
	OwnerName string `gorm:"column:owner_name"`
}

// Ref 规范引用 @命名空间/slug。
func (r *ConfigRow) Ref() string { return "@" + r.NsSlug + "/" + r.Slug }

// ConfigInput 写入一条配置（Content 由上层决定是明文还是密文）。
type ConfigInput struct {
	NamespaceID string
	Slug        string
	Name        string
	Kind        string
	Environment string
	Format      string
	Summary     string
	Tags        []string
	Visibility  string
	Status      string
	Secret      bool
	Content     string
	Checksum    string
	Size        int64
	Note        string
	AuthorID    string
	AuthorName  string
}

// ConfigListOpts 配置检索条件。
type ConfigListOpts struct {
	NamespaceIDs []string // 限定这些命名空间（mine 用）
	// Visible=true 时按「我能读的」过滤：
	//   (公开 + active) ∪ 我的命名空间 ∪ 把 config 授权给我的人所在命名空间
	Visible       bool
	GrantedOwners []string
	NsSlug        string
	Kind          string
	Env           string // 命中该环境或 any（bundle 语义）
	Tag           string
	Q             string
	SecretsOnly   bool
	NoSecrets     bool
	Statuses      []string
	PublicOnly    bool
	Page          int
	Size          int
	Limit         int
}

// configBase 配置检索的基查询（只带表与 join，**不带 Select**）。
//
// 为什么不在这里 Select：GORM 的 Count() 会拿 Selects 去拼 count(...)，
// 一旦只有一项就会生成 `count(c.*)` → SQLite 直接报 `no such column: c.*`。
// 于是约定：Count 走 configBase，取行走 configQuery（带列）。
func (s *Store) configBase() *gorm.DB {
	return s.DB.Table("config_entries c").
		Joins("JOIN namespaces ns ON ns.id = c.namespace_id")
}

func (s *Store) configQuery() *gorm.DB {
	return s.configBase().
		Select(`c.*, ns.slug AS ns_slug, ns.name AS ns_name,
			ns.owner_id AS owner_id, u.name AS owner_name`).
		Joins("LEFT JOIN users u ON u.id = ns.owner_id")
}

func (o ConfigListOpts) apply(q *gorm.DB) *gorm.DB {
	if o.Visible {
		// 可见性是一条 OR 条件（公开 / 我的 / 被授权者的），空切片不能拼进 IN，
		// 所以按有没有值分别构造。
		conds := []string{"(c.visibility = ? AND c.status = ?)"}
		args := []any{model.ConfigPublic, model.ConfigActive}
		if len(o.NamespaceIDs) > 0 {
			conds = append(conds, "c.namespace_id IN ?")
			args = append(args, o.NamespaceIDs)
		}
		if len(o.GrantedOwners) > 0 {
			conds = append(conds, "ns.owner_id IN ?")
			args = append(args, o.GrantedOwners)
		}
		q = q.Where("("+strings.Join(conds, " OR ")+")", args...)
	}
	if len(o.NamespaceIDs) > 0 && !o.Visible {
		q = q.Where("c.namespace_id IN ?", o.NamespaceIDs)
	}
	if o.NsSlug != "" {
		q = q.Where("ns.slug = ?", o.NsSlug)
	}
	if o.Kind != "" {
		q = q.Where("c.kind = ?", o.Kind)
	}
	if o.Env != "" {
		// 「any = 与环境无关」对任何环境查询都算命中，否则 prod 的 bundle 会漏掉通用配置。
		q = q.Where("(c.environment = ? OR c.environment = 'any')", o.Env)
	}
	if o.Tag != "" {
		q = q.Where("c.tags LIKE ?", `%"`+o.Tag+`"%`)
	}
	if o.Q != "" {
		like := "%" + o.Q + "%"
		q = q.Where("(c.name LIKE ? OR c.slug LIKE ? OR c.summary LIKE ? OR c.tags LIKE ?)", like, like, like, like)
	}
	if o.SecretsOnly {
		q = q.Where("c.secret = ?", true)
	}
	if o.NoSecrets {
		q = q.Where("c.secret = ?", false)
	}
	if len(o.Statuses) > 0 {
		q = q.Where("c.status IN ?", o.Statuses)
	}
	if o.PublicOnly {
		q = q.Where("c.visibility = ? AND c.status = ?", model.ConfigPublic, model.ConfigActive)
	}
	return q
}

// ListConfigs 配置检索（目录 / bundle / 我的配置共用），返回行与总数。
func (s *Store) ListConfigs(o ConfigListOpts) ([]ConfigRow, int64, error) {
	var total int64
	if err := o.apply(s.configBase()).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	limit := o.Limit
	if limit <= 0 {
		limit = o.Size
		if limit <= 0 {
			limit = 20
		}
		if limit > 200 {
			limit = 200
		}
	}
	page := o.Page
	if page < 1 {
		page = 1
	}
	var rows []ConfigRow
	err := o.apply(s.configQuery()).
		Order("c.updated_at DESC").
		Offset((page - 1) * limit).Limit(limit).
		Scan(&rows).Error
	return rows, total, err
}

func (s *Store) FindConfigByID(id string) (*ConfigRow, error) {
	var rows []ConfigRow
	if err := s.configQuery().Where("c.id = ?", id).Limit(1).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &rows[0], nil
}

// FindConfigByNsSlug 按「命名空间 + slug」取（外部引用的写法：@team/network）。
func (s *Store) FindConfigByNsSlug(nsSlug, slug string) (*ConfigRow, error) {
	var rows []ConfigRow
	if err := s.configQuery().
		Where("ns.slug = ? AND c.slug = ?", nsSlug, slug).
		Limit(1).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &rows[0], nil
}

// ConfigSlugExists 同一命名空间下 slug 是否已占用。
func (s *Store) ConfigSlugExists(nsID, slug string) (bool, error) {
	var c int64
	err := s.DB.Model(&model.ConfigEntry{}).
		Where("namespace_id = ? AND slug = ?", nsID, slug).Count(&c).Error
	return c > 0, err
}

func (s *Store) CountConfigs() (int64, error) {
	var c int64
	err := s.DB.Model(&model.ConfigEntry{}).Count(&c).Error
	return c, err
}

// CountConfigsInNamespace 命名空间下的配置数（配额检查用）。
func (s *Store) CountConfigsInNamespace(nsID string) (int64, error) {
	var c int64
	err := s.DB.Model(&model.ConfigEntry{}).Where("namespace_id = ?", nsID).Count(&c).Error
	return c, err
}

// CreateConfig 建一条配置，并写入第 1 个版本。
func (s *Store) CreateConfig(in ConfigInput) (*model.ConfigEntry, error) {
	tags, _ := json.Marshal(in.Tags)
	if len(in.Tags) == 0 {
		tags = []byte("[]")
	}
	row := &model.ConfigEntry{
		ID: NewID("C"), NamespaceID: in.NamespaceID, Slug: in.Slug, Name: in.Name,
		Kind: in.Kind, Environment: in.Environment, Format: in.Format,
		Summary: in.Summary, Tags: string(tags),
		Visibility: in.Visibility, Status: in.Status, Secret: in.Secret,
		Revision: 1, Content: in.Content, Checksum: in.Checksum, Size: in.Size,
		CreatedBy: in.AuthorID, UpdatedBy: in.AuthorID,
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(row).Error; err != nil {
			return err
		}
		rev := &model.ConfigRevision{
			ID: NewID("CR"), ConfigID: row.ID, Revision: 1,
			Content: in.Content, Checksum: in.Checksum, Size: in.Size, Secret: in.Secret,
			Note: firstNote(in.Note), AuthorID: in.AuthorID, AuthorName: in.AuthorName,
		}
		return tx.Create(rev).Error
	})
	if err != nil {
		return nil, err
	}
	return row, nil
}

// UpdateConfig 写入新内容：版本号 +1 并追加历史（历史永不改写）。
func (s *Store) UpdateConfig(id string, in ConfigInput) (*model.ConfigEntry, error) {
	tags, _ := json.Marshal(in.Tags)
	if len(in.Tags) == 0 {
		tags = []byte("[]")
	}
	var out *model.ConfigEntry
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var cur model.ConfigEntry
		if err := tx.First(&cur, "id = ?", id).Error; err != nil {
			return err
		}
		next := cur.Revision + 1
		fields := map[string]any{
			"name": in.Name, "kind": in.Kind, "environment": in.Environment,
			"format": in.Format, "summary": in.Summary, "tags": string(tags),
			"visibility": in.Visibility, "status": in.Status,
			"secret": in.Secret, "revision": next,
			"content": in.Content, "checksum": in.Checksum, "size": in.Size,
			"updated_by": in.AuthorID, "updated_at": time.Now(),
		}
		if err := tx.Model(&model.ConfigEntry{}).Where("id = ?", id).Updates(fields).Error; err != nil {
			return err
		}
		rev := &model.ConfigRevision{
			ID: NewID("CR"), ConfigID: id, Revision: next,
			Content: in.Content, Checksum: in.Checksum, Size: in.Size, Secret: in.Secret,
			Note: firstNote(in.Note), AuthorID: in.AuthorID, AuthorName: in.AuthorName,
		}
		if err := tx.Create(rev).Error; err != nil {
			return err
		}
		var fresh model.ConfigEntry
		if err := tx.First(&fresh, "id = ?", id).Error; err != nil {
			return err
		}
		out = &fresh
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PatchConfig 只改元数据（改名 / 改标签 / 归档 / 切换可见性），不动内容也不加版本 ——
// 把「配置内容变了」与「只是改了备注」区分开，版本历史才有意义。
func (s *Store) PatchConfig(id string, fields map[string]any) error {
	fields["updated_at"] = time.Now()
	return s.DB.Model(&model.ConfigEntry{}).Where("id = ?", id).Updates(fields).Error
}

func (s *Store) DeleteConfig(id string) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("config_id = ?", id).Delete(&model.ConfigRevision{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).Delete(&model.ConfigEntry{}).Error
	})
}

func (s *Store) ListConfigRevisions(configID string) ([]model.ConfigRevision, error) {
	var out []model.ConfigRevision
	err := s.DB.Where("config_id = ?", configID).
		Order("revision DESC").Limit(200).Find(&out).Error
	return out, err
}

func (s *Store) FindConfigRevision(configID string, revision int64) (*model.ConfigRevision, error) {
	var r model.ConfigRevision
	if err := s.DB.Where("config_id = ? AND revision = ?", configID, revision).First(&r).Error; err != nil {
		return nil, err
	}
	return &r, nil
}

// ConfigKindCounts 各类配置的数量（**只统计公开且 active 的**）——
// 这份计数会被匿名控制台与公开的 /api/configs/kinds 用到，「有 1 条安全类配置」
// 这种信息不该从匿名接口漏出去。
func (s *Store) ConfigKindCounts() (map[string]int64, error) {
	type row struct {
		Kind string `gorm:"column:kind"`
		C    int64  `gorm:"column:c"`
	}
	var rows []row
	if err := s.DB.Model(&model.ConfigEntry{}).
		Select("kind, COUNT(*) AS c").
		Where("visibility = ? AND status = ?", model.ConfigPublic, model.ConfigActive).
		Group("kind").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, r := range rows {
		out[r.Kind] = r.C
	}
	return out, nil
}

// ConfigEnvCounts 各环境的配置数量（同样只算公开且 active 的）。
func (s *Store) ConfigEnvCounts() (map[string]int64, error) {
	type row struct {
		Env string `gorm:"column:environment"`
		C   int64  `gorm:"column:c"`
	}
	var rows []row
	if err := s.DB.Model(&model.ConfigEntry{}).
		Select("environment, COUNT(*) AS c").
		Where("visibility = ? AND status = ?", model.ConfigPublic, model.ConfigActive).
		Group("environment").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, r := range rows {
		out[r.Env] = r.C
	}
	return out, nil
}

// CountPublicConfigs 公开配置数（控制台匿名视图用）。
func (s *Store) CountPublicConfigs() (int64, error) {
	var c int64
	err := s.DB.Model(&model.ConfigEntry{}).
		Where("visibility = ? AND status = ?", model.ConfigPublic, model.ConfigActive).Count(&c).Error
	return c, err
}

func firstNote(note string) string {
	if note == "" {
		return "（未写变更说明）"
	}
	return note
}
