package store

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/fusedmodel/ncc-registry/model"
)

// 节点治理面（admin）的数据访问：用户 / 节点 / 服务 / 审计 / admin key。
//
// 与「我的资产」那套的分界：这里**不带 ownerID 过滤** —— 管理员的视角本来就是全节点。
// 但每条写操作都必须由 HTTP 层先过 requireAdmin，别把治理函数暴露给普通路径的 caller。

/* ---------------- 用户 ---------------- */

// AdminUserRow 用户 + 他名下的规模（管理台一眼看清「谁在用」）。
type AdminUserRow struct {
	model.User
	Nodes     int64 `gorm:"column:nodes"`
	Artifacts int64 `gorm:"column:artifacts"`
}

func (s *Store) adminUserQuery() *gorm.DB {
	// 显式列出 users.*：join/子查询混用时不写清楚，列名会互相覆盖。
	return s.DB.Table("users").
		Select(`users.*,
			(SELECT COUNT(*) FROM hosted_nodes WHERE namespace_id IN (SELECT id FROM namespaces WHERE owner_id = users.id)) AS nodes,
			(SELECT COUNT(*) FROM artifacts WHERE namespace_id IN (SELECT id FROM namespaces WHERE owner_id = users.id)) AS artifacts`)
}

// ListUsers 用户列表（管理员视角，含被禁用的）。
func (s *Store) ListUsers(q string, limit, offset int) ([]AdminUserRow, error) {
	query := s.adminUserQuery()
	if q = strings.TrimSpace(q); q != "" {
		like := "%" + q + "%"
		query = query.Where("users.email LIKE ? OR users.name LIKE ? OR users.id LIKE ?", like, like, like)
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var rows []AdminUserRow
	err := query.Order("users.created_at DESC").Offset(offset).Limit(limit).Scan(&rows).Error
	return rows, err
}

// CountUsersFiltered 与 ListUsers 同口径的总数（分开写：Count 不能带 Select 子查询）。
func (s *Store) CountUsersFiltered(q string) (int64, error) {
	query := s.DB.Model(&model.User{})
	if q = strings.TrimSpace(q); q != "" {
		like := "%" + q + "%"
		query = query.Where("email LIKE ? OR name LIKE ? OR id LIKE ?", like, like, like)
	}
	var n int64
	err := query.Count(&n).Error
	return n, err
}

// SetUserDisabled 禁用 / 启用。禁用立即生效：authMiddleware 每次都用 JWT 里的 id
// 回查一次库，所以旧令牌不会继续通行。
func (s *Store) SetUserDisabled(id string, disabled bool, note string) error {
	up := map[string]any{"disabled": disabled}
	if disabled {
		up["disabled_at"] = time.Now()
	} else {
		up["disabled_at"] = nil
	}
	if note = strings.TrimSpace(note); note != "" {
		up["admin_note"] = note
	}
	return s.DB.Model(&model.User{}).Where("id = ?", id).Updates(up).Error
}

// CountAdmins 本节点管理员数量（用于「最后一个管理员不能被禁用」这类判断）。
func (s *Store) CountAdmins() (int64, error) {
	var n int64
	err := s.DB.Model(&model.User{}).Where("is_admin = ? AND disabled = ?", true, false).Count(&n).Error
	return n, err
}

/* ---------------- 节点（管理面看全部） ---------------- */

// ListAllNodes 全节点列表：管理台没有「我的 / 别人的」之分，私有与离线也照列。
func (s *Store) ListAllNodes(kind, region, q string, limit, offset int) ([]NodeRow, error) {
	// ownerID 传空串：管理面不需要「我连没连它」这一列（links 会被 join 成空）。
	query := s.nodeQuery("").Where("1 = 1")
	if kind != "" {
		query = query.Where("hosted_nodes.kind = ?", kind)
	}
	if region != "" {
		query = query.Where("hosted_nodes.region = ?", region)
	}
	if q = strings.TrimSpace(q); q != "" {
		like := "%" + q + "%"
		query = query.Where("hosted_nodes.name LIKE ? OR hosted_nodes.slug LIKE ? OR users.email LIKE ?", like, like, like)
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var rows []NodeRow
	err := query.Order("hosted_nodes.last_seen DESC").Offset(offset).Limit(limit).Scan(&rows).Error
	return rows, err
}

// CountAllNodes 与 ListAllNodes 同口径的总数。
func (s *Store) CountAllNodes(kind, region, q string) (int64, error) {
	query := s.DB.Table("hosted_nodes").
		Joins("LEFT JOIN namespaces ON namespaces.id = hosted_nodes.namespace_id").
		Joins("LEFT JOIN users ON users.id = namespaces.owner_id")
	if kind != "" {
		query = query.Where("hosted_nodes.kind = ?", kind)
	}
	if region != "" {
		query = query.Where("hosted_nodes.region = ?", region)
	}
	if q = strings.TrimSpace(q); q != "" {
		like := "%" + q + "%"
		query = query.Where("hosted_nodes.name LIKE ? OR hosted_nodes.slug LIKE ? OR users.email LIKE ?", like, like, like)
	}
	var n int64
	err := query.Count(&n).Error
	return n, err
}

// NodeKindCounts 各类型节点数（service / agent / assigned）。
func (s *Store) NodeKindCounts() (map[string]int64, error) {
	type row struct {
		Kind string
		N    int64
	}
	var rows []row
	if err := s.DB.Model(&model.HostedNode{}).Select("kind, COUNT(*) AS n").Group("kind").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, r := range rows {
		out[r.Kind] = r.N
	}
	return out, nil
}

// DeleteHostedNodeAsAdmin 摘除一个节点（不论归属），并清掉指向它的连接记录 ——
// 否则别人的连接表里会留下一条指向空气的条目。
func (s *Store) DeleteHostedNodeAsAdmin(id string) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", id).Delete(&model.HostedNode{}).Error; err != nil {
			return err
		}
		return tx.Where("node_id = ?", id).Delete(&model.NodeLink{}).Error
	})
}

/* ---------------- 服务（两类来源） ---------------- */

// ListServiceArtifacts 制品侧的服务：kind=api 的条目。
func (s *Store) ListServiceArtifacts(kind, q string, limit, offset int) ([]ArtifactRow, error) {
	kinds := model.AdminServiceArtifactKinds
	if kind != "" {
		kinds = []string{kind}
	}
	query := s.artifactQuery().Where("artifacts.kind IN ?", kinds)
	if q = strings.TrimSpace(q); q != "" {
		like := "%" + q + "%"
		query = query.Where("artifacts.name LIKE ? OR artifacts.slug LIKE ? OR artifacts.summary LIKE ?", like, like, like)
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var rows []ArtifactRow
	err := query.Order("artifacts.updated_at DESC").Offset(offset).Limit(limit).Scan(&rows).Error
	return rows, err
}

// CountServiceArtifacts 与 ListServiceArtifacts 同口径的总数。
func (s *Store) CountServiceArtifacts(kind, q string) (int64, error) {
	kinds := model.AdminServiceArtifactKinds
	if kind != "" {
		kinds = []string{kind}
	}
	query := s.DB.Table("artifacts").
		Joins("LEFT JOIN namespaces ON namespaces.id = artifacts.namespace_id").
		Where("artifacts.kind IN ?", kinds)
	if q = strings.TrimSpace(q); q != "" {
		like := "%" + q + "%"
		query = query.Where("artifacts.name LIKE ? OR artifacts.slug LIKE ? OR artifacts.summary LIKE ?", like, like, like)
	}
	var n int64
	err := query.Count(&n).Error
	return n, err
}

// ArchiveArtifact 下架（归档）而不删字节：管理员处理「有问题的服务」时，
// 先让它从目录里消失，字节是否清理交给条目所属者决定。
func (s *Store) ArchiveArtifact(id string) error {
	return s.DB.Model(&model.Artifact{}).Where("id = ?", id).Update("status", "archived").Error
}

/* ---------------- 审计 ---------------- */

func (s *Store) AppendAudit(l *model.AuditLog) error {
	if l.ID == "" {
		l.ID = NewID("L")
	}
	return s.DB.Create(l).Error
}

func (s *Store) ListAudit(action string, limit, offset int) ([]model.AuditLog, error) {
	query := s.DB.Model(&model.AuditLog{})
	if action = strings.TrimSpace(action); action != "" {
		query = query.Where("action = ?", action)
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var rows []model.AuditLog
	err := query.Order("created_at DESC").Offset(offset).Limit(limit).Find(&rows).Error
	return rows, err
}

func (s *Store) CountAudit(action string) (int64, error) {
	query := s.DB.Model(&model.AuditLog{})
	if action = strings.TrimSpace(action); action != "" {
		query = query.Where("action = ?", action)
	}
	var n int64
	err := query.Count(&n).Error
	return n, err
}

/* ---------------- admin key / secret ---------------- */

// NewAdminKey 生成短 admin key（可念、可抄）。
func NewAdminKey() string { return "AK-" + strings.ToUpper(RandHex(3)) }

// NewAdminSecret 生成 admin secret（只显示一次）。
func NewAdminSecret() string { return RandHex(20) }

// CreateAdminKey 签发一份机器管理凭据（返回明文 secret，仅此一次）。
func (s *Store) CreateAdminKey(label, createdBy string) (*model.AdminKey, string, error) {
	key, secret := NewAdminKey(), NewAdminSecret()
	k := &model.AdminKey{
		ID: NewID("AKX"), Label: strings.TrimSpace(label),
		Key: key, SecretHash: HashSecret(secret), CreatedBy: createdBy,
	}
	if err := s.DB.Create(k).Error; err != nil {
		return nil, "", err
	}
	return k, secret, nil
}

// FindAdminKey 按 key 找凭据（不存在返回 gorm.ErrRecordNotFound）。
func (s *Store) FindAdminKey(key string) (*model.AdminKey, error) {
	var k model.AdminKey
	if err := s.DB.Where("key = ?", strings.TrimSpace(key)).First(&k).Error; err != nil {
		return nil, err
	}
	return &k, nil
}

// ListAdminKeys 全部凭据（含已撤销，便于说明「为什么那份 secret 不能用了」）。
func (s *Store) ListAdminKeys() ([]model.AdminKey, error) {
	var rows []model.AdminKey
	err := s.DB.Order("created_at DESC").Find(&rows).Error
	return rows, err
}

// HasActiveAdminKey 本节点是否已有可用的机器管理凭据。
func (s *Store) HasActiveAdminKey() (bool, error) {
	var n int64
	err := s.DB.Model(&model.AdminKey{}).Where("revoked_at IS NULL").Count(&n).Error
	return n > 0, err
}

func (s *Store) TouchAdminKey(id string) error {
	now := time.Now()
	return s.DB.Model(&model.AdminKey{}).Where("id = ?", id).Update("last_used_at", now).Error
}

// RevokeAdminKeys 撤销除 keepID 之外的全部机器凭据（轮换用；keepID 为空即全撤）。
func (s *Store) RevokeAdminKeys(keepID string) (int64, error) {
	now := time.Now()
	query := s.DB.Model(&model.AdminKey{}).Where("revoked_at IS NULL")
	if keepID != "" {
		query = query.Where("id <> ?", keepID)
	}
	res := query.Update("revoked_at", now)
	return res.RowsAffected, res.Error
}

// AdminKeyHint 给控制台/CLI 展示用的短描述。
func AdminKeyHint(k *model.AdminKey) string {
	if k == nil {
		return ""
	}
	return fmt.Sprintf("%s (%s)", k.Key, k.Label)
}
