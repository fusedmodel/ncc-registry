package store

import (
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/fusedmodel/ncc-registry/model"
)

// 制品分享链接：带 token 的临时下载地址（对方不用登录、不用装 CLI）。
//
// 与接入票据（AccessTicket）的差别：票据换的是「一个节点身份」，分享换的是
// 「一次/一段时间的读取权」。相同之处：token/secret 都只存 sha256、都只显示一次。

// NewShareToken 生成分享 token（32 位 hex，放进 URL 路径，足够长到不可猜）。
func NewShareToken() string { return RandHex(16) }

// ShareRow 分享 + 制品 + 命名空间 + 创建者（列表页一次 join 拿全）。
type ShareRow struct {
	model.ArtifactShare
	ArtifactSlug  string `gorm:"column:artifact_slug"`
	ArtifactName  string `gorm:"column:artifact_name"`
	ArtifactKind  string `gorm:"column:artifact_kind"`
	ArtifactSHA   string `gorm:"column:artifact_sha"`
	ArtifactSize  int64  `gorm:"column:artifact_size"`
	ArtifactState string `gorm:"column:artifact_status"`
	NsSlug        string `gorm:"column:ns_slug"`
	NsName        string `gorm:"column:ns_name"`
	CreatedByName string `gorm:"column:created_by_name"`
}

func (s *Store) shareQuery() *gorm.DB {
	// 显式列出 artifact_shares.*：join 之后 id/created_at 在几张表里都有，不写清楚会互相覆盖。
	return s.DB.Table("artifact_shares").
		Select(`artifact_shares.*,
			artifacts.slug AS artifact_slug, artifacts.name AS artifact_name,
			artifacts.kind AS artifact_kind, artifacts.sha256 AS artifact_sha,
			artifacts.size AS artifact_size, artifacts.status AS artifact_status,
			namespaces.slug AS ns_slug, namespaces.name AS ns_name,
			users.name AS created_by_name`).
		Joins("LEFT JOIN artifacts ON artifacts.id = artifact_shares.artifact_id").
		Joins("LEFT JOIN namespaces ON namespaces.id = artifact_shares.namespace_id").
		Joins("LEFT JOIN users ON users.id = artifact_shares.created_by")
}

// CreateShare 建一条分享链接。
func (s *Store) CreateShare(artifactID, nsID, createdBy, label string, maxUses int64, expiresAt *time.Time) (*model.ArtifactShare, string, error) {
	token := NewShareToken()
	hint := token
	if len(hint) > 6 {
		hint = hint[:6]
	}
	sh := &model.ArtifactShare{
		ID: NewID("SH"), ArtifactID: artifactID, NamespaceID: nsID,
		TokenHash: HashSecret(token), TokenHint: hint,
		Label: strings.TrimSpace(label), CreatedBy: createdBy,
		MaxUses: maxUses, ExpiresAt: expiresAt,
	}
	if err := s.DB.Create(sh).Error; err != nil {
		return nil, "", err
	}
	return sh, token, nil
}

// FindShareByToken token 是明文，库里存哈希 —— 查的时候现算。
func (s *Store) FindShareByToken(token string) (*model.ArtifactShare, error) {
	var sh model.ArtifactShare
	if err := s.DB.Where("token_hash = ?", HashSecret(strings.TrimSpace(token))).First(&sh).Error; err != nil {
		return nil, err
	}
	return &sh, nil
}

// ListShares 分享列表。createdBy 为空 = 全部（管理员视角）。
func (s *Store) ListShares(createdBy string, limit, offset int) ([]ShareRow, error) {
	query := s.shareQuery()
	if createdBy != "" {
		query = query.Where("artifact_shares.created_by = ?", createdBy)
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var rows []ShareRow
	err := query.Order("artifact_shares.created_at DESC").Offset(offset).Limit(limit).Scan(&rows).Error
	return rows, err
}

func (s *Store) CountShares(createdBy string) (int64, error) {
	query := s.DB.Model(&model.ArtifactShare{})
	if createdBy != "" {
		query = query.Where("created_by = ?", createdBy)
	}
	var n int64
	err := query.Count(&n).Error
	return n, err
}

// CountActiveShares 未撤销 / 未过期 / 次数未用尽的数量（管理台概览用）。
func (s *Store) CountActiveShares() (int64, error) {
	var n int64
	err := s.DB.Model(&model.ArtifactShare{}).
		Where("revoked_at IS NULL").
		Where("expires_at IS NULL OR expires_at > ?", time.Now()).
		Where("max_uses = 0 OR used_count < max_uses").
		Count(&n).Error
	return n, err
}

// FindShareByID 取一条分享（撤销前先确认归属）。
func (s *Store) FindShareByID(id string) (*model.ArtifactShare, error) {
	var sh model.ArtifactShare
	if err := s.DB.Where("id = ?", id).First(&sh).Error; err != nil {
		return nil, err
	}
	return &sh, nil
}

// RevokeShare 撤销。createdBy 非空时限定为「只能撤自己发的」；管理员传空串撤任意。
func (s *Store) RevokeShare(id, createdBy string) error {
	query := s.DB.Model(&model.ArtifactShare{}).Where("id = ?", id)
	if createdBy != "" {
		query = query.Where("created_by = ?", createdBy)
	}
	res := query.Update("revoked_at", time.Now())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// MarkShareUsed 记一次使用（用尽后自动失效，见 model.ArtifactShare.Usable）。
func (s *Store) MarkShareUsed(id string) error {
	now := time.Now()
	return s.DB.Model(&model.ArtifactShare{}).Where("id = ?", id).
		Updates(map[string]any{"used_count": gorm.Expr("used_count + 1"), "last_used_at": now}).Error
}
