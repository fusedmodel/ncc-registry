package model

import "time"

// ArtifactShare 制品分享链接：带 token 的**临时下载地址**，对方不用登录、不用装 CLI。
//
//	token   32 位随机串，库里只存 sha256（与接入票据的 secret 同一规矩）
//	链接    <publicURL>/s/<token>      落地页（给人看，不计数）
//	        <publicURL>/s/<token>/raw  直接下发字节（给 curl / Agent，计数）
//
// 分享是**临时放行**，不是授权：撤销 / 过期 / 用尽即失效，且不改变制品本身的可见性
// （撤销分享不会把公开制品变私有，反过来也一样）。所以它进不了 Grant 那张表。
type ArtifactShare struct {
	ID          string     `gorm:"primaryKey"`
	ArtifactID  string     `gorm:"not null;index"`
	NamespaceID string     `gorm:"not null;index"`
	TokenHash   string     `gorm:"not null;uniqueIndex"`
	TokenHint   string     `gorm:"not null;default:''"` // token 前 6 位，便于在列表里认人
	Label       string     `gorm:"not null;default:''"`
	CreatedBy   string     `gorm:"not null;index"`
	MaxUses     int64      `gorm:"not null;default:0"` // 0 = 不限次
	UsedCount   int64      `gorm:"not null;default:0"`
	ExpiresAt   *time.Time `gorm:"default:null"`
	RevokedAt   *time.Time `gorm:"default:null"`
	LastUsedAt  *time.Time `gorm:"default:null"`
	CreatedAt   time.Time  `gorm:"autoCreateTime"`
	UpdatedAt   time.Time  `gorm:"autoUpdateTime"`
}

func (ArtifactShare) TableName() string { return "artifact_shares" }

// Usable 现在还能用吗（撤销 / 过期 / 用尽是三个独立条件，缺一即失效）。
func (sh *ArtifactShare) Usable(now time.Time) bool {
	if sh.RevokedAt != nil {
		return false
	}
	if sh.ExpiresAt != nil && now.After(*sh.ExpiresAt) {
		return false
	}
	if sh.MaxUses > 0 && sh.UsedCount >= sh.MaxUses {
		return false
	}
	return true
}

// RemainingUses 剩余次数：0 = 不限次（与 MaxUses 的 0 同义，便于展示）。
func (sh *ArtifactShare) RemainingUses() int64 {
	if sh.MaxUses <= 0 {
		return 0
	}
	if left := sh.MaxUses - sh.UsedCount; left > 0 {
		return left
	}
	return 0
}
