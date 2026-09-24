// Package secretbox 配置内容的静态加密（AES-256-GCM，只依赖标准库）。
//
// 为什么需要它：基础设施配置里经常夹着凭据（Wi-Fi PSK、模型 API key、DB 口令）。
// 「靠用户记得别写进去」不是工程手段，所以 `secret=true` 的配置在**落库前**就加密：
//
//	密钥 = HMAC-SHA256(节点密钥, "ncc-registry/config-content-v1")  → 32 字节
//	密文 = "enc:v1:" + base64(nonce‖ciphertext‖tag)   （每条随机 nonce）
//
// 节点密钥沿用 <data>/jwt-secret（首次启动生成并落盘、重启不变），因此：
//   - 换机器/丢数据目录 = 密文打不开（这是预期：密文属于那个节点）；
//   - 备份数据库时，不带 jwt-secret 的备份是安全的（拿到库也解不开 secret 配置）。
//
// Open 对**不带前缀**的内容原样返回：历史明文行、或某条配置把 secret 关掉之后，
// 仍然读得出来，不会因为一次切换就把数据读挂。
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Prefix 密文标记。改算法时递增版本号（v2…），并让 Open 同时认旧前缀。
const Prefix = "enc:v1:"

// Box 加解密器（拿节点密钥派生一次，进程内复用）。
type Box struct {
	aead cipher.AEAD
}

// New 用节点密钥构造；secret 为空则返回错误（调用方通常已保证非空，纯防御）。
func New(secret string) (*Box, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("secretbox: 节点密钥为空")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("ncc-registry/config-content-v1"))
	key := mac.Sum(nil) // 32 字节 = AES-256

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretbox: 初始化失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretbox: GCM 初始化失败: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Seal 加密明文，返回带前缀的密文。
func (b *Box) Seal(plain string) (string, error) {
	if b == nil {
		return "", errors.New("secretbox: 未初始化")
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secretbox: 生成 nonce 失败: %w", err)
	}
	ct := b.aead.Seal(nil, nonce, []byte(plain), nil)
	return Prefix + base64.StdEncoding.EncodeToString(append(nonce, ct...)), nil
}

// Open 解密；不带前缀视为明文原样返回。
func (b *Box) Open(stored string) (string, error) {
	if !strings.HasPrefix(stored, Prefix) {
		return stored, nil
	}
	if b == nil {
		return "", errors.New("secretbox: 未初始化")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, Prefix))
	if err != nil {
		return "", fmt.Errorf("secretbox: 密文解码失败: %w", err)
	}
	n := b.aead.NonceSize()
	if len(raw) < n+b.aead.Overhead() {
		return "", errors.New("secretbox: 密文长度异常")
	}
	plain, err := b.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", errors.New("secretbox: 解密失败（密钥不匹配或密文被改）")
	}
	return string(plain), nil
}

// Sealed 判断内容是否已是密文。
func Sealed(stored string) bool { return strings.HasPrefix(stored, Prefix) }
