package httpapi

import "testing"

// 与平台侧同口径的两条硬规则（任一侧放宽都会让"签名错配"偷偷进来）：
//  1. 清单自述的产物摘要必须等于上传字节的摘要；
//  2. 签名覆盖的摘要必须等于制品摘要。
func TestValidateHurManifestAndSignature(t *testing.T) {
	const sha = "0f1e2d"
	m := map[string]any{
		"hur": map[string]any{
			"spec":     "harness-use-package/v1",
			"id":       "A-generic-demo-abc123",
			"artifact": map[string]any{"name": "A-demo.hur", "sha256": sha, "bytes": 12.0},
			"signature": map[string]any{
				"format": "minisign", "keynum": "AABBCCDD11223344", "sha256": sha,
			},
		},
	}
	if code, msg := validateHurManifest(m, sha); code != "" {
		t.Fatalf("合法清单不该报错，得到 %s: %s", code, msg)
	}
	if code, _ := validateHurManifest(m, "ffffff"); code != "digest_mismatch" {
		t.Fatalf("上传字节摘要不符应为 digest_mismatch，实际 %q", code)
	}
	// 签名指向另一份产物 → 必须拒
	m["hur"].(map[string]any)["signature"] = map[string]any{"keynum": "AA", "sha256": "999999"}
	if code, _ := validateHurManifest(m, sha); code != "signature_mismatch" {
		t.Fatalf("签名摘要不符应为 signature_mismatch，实际 %q", code)
	}
	// 缺清单 / 缺 spec 一律拒
	if code, _ := validateHurManifest(map[string]any{}, sha); code != "bad_manifest" {
		t.Fatalf("缺 hur 对象应为 bad_manifest，实际 %q", code)
	}
	if code, _ := validateHurManifest(map[string]any{"hur": map[string]any{"id": "X", "artifact": map[string]any{"sha256": sha}}}, sha); code != "bad_manifest" {
		t.Fatalf("缺 spec 应为 bad_manifest，实际 %q", code)
	}
	// replica 也走同一套校验（分发过去的副本带的是同一份清单）
	if code, _ := validateHurSignature(map[string]any{"keynum": "AA", "url": "u"}, sha); code != "bad_signature" {
		t.Fatalf("有 url 无 sigSha256 应为 bad_signature，实际 %q", code)
	}
	_ = parseManifestMap(`{"hur":{"id":"X"}}`)
}
