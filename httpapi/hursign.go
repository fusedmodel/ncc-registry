// HUR（kind=hur）制品的清单校验与「加签」（与平台侧同口径）。
//
// 边界（别在这里糊掉）：
//   - **签名在发布者自己的机器上做**（`ncc hur sign`），私钥不出设备；本节点不代签。
//   - 这里只做**自洽性核对**（清单自述摘要 vs 上传字节摘要、签名覆盖摘要 vs 制品摘要），
//     不做密码学验签 —— 那是下载方拿公钥自己判断的事。
//   - 内网节点常常是**副本的持有者**：副本不能被本节点改（改要走源头），加签同理。
package httpapi

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// validateHurManifest 校验 kind=hur 的清单，返回错误码与说明（空 = 通过）。
// storageSHA 是上传接口算出的字节摘要，用于与清单自述的产物摘要交叉核对。
func validateHurManifest(m map[string]any, storageSHA string) (code, msg string) {
	h, _ := m["hur"].(map[string]any)
	if h == nil {
		return "bad_manifest", "kind=hur 的 manifest 需要 hur 对象（spec / id / artifact）"
	}
	if v, _ := h["spec"].(string); strings.TrimSpace(v) == "" {
		return "bad_manifest", "manifest.hur.spec 不能为空（如 harness-use-package/v1）"
	}
	if v, _ := h["id"].(string); strings.TrimSpace(v) == "" {
		return "bad_manifest", "manifest.hur.id 不能为空（HUR 的包 id 就是它的身份）"
	}
	art, _ := h["artifact"].(map[string]any)
	if art == nil {
		return "bad_manifest", "manifest.hur.artifact 缺失（name / sha256 / bytes）"
	}
	artSHA, _ := art["sha256"].(string)
	artSHA = strings.TrimSpace(artSHA)
	if artSHA == "" {
		return "bad_manifest", "manifest.hur.artifact.sha256 不能为空"
	}
	if s := strings.TrimSpace(storageSHA); s != "" && !strings.EqualFold(s, artSHA) {
		return "digest_mismatch", "上传字节的 sha256 与 manifest.hur.artifact.sha256 不一致（上传的不是清单声明的那份产物）"
	}
	if sig, ok := h["signature"].(map[string]any); ok && sig != nil {
		return validateHurSignature(sig, artSHA)
	}
	return "", ""
}

// validateHurSignature 校验签名对象的自洽性（不做密码学验签）。
func validateHurSignature(sig map[string]any, artSHA string) (code, msg string) {
	if v, _ := sig["keynum"].(string); strings.TrimSpace(v) == "" {
		return "bad_signature", "signature.keynum 不能为空（没有指纹就说明不了是谁签的）"
	}
	if v, _ := sig["format"].(string); v != "" && v != "minisign" {
		return "bad_signature", "signature.format 目前只支持 minisign"
	}
	if v, _ := sig["sha256"].(string); strings.TrimSpace(v) != "" && artSHA != "" {
		if !strings.EqualFold(strings.TrimSpace(v), artSHA) {
			return "signature_mismatch", "签名覆盖的摘要与制品摘要不一致（这份签名不是这份产物的）"
		}
	}
	if v, _ := sig["url"].(string); strings.TrimSpace(v) != "" {
		if s, _ := sig["sigSha256"].(string); strings.TrimSpace(s) == "" {
			return "bad_signature", "提供了 signature.url 就必须同时提供 signature.sigSha256"
		}
	}
	return "", ""
}

// attachSignature PUT /api/registry/:ref/signature —— 给已发布的 hur 制品附着（或替换）签名。
//
// 只收 signature、不收整个 manifest：产物字节没变，只是把本机签名补上去；
// 收 manifest 就等于允许顺手改权限面与产物摘要，那是「换包」不是「加签」。
func (s *Server) attachSignature(c *gin.Context) {
	a := authOf(c)
	row, err := s.findByRef(refFromParams(c))
	if err != nil {
		fail(c, 404, "not_found", "制品不存在")
		return
	}
	if row.IsReplica() {
		fail(c, 403, "replica_readonly", "这是其它节点分发过来的副本，请到源头节点加签")
		return
	}
	if !s.canManage(row.NamespaceID, a.UserID) {
		fail(c, 403, "forbidden", "你不是该制品的 owner/成员")
		return
	}
	if row.Kind != "hur" {
		fail(c, 400, "bad_kind", "只有 kind=hur 的制品支持加签（其他类型没有 HUR 的清单语义）")
		return
	}
	var body struct {
		Signature map[string]any `json:"signature"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.Signature) == 0 {
		fail(c, 400, "bad_request", "请求体需提供 signature 对象（keynum 必填）")
		return
	}
	man := parseManifestMap(row.Manifest)
	h, _ := man["hur"].(map[string]any)
	if h == nil {
		fail(c, 400, "bad_manifest", "该制品的 manifest 里没有 hur 对象，无法加签（请用 `ncc hur publish` 重新发布）")
		return
	}
	art, _ := h["artifact"].(map[string]any)
	artSHA, _ := art["sha256"].(string)
	if strings.TrimSpace(artSHA) == "" {
		fail(c, 400, "bad_manifest", "manifest.hur.artifact.sha256 为空，无法核对签名归属")
		return
	}
	if code, msg := validateHurSignature(body.Signature, artSHA); code != "" {
		fail(c, 400, code, msg)
		return
	}
	h["signature"] = body.Signature
	man["hur"] = h
	b, err := jsonMarshal(man)
	if err != nil {
		fail(c, 500, "internal", "manifest 序列化失败")
		return
	}
	if err := s.St.UpdateArtifactFields(row.ID, map[string]any{"manifest": string(b)}); err != nil {
		fail(c, 500, "internal", "写入签名失败")
		return
	}
	fresh, _ := s.St.FindArtifactByID(row.ID)
	ok(c, 200, gin.H{"item": artifactJSON(fresh)})
}
