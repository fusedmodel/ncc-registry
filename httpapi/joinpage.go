package httpapi

import (
	"html/template"
	"strings"
)

// 接入页：内网短链 <publicURL>/j/<key>#<secret> 打开后看到的东西。
//
// 设计要点：**secret 只在 fragment 里**，浏览器不会把它发给服务端（不进访问日志、
// 不进 Referer）。页面用 JS 把它读出来，拼成可直接粘贴的 CLI 命令。
const joinPageTpl = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>接入内网 NCC Registry</title>
<meta name="robots" content="noindex,nofollow" />
<style>
:root{--bg:#fff;--bg2:#f9fafb;--bg3:#f3f4f6;--ink:#111827;--ink2:#4b5563;--ink3:#6b7280;
--ink4:#9ca3af;--line:#e5e7eb;--line2:#f3f4f6;--ok:#16a34a;--err:#dc2626;
--mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Noto Sans SC',system-ui,sans-serif}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--sans);color:var(--ink);background:var(--bg);line-height:1.65;-webkit-font-smoothing:antialiased}
.wrap{max-width:760px;margin:0 auto;padding:44px 24px 64px}
.head{display:flex;align-items:center;gap:12px;margin-bottom:6px}
.logo{display:grid;place-items:center;width:30px;height:30px;border-radius:9px;background:var(--ink);color:#fff;font-weight:800;font-size:14px}
h1{font-size:21px;font-weight:800;letter-spacing:-.015em}
.sub{color:var(--ink3);font-size:14px;margin:10px 0 22px}
.badge{display:inline-block;font-family:var(--mono);font-size:10.5px;font-weight:700;letter-spacing:.03em;
padding:2px 9px;border-radius:999px;border:1px solid var(--line);color:var(--ink3);background:#fff}
.badge.ok{color:var(--ok);border-color:#bbf7d0}
.badge.no{color:var(--err);border-color:#fecaca}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1px;background:var(--line);
border:1px solid var(--line);border-radius:12px;overflow:hidden;margin:18px 0 22px}
.kv div{background:#fff;padding:11px 13px}
.kv b{display:block;font-size:10.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--ink4);margin-bottom:3px}
.kv i{font-style:normal;font-family:var(--mono);font-size:12.5px;word-break:break-all}
h2{font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--ink3);margin:24px 0 10px}
pre{font-family:var(--mono);font-size:12.5px;background:var(--bg2);border:1px solid var(--line2);
border-radius:12px;padding:14px 16px;overflow-x:auto;color:var(--ink2);line-height:1.85}
pre b{color:var(--ink)}
button{font-family:inherit;font-size:13px;font-weight:600;border:1px solid var(--line);background:#fff;
color:var(--ink);border-radius:9px;padding:8px 14px;cursor:pointer;margin:0 8px 8px 0}
button:hover{border-color:var(--ink)}
button.primary{background:var(--ink);color:#fff;border-color:var(--ink)}
.warn{border:1px solid #fecaca;background:#fef2f2;color:#991b1b;border-radius:12px;padding:12px 14px;font-size:13.5px;margin:16px 0}
.msg{font-size:13.5px;margin-top:10px;white-space:pre-wrap}
.mono{font-family:var(--mono);font-size:12.5px}
.muted{color:var(--ink3)}
footer{margin-top:36px;color:var(--ink4);font-size:12.5px;border-top:1px solid var(--line2);padding-top:14px}
</style>
</head>
<body>
<div class="wrap">
  <div class="head">
    <div class="logo">N</div>
    <h1>接入内网 NCC Registry</h1>
  </div>
  <p class="sub">这是一个自托管的内网节点（制品托管 · 节点托管 · Agent 发现与互联）。链接里带着接入凭据，粘贴即可接入。</p>

  <p>
    <span class="badge {{if .Usable}}ok{{else}}no{{end}}">{{.Note}}</span>
    <span class="badge">key {{.Key}}</span>
    {{if .Namespace}}<span class="badge">命名空间 @{{.Namespace}}</span>{{end}}
  </p>

  <div class="kv">
    <div><b>服务地址</b><i>{{.Base}}</i></div>
    <div><b>key</b><i>{{.Key}}</i></div>
    <div><b>secret</b><i id="secretView">（读取链接片段…）</i></div>
    <div><b>控制台</b><i>{{.Base}}/</i></div>
  </div>

  <div id="noFragment" class="warn" style="display:none">
    这个链接里没有 secret（片段被去掉了）。请让签发者重新发一条完整短链，
    或用 <span class="mono">--key / --secret</span> 分开传入。
  </div>

  <h2>方式一：命令行接入（推荐）</h2>
  <pre id="cmdBox">ncc registry add &lt;这条链接&gt; --join</pre>
  <button class="primary" id="copyCmd">复制命令</button>
  <button id="copyLink">复制完整链接</button>
  <div class="msg muted" id="copyMsg"></div>

  <h2>方式二：手工填 key / secret</h2>
  <pre id="manualBox">ncc registry add --base {{.Base}} --key {{.Key}} --secret &lt;secret&gt;
# 或只登录、不托管本机：
ncc --base {{.Base}} registry login --key {{.Key}} --secret &lt;secret&gt;</pre>

  <h2>方式三：在这个浏览器里验证</h2>
  <p class="muted" style="font-size:13.5px">只做一次兑换请求，确认 key/secret 与这个节点的连通性；不会把凭据存到服务端。</p>
  <button id="redeemBtn">用本链接凭据接入</button>
  <pre id="result" style="display:none"></pre>

  <footer>
    凭据在链接的 <span class="mono">#</span> 片段里，浏览器不会把它发给服务端 —— 也就不进访问日志。
    接入后拿到的是**节点令牌**：默认只允许上报自己的心跳与读取公开制品。
  </footer>
</div>

<script>
const KEY = {{.KeyJSON}};
const BASE = {{.BaseJSON}};
const hash = location.hash.startsWith('#') ? location.hash.slice(1) : '';
const secret = hash.startsWith('s=') ? hash.slice(2) : hash;

const secretView = document.getElementById('secretView');
const cmdBox = document.getElementById('cmdBox');
const fullLink = BASE + '/j/' + KEY + '#' + secret;

if (!secret) {
  document.getElementById('noFragment').style.display = 'block';
  secretView.textContent = '—';
} else {
  secretView.textContent = secret.slice(0, 6) + '…（已读取，共 ' + secret.length + ' 位）';
  cmdBox.textContent = 'ncc registry add ' + fullLink + ' --join';
}

function flash(el, text) {
  el.textContent = text;
  setTimeout(() => { el.textContent = ''; }, 2500);
}
document.getElementById('copyCmd').onclick = async () => {
  try { await navigator.clipboard.writeText(cmdBox.textContent); flash(document.getElementById('copyMsg'), '已复制命令'); }
  catch (e) { flash(document.getElementById('copyMsg'), '复制失败，请手动选中'); }
};
document.getElementById('copyLink').onclick = async () => {
  try { await navigator.clipboard.writeText(fullLink); flash(document.getElementById('copyMsg'), '已复制链接'); }
  catch (e) { flash(document.getElementById('copyMsg'), '复制失败，请手动选中'); }
};
document.getElementById('redeemBtn').onclick = async () => {
  const out = document.getElementById('result');
  out.style.display = 'block';
  if (!secret) { out.textContent = '链接里没有 secret，无法兑换。'; return; }
  out.textContent = '兑换中…';
  try {
    const r = await fetch('/api/access/redeem', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: KEY, secret })
    });
    const d = await r.json();
    out.textContent = JSON.stringify(d, null, 2);
  } catch (e) {
    out.textContent = '请求失败：' + e;
  }
};
</script>
</body>
</html>
`

var joinPageTemplate = template.Must(template.New("join").Parse(joinPageTpl))

type joinPageData struct {
	Key       string
	Base      string
	Namespace string
	Note      string
	Usable    bool
	// 已是带引号的 JS 字符串字面量（见 jsonStringLiteral），所以用 template.JS 原样插入；
	// template.JSStr 会再加一层引号，变成 ""NK-…"" 直接把脚本搞挂。
	KeyJSON  template.JS
	BaseJSON template.JS
}

// joinPageHTML 渲染接入页。jsonStr 用 JS 字面量，避免注入。
func joinPageHTML(key, note string, usable bool, base, nsSlug string) string {
	var sb strings.Builder
	data := joinPageData{
		Key: key, Base: strings.TrimRight(base, "/"), Namespace: nsSlug,
		Note: note, Usable: usable,
		KeyJSON:  template.JS(jsonStringLiteral(key)),
		BaseJSON: template.JS(jsonStringLiteral(strings.TrimRight(base, "/"))),
	}
	if err := joinPageTemplate.Execute(&sb, data); err != nil {
		return "<!doctype html><meta charset=\"utf-8\"><p>渲染失败</p>"
	}
	return sb.String()
}

// jsonStringLiteral 把任意字符串编码成可安全嵌进 <script> 的 JS 字符串字面量。
func jsonStringLiteral(s string) string {
	b, err := jsonMarshal(s)
	if err != nil {
		return `""`
	}
	// 防止 </script> 提前闭合脚本块
	return strings.ReplaceAll(strings.ReplaceAll(string(b), "<", `\u003c`), ">", `\u003e`)
}
