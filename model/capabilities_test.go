package model

import "testing"

// 词表自身的一致性：每个 id 都必须被 KnownOffer 认得，且 id 唯一。
func TestNodeOfferCatalogIsSelfConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, o := range NodeOffers {
		if o.ID == "" || o.Zh == "" || o.Desc == "" {
			t.Fatalf("词表条目缺少 id/zh/desc: %+v", o)
		}
		if seen[o.ID] {
			t.Fatalf("词表里有重复 id: %s", o.ID)
		}
		seen[o.ID] = true
		if !KnownOffer(o.ID) {
			t.Fatalf("词表里的 id 却过不了 KnownOffer: %s", o.ID)
		}
		// id 必须是规范形态：归一之后不能再变
		if got := NormalizeOffer(o.ID); got != o.ID {
			t.Fatalf("id 不是规范形态: %s → %s", o.ID, got)
		}
	}
}

// 历史短名要能归一，而且要能被检索命中（这是「不破坏老节点」的关键）。
func TestOfferAliasesRoundTrip(t *testing.T) {
	cases := map[string]string{
		"mcp":           "serve:mcp",
		"api":           "serve:http",
		"wasm":          "run:wasm",
		"LLM":           "egress:llm",
		" js ":          "run:js",
		"unknown-thing": "unknown-thing", // 未知 id 原样保留
	}
	for in, want := range cases {
		if got := NormalizeOffer(in); got != want {
			t.Fatalf("NormalizeOffer(%q) = %q，期望 %q", in, got, want)
		}
	}

	// 每个别名都必须能被它指向的规范 id 的候选集命中
	for alias, canonical := range offerAliases {
		alts := OfferAlternatives(canonical)
		found := false
		for _, a := range alts {
			if a == alias {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("别名 %s 不在 %s 的候选集里：%v", alias, canonical, alts)
		}
		if NormalizeOffer(alias) != canonical {
			t.Fatalf("别名 %s 归一后不是 %s", alias, canonical)
		}
	}
}

func TestOfferAlternativesHandlesEmptyAndCustom(t *testing.T) {
	if got := OfferAlternatives("  "); got != nil {
		t.Fatalf("空串应返回 nil，得到 %v", got)
	}
	got := OfferAlternatives("mcp")
	if len(got) == 0 || got[0] != "serve:mcp" {
		t.Fatalf("候选集必须以规范 id 开头，得到 %v", got)
	}
	// 自定义 id 没有别名，候选集就是它自己
	custom := OfferAlternatives("egress:corp-vpn")
	if len(custom) != 1 || custom[0] != "egress:corp-vpn" {
		t.Fatalf("自定义 id 的候选集应只有自己，得到 %v", custom)
	}
}

func TestParseOfferQuery(t *testing.T) {
	cases := []struct {
		in       string
		id       string
		verified bool
	}{
		{"run:wasm", "run:wasm", false},
		{"wasm", "run:wasm", false}, // 别名照旧归一
		{"run:wasm@verified", "run:wasm", true},
		{"mcp@verified", "serve:mcp", true}, // 别名 + 限定符
		{" mcp @verified ", "serve:mcp", true},
		// 不是 `@verified` 后缀就整串当 id（自定 id 里带 @ 也照旧可用）
		{"egress:corp@vpn", "egress:corp@vpn", false},
		{"run:wasm@Verified", "run:wasm@verified", false},
	}
	for _, c := range cases {
		got := ParseOfferQuery(c.in)
		if got.ID != c.id || got.VerifiedOnly != c.verified {
			t.Fatalf("ParseOfferQuery(%q) = {%q,%v}，期望 {%q,%v}", c.in, got.ID, got.VerifiedOnly, c.id, c.verified)
		}
	}
}

func TestNormalizeOffersDedupesKeepingOrder(t *testing.T) {
	got := NormalizeOffers([]string{"mcp", " serve:mcp ", "wasm", "", "  ", "WASM", "custom:x"})
	want := []string{"serve:mcp", "run:wasm", "custom:x"}
	if len(got) != len(want) {
		t.Fatalf("NormalizeOffers 结果 %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("NormalizeOffers 结果 %v，期望 %v", got, want)
		}
	}
}
