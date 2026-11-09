// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const explicitFallback = `ownership_fallback:
  missing: refuse
  malformed: refuse
  ambiguous: refuse
  unmatched: refuse
  approved_maintainers: []
`

func TestOwnershipFallbackDefaultsAndExample(t *testing.T) {
	p, err := ParseRepository([]byte(profileYAML), "yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range []OwnershipGap{OwnershipMissing, OwnershipMalformed, OwnershipAmbiguous, OwnershipUnmatched, "", "other"} {
		if got := p.OwnershipFallback.ModeFor(reason); got != OwnershipRefuse {
			t.Fatalf("unspecified %q guessed owner: %q", reason, got)
		}
	}
	if p.OwnershipFallback.Missing != OwnershipRefuse || p.OwnershipFallback.Malformed != OwnershipRefuse ||
		p.OwnershipFallback.Ambiguous != OwnershipRefuse || p.OwnershipFallback.Unmatched != OwnershipRefuse ||
		len(p.OwnershipFallback.ApprovedMaintainers) != 0 {
		t.Fatalf("missing policy did not default to refusal: %+v", p.OwnershipFallback)
	}
	path := filepath.Join("..", "..", "configs", "repository.example.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	example, err := ParseRepository(data, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range []OwnershipGap{OwnershipMissing, OwnershipMalformed, OwnershipAmbiguous, OwnershipUnmatched} {
		if example.OwnershipFallback.ModeFor(reason) != OwnershipRefuse {
			t.Fatalf("example selected owner for %s", reason)
		}
	}
	explicit, err := ParseRepository([]byte(profileYAML+explicitFallback), "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, explicit) {
		t.Fatalf("explicit refusal differs from safe default: %+v vs %+v", p, explicit)
	}
	// Normalized default refusal must round-trip to strict JSON without null.
	j, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := ParseRepository(j, "json")
	if err != nil || !reflect.DeepEqual(p, fromJSON) {
		t.Fatalf("default refusal JSON round-trip: %v", err)
	}
}

func TestOwnershipFallbackBoundedExplicitPolicy(t *testing.T) {
	body := `ownership_fallback:
  missing: approved_maintainers
  malformed: refuse
  ambiguous: refuse
  unmatched: approved_maintainers
  approved_maintainers: [Alice, Bob]
`
	yamlProfile := profileYAML + body
	if _, err := ParseRepository([]byte(strings.Replace(yamlProfile, "[Alice, Bob]", "[a,b,c,d,e,f,g,h]", 1)), "yaml"); err != nil {
		t.Fatalf("bounded eight-maintainer list rejected: %v", err)
	}
	p, err := ParseRepository([]byte(yamlProfile), "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.OwnershipFallback.ModeFor(OwnershipMissing) != OwnershipApprovedMaintainers ||
		p.OwnershipFallback.ModeFor(OwnershipUnmatched) != OwnershipApprovedMaintainers ||
		p.OwnershipFallback.ModeFor(OwnershipMalformed) != OwnershipRefuse ||
		p.OwnershipFallback.ModeFor(OwnershipAmbiguous) != OwnershipRefuse ||
		p.OwnershipFallback.ModeFor("unknown") != OwnershipRefuse {
		t.Fatalf("case fallback mismatch: %+v", p.OwnershipFallback)
	}
	j, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := ParseRepository(j, "json")
	if err != nil || !reflect.DeepEqual(p, fromJSON) {
		t.Fatalf("YAML/JSON fallback mismatch: %v", err)
	}
	// Even programmatically constructed profiles must pass through the same
	// fail-closed validation before the effective resolver can accept them.
	p.OwnershipFallback.ApprovedMaintainers = []string{"Alice", "alice"}
	if err := p.Validate(); err == nil {
		t.Fatal("duplicate identities accepted in memory")
	}
	if p.OwnershipFallback.ModeFor(OwnershipMissing) != OwnershipRefuse {
		t.Fatal("invalid direct policy authorized fallback")
	}
}

func TestRejectUnsafeOwnershipFallback(t *testing.T) {
	base := profileYAML + `ownership_fallback:
  missing: approved_maintainers
  malformed: refuse
  ambiguous: refuse
  unmatched: refuse
  approved_maintainers: [Alice]
`
	cases := map[string]string{
		"unknown mode":           strings.Replace(base, "missing: approved_maintainers", "missing: infer_from_author", 1),
		"unknown nested field":   base + "  fallback_on_conflict: true\n",
		"no listed maintainer":   strings.Replace(base, "approved_maintainers: [Alice]", "approved_maintainers: []", 1),
		"unused maintainer list": strings.Replace(base, "missing: approved_maintainers", "missing: refuse", 1),
		"duplicate case":         strings.Replace(base, "[Alice]", "[Alice, alice]", 1),
		"unbounded list":         strings.Replace(base, "[Alice]", "[a,b,c,d,e,f,g,h,i]", 1),
		"too long":               strings.Replace(base, "Alice", strings.Repeat("a", 40), 1),
		"team without metadata":  strings.Replace(base, "Alice", "example-org/team", 1),
		"at-prefixed handle":     strings.Replace(base, "Alice", "@Alice", 1),
		"unicode":                strings.Replace(base, "Alice", "Álice", 1),
		"double hyphen":          strings.Replace(base, "Alice", "Al--ice", 1),
		"trailing hyphen":        strings.Replace(base, "Alice", "Alice-", 1),
		"duplicate YAML key":     base + "  missing: refuse\n",
		"null list":              strings.Replace(base, "[Alice]", "null", 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRepository([]byte(data), "yaml"); err == nil {
				t.Fatal("accepted unsafe fallback")
			}
		})
	}
	for name, value := range map[string]string{
		"unknown JSON mode":    `{"missing":"guess"}`,
		"unknown JSON nested":  `{"surprise":"refuse"}`,
		"unknown JSON handle":  `{"missing":"approved_maintainers","approved_maintainers":["@Alice"]}`,
		"missing identities":   `{"missing":"approved_maintainers"}`,
		"duplicate JSON field": `{"missing":"refuse","missing":"approved_maintainers","approved_maintainers":["Alice"]}`,
		"wrong type":           `{"missing":true}`,
		"case-alias key":       `{"Missing":"refuse"}`,
	} {
		t.Run(name, func(t *testing.T) {
			baseProfile, err := ParseRepository([]byte(profileYAML), "yaml")
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(baseProfile)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &doc); err != nil {
				t.Fatal(err)
			}
			doc["ownership_fallback"] = json.RawMessage(value)
			encoded, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRepository(encoded, "json"); err == nil {
				t.Fatal("accepted unsafe JSON fallback")
			}
		})
	}
}
