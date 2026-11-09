// SPDX-License-Identifier: AGPL-3.0-or-later
package acquire

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var approval = Approved{"ClawOsirisOrg/syn", "main"}

const file = ".github/CODEOWNERS"

var body = []byte("* @owner\n")

type fake func(string, int64) ([]byte, error)

func (f fake) GET(_ context.Context, p string, n int64) ([]byte, error) { return f(p, n) }
func sample(repo, branch, obj map[string]any) fake {
	return func(p string, _ int64) ([]byte, error) {
		switch p {
		case "/repos/ClawOsirisOrg/syn":
			return json.Marshal(repo)
		case "/repos/ClawOsirisOrg/syn/branches/main":
			return json.Marshal(branch)
		case "/repos/ClawOsirisOrg/syn/contents/.github/CODEOWNERS?ref=" + commit:
			return json.Marshal(obj)
		default:
			return nil, errors.New("unexpected request")
		}
	}
}
func fixtures() (map[string]any, map[string]any, map[string]any) {
	return map[string]any{"full_name": approval.Repository, "default_branch": "main"}, map[string]any{"name": "main", "commit": map[string]any{"sha": commit}}, map[string]any{"type": "file", "path": file, "sha": gitBlob(body), "size": len(body), "encoding": "base64", "content": base64.StdEncoding.EncodeToString(body)}
}
func TestAcquirePinned(t *testing.T) {
	r, b, o := fixtures()
	g, e := Acquire(context.Background(), sample(r, b, o), approval, file)
	if e != nil {
		t.Fatal(e)
	}
	if string(g.Body) != string(body) || g.Witness.Commit != commit || g.Witness.Blob != gitBlob(body) {
		t.Fatal("incorrect witness")
	}
	if e = g.Verify(approval.Repository, "main", commit, file); e != nil {
		t.Fatal(e)
	}
	g.Body[0] = '!'
	if g.Verify(approval.Repository, "main", commit, file) == nil {
		t.Fatal("mutated bytes accepted")
	}
}
func TestOnlyAcquiredGuidanceCarriesProvenance(t *testing.T) {
	r, b, o := fixtures()
	g, err := Acquire(context.Background(), sample(r, b, o), approval, file)
	if err != nil {
		t.Fatal(err)
	}
	forged := Guidance{Body: append([]byte(nil), g.Body...), Witness: g.Witness}
	if forged.Verify(approval.Repository, "main", commit, file) == nil {
		t.Fatal("caller-built witness accepted")
	}
	encoded, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Guidance
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Verify(approval.Repository, "main", commit, file) == nil {
		t.Fatal("serialized witness accepted")
	}
	changed := g
	changed.Witness.Commit = strings.Repeat("b", 40)
	if changed.Verify(approval.Repository, "main", changed.Witness.Commit, file) == nil {
		t.Fatal("mutated commit accepted")
	}
}

func TestAcquireRefusals(t *testing.T) {
	tests := map[string]func(map[string]any, map[string]any, map[string]any){
		"repository":              func(r, b, o map[string]any) { r["full_name"] = "other/repo" },
		"default branch":          func(r, b, o map[string]any) { r["default_branch"] = "feature" },
		"branch response":         func(r, b, o map[string]any) { b["name"] = "feature" },
		"missing commit":          func(r, b, o map[string]any) { delete(b, "commit") },
		"wrong commit":            func(r, b, o map[string]any) { b["commit"] = map[string]any{"sha": "branch-name"} },
		"different pinned commit": func(r, b, o map[string]any) { b["commit"] = map[string]any{"sha": strings.Repeat("c", 40)} },
		"wrong blob":              func(r, b, o map[string]any) { o["sha"] = strings.Repeat("b", 40) },
		"wrong content":           func(r, b, o map[string]any) { o["content"] = base64.StdEncoding.EncodeToString([]byte("not the file")) },
		"wrong path":              func(r, b, o map[string]any) { o["path"] = "AGENTS.md" },
		"wrong type":              func(r, b, o map[string]any) { o["type"] = "dir" },
		"missing content":         func(r, b, o map[string]any) { delete(o, "content") },
		"oversize":                func(r, b, o map[string]any) { o["size"] = maxBody + 1 },
	}
	for label, change := range tests {
		t.Run(label, func(t *testing.T) {
			r, b, o := fixtures()
			change(r, b, o)
			if _, e := Acquire(context.Background(), sample(r, b, o), approval, file); e == nil {
				t.Fatal("accepted mismatch")
			}
		})
	}
	for _, f := range []string{"../AGENTS.md", "/AGENTS.md", "docs/../AGENTS.md", "docs//AGENTS.md", "https://example.org/a", "x%2fAGENTS.md", "x?ref=feature"} {
		if _, e := Acquire(context.Background(), fake(func(string, int64) ([]byte, error) { t.Fatal("network on invalid file"); return nil, nil }), approval, f); e == nil {
			t.Errorf("accepted %s", f)
		}
	}
	if _, e := Acquire(context.Background(), fake(func(string, int64) ([]byte, error) { t.Fatal("network on invalid repo"); return nil, nil }), Approved{"bad/repo/extra", "main"}, file); e == nil {
		t.Fatal("accepted invalid repo")
	}
	if _, e := Acquire(context.Background(), fake(func(string, int64) ([]byte, error) { return []byte(strings.Repeat("x", maxMetadata+1)), nil }), approval, file); e == nil {
		t.Fatal("accepted oversized metadata")
	}
}
func TestAcquireDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	reader := fake(func(_ string, _ int64) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() })
	if _, e := Acquire(ctx, reader, approval, file); e == nil {
		t.Fatal("accepted expired acquisition")
	}
}

func TestCanonicalRepoCase(t *testing.T) {
	r, b, o := fixtures()
	a := Approved{"clawosirisorg/SYN", "main"}
	reader := fake(func(p string, n int64) ([]byte, error) {
		if !strings.HasPrefix(p, "/repos/"+a.Repository) {
			t.Fatalf("unexpected origin/path: %q", p)
		}
		return sample(r, b, o).GET(context.Background(), strings.Replace(p, "/repos/"+a.Repository, "/repos/"+approval.Repository, 1), n)
	})
	g, e := Acquire(context.Background(), reader, a, file)
	if e != nil {
		t.Fatal(e)
	}
	if g.Witness.Repository != approval.Repository || g.Verify(a.Repository, "main", commit, file) != nil {
		t.Fatal("not bound to canonical case-insensitive repo")
	}
	r["full_name"] = "ClawOsirisOrg/other"
	if _, e = Acquire(context.Background(), reader, a, file); e == nil {
		t.Fatal("promoted another repository")
	}
}
func TestDriftAfterBlob(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any, map[string]any)
	}{
		{"default branch", func(r, b map[string]any) { r["default_branch"] = "next" }},
		{"commit", func(r, b map[string]any) { b["commit"] = map[string]any{"sha": strings.Repeat("b", 40)} }},
		{"branch identity", func(r, b map[string]any) { b["name"] = "other" }},
		{"repository", func(r, b map[string]any) { r["full_name"] = "ClawOsirisOrg/other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, b, o := fixtures()
			reads := 0
			reader := fake(func(p string, n int64) ([]byte, error) {
				if strings.Contains(p, "/contents/") {
					reads++
					response, e := sample(r, b, o).GET(context.Background(), p, n)
					tc.change(r, b)
					return response, e
				}
				return sample(r, b, o).GET(context.Background(), p, n)
			})
			if _, e := Acquire(context.Background(), reader, approval, file); e == nil || reads != 1 {
				t.Fatalf("drift accepted or content not fetched: %v, reads=%d", e, reads)
			}
		})
	}
}
