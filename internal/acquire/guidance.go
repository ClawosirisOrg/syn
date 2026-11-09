// SPDX-License-Identifier: AGPL-3.0-or-later
package acquire

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	maxMetadata = 32 << 10
	maxBody     = 1 << 20
)

var name = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
var sha = regexp.MustCompile("^[0-9a-f]{40}$")

// Approved must come from authenticated operator policy, never from a PR.
type Approved struct{ Repository, DefaultBranch string }

// Witness binds bytes to a repository, default branch, immutable commit, path
// and Git blob. It is not an independently authenticated attestation.
type Witness struct{ Repository, DefaultBranch, Commit, Path, Blob string }
type Guidance struct {
	Body    []byte
	Witness Witness
	// Only Acquire can set this nonserialized provenance seal.
	proof [32]byte
}

func (g Guidance) Verify(repo, branch, commit, file string) error {
	w := g.Witness
	if g.proof == ([32]byte{}) || g.proof != provenance(g) || !validRepo(repo) || !validRepo(w.Repository) || !strings.EqualFold(w.Repository, repo) || w.DefaultBranch != branch || w.Commit != commit || w.Path != file || !sha.MatchString(commit) || !sha.MatchString(w.Blob) || gitBlob(g.Body) != w.Blob {
		return errors.New("guidance witness mismatch")
	}
	return nil
}

func provenance(g Guidance) [32]byte {
	b, _ := json.Marshal(struct {
		Witness Witness
		Body    []byte
	}{g.Witness, g.Body})
	return sha256.Sum256(append([]byte("syn-guidance-provenance-v1:"), b...))
}

// Client is an injected authenticated read-only GitHub API reader. Its
// implementations must enforce GET only, fixed origin, limits and no redirects.
type Client interface {
	GET(context.Context, string, int64) ([]byte, error)
}

// Acquire resolves the approved default branch and reads content at its SHA;
// it cannot select or promote a PR branch.
func Acquire(ctx context.Context, c Client, a Approved, file string) (Guidance, error) {
	var empty Guidance
	if ctx == nil || c == nil || !validRepo(a.Repository) || !validBranch(a.DefaultBranch) || !validFile(file) {
		return empty, errors.New("invalid approved guidance request")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	prefix := "/repos/" + a.Repository
	repo, e := get(ctx, c, prefix, maxMetadata)
	if e != nil {
		return empty, e
	}
	r, e := field(repo, "full_name")
	if e != nil || !validRepo(r) || !strings.EqualFold(r, a.Repository) {
		return empty, errors.New("repository identity mismatch")
	}
	canonicalRepo := r
	r, e = field(repo, "default_branch")
	if e != nil || r != a.DefaultBranch {
		return empty, errors.New("default branch mismatch")
	}
	branch, e := get(ctx, c, prefix+"/branches/"+a.DefaultBranch, maxMetadata)
	if e != nil {
		return empty, e
	}
	r, e = field(branch, "name")
	if e != nil || r != a.DefaultBranch {
		return empty, errors.New("branch identity mismatch")
	}
	commitObj, ok := branch["commit"].(map[string]any)
	if !ok {
		return empty, errors.New("missing branch commit")
	}
	commit, e := field(commitObj, "sha")
	if e != nil || !sha.MatchString(commit) {
		return empty, errors.New("invalid branch commit")
	}
	obj, e := get(ctx, c, prefix+"/contents/"+file+"?ref="+commit, maxBody*2+maxMetadata)
	if e != nil {
		return empty, e
	}
	for k, v := range map[string]string{"type": "file", "path": file, "encoding": "base64"} {
		got, err := field(obj, k)
		if err != nil || got != v {
			return empty, errors.New("guidance object mismatch")
		}
	}
	blob, e := field(obj, "sha")
	if e != nil || !sha.MatchString(blob) {
		return empty, errors.New("invalid blob identity")
	}
	size, ok := obj["size"].(json.Number)
	if !ok {
		return empty, errors.New("invalid blob size")
	}
	n, e := size.Int64()
	if e != nil || n < 0 || n > maxBody {
		return empty, errors.New("invalid blob size")
	}
	content, e := field(obj, "content")
	if e != nil || len(content) > maxBody*2 {
		return empty, errors.New("invalid blob content")
	}
	b, e := base64.StdEncoding.Strict().DecodeString(strings.ReplaceAll(content, "\n", ""))
	if e != nil || int64(len(b)) != n || gitBlob(b) != blob {
		return empty, errors.New("guidance blob identity mismatch")
	}
	// Recheck both mutable identities after fetching content. A branch or
	// default-branch switch mid-acquisition cannot yield a pinned witness.
	repo, e = get(ctx, c, prefix, maxMetadata)
	if e != nil {
		return empty, e
	}
	r, e = field(repo, "full_name")
	if e != nil || !validRepo(r) || !strings.EqualFold(r, canonicalRepo) {
		return empty, errors.New("repository identity changed")
	}
	r, e = field(repo, "default_branch")
	if e != nil || r != a.DefaultBranch {
		return empty, errors.New("default branch changed")
	}
	branch, e = get(ctx, c, prefix+"/branches/"+a.DefaultBranch, maxMetadata)
	if e != nil {
		return empty, e
	}
	r, e = field(branch, "name")
	if e != nil || r != a.DefaultBranch {
		return empty, errors.New("branch identity changed")
	}
	commitObj, ok = branch["commit"].(map[string]any)
	if !ok {
		return empty, errors.New("branch commit missing after fetch")
	}
	r, e = field(commitObj, "sha")
	if e != nil || r != commit {
		return empty, errors.New("branch commit changed")
	}
	g := Guidance{Body: b, Witness: Witness{canonicalRepo, a.DefaultBranch, commit, file, blob}}
	g.proof = provenance(g)
	return g, nil
}
func get(ctx context.Context, c Client, p string, limit int64) (map[string]any, error) {
	b, e := c.GET(ctx, p, limit)
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, errors.New("oversized GitHub response")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var obj map[string]any
	if dec.Decode(&obj) != nil || obj == nil {
		return nil, errors.New("invalid GitHub response")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("trailing GitHub response")
	}
	return obj, nil
}
func field(obj map[string]any, key string) (string, error) {
	s, ok := obj[key].(string)
	if !ok {
		return "", errors.New("missing GitHub field")
	}
	return s, nil
}
func gitBlob(b []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(b))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
func validRepo(r string) bool {
	p := strings.Split(r, "/")
	return len(p) == 2 && name.MatchString(p[0]) && name.MatchString(p[1]) && p[0] != "." && p[1] != "."
}
func validBranch(s string) bool {
	if s == "" || len(s) > 200 || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") || strings.HasSuffix(s, ".") || strings.ContainsAny(s, "\\%?#:~^*[] \x00") || strings.Contains(s, "..") || strings.Contains(s, "//") || strings.Contains(s, "@{") {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "" || strings.HasPrefix(p, ".") || strings.HasSuffix(p, ".lock") {
			return false
		}
	}
	for _, r := range s {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}
func validFile(f string) bool {
	if f == "" || len(f) > 512 || path.Clean(f) != f || strings.HasPrefix(f, "/") || strings.ContainsAny(f, "\\%?#:\x00") {
		return false
	}
	for _, p := range strings.Split(f, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	for _, r := range f {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}
