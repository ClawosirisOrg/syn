// SPDX-License-Identifier: AGPL-3.0-or-later
package ownership

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ClawOsirisOrg/syn/internal/acquire"
	"github.com/ClawOsirisOrg/syn/internal/config"
)

const testRepo = "ClawOsirisOrg/syn"
const testCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testPath = ".github/CODEOWNERS"

type fakeClient func(string) ([]byte, error)

func (f fakeClient) GET(_ context.Context, path string, _ int64) ([]byte, error) { return f(path) }
func acquired(t *testing.T, body string) acquire.Guidance {
	t.Helper()
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(body))
	h.Write([]byte(body))
	blob := hex.EncodeToString(h.Sum(nil))
	client := fakeClient(func(p string) ([]byte, error) {
		var obj any
		switch p {
		case "/repos/" + testRepo:
			obj = map[string]any{"full_name": testRepo, "default_branch": "main"}
		case "/repos/" + testRepo + "/branches/main":
			obj = map[string]any{"name": "main", "commit": map[string]any{"sha": testCommit}}
		case "/repos/" + testRepo + "/contents/" + testPath + "?ref=" + testCommit:
			obj = map[string]any{"type": "file", "path": testPath, "sha": blob, "size": len(body), "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(body))}
		default:
			return nil, fmt.Errorf("unexpected read %q", p)
		}
		return json.Marshal(obj)
	})
	guidance, err := acquire.Acquire(context.Background(), client, acquire.Approved{Repository: testRepo, DefaultBranch: "main"}, testPath)
	if err != nil {
		t.Fatal(err)
	}
	return guidance
}
func request(t *testing.T, body string) Request {
	t.Helper()
	g := acquired(t, body)
	return Request{
		Profile:     config.RepositoryProfile{Version: config.Version, Organization: "ClawOsirisOrg", Repository: testRepo, DataClass: "public", EventAllowlist: []string{"pull_request/opened"}},
		Pin:         Pin{Repository: testRepo, DefaultBranch: "main", Commit: testCommit, Path: testPath},
		Guidance:    &g,
		Maintainers: TrustedMaintainers{Repository: testRepo, Approved: true, Logins: []string{"Alice", "Bob"}},
		Kind:        "pull_request", Paths: []string{"docs/readme.md"},
	}
}
func mustOwner(t *testing.T, req Request, want string, gap config.OwnershipGap) {
	t.Helper()
	result, err := Resolve(req)
	if err != nil || result.OwnerID != want || result.Gap != gap || result.FromFallback != (gap != "") {
		t.Fatalf("Resolve: %+v, %v; want %s/%s", result, err, want, gap)
	}
}
func mustRefuse(t *testing.T, req Request, gap config.OwnershipGap) {
	t.Helper()
	result, err := Resolve(req)
	if err == nil || result.OwnerID != "" || result.Gap != gap {
		t.Fatalf("expected refusal %s: %+v, %v", gap, result, err)
	}
}
func TestPinnedDefaultBranchNotPRBody(t *testing.T) {
	req := request(t, "* @Alice\n/docs/ @Bob\n")
	mustOwner(t, req, "Bob", "")
	req.Paths = []string{"readme.md"}
	mustOwner(t, req, "Alice", "")
	req.Paths = []string{"docs/notes.txt", "readme.md"}
	mustRefuse(t, req, config.OwnershipAmbiguous)
	// A PR-body CODEOWNERS cannot carry Acquire's private provenance seal.
	pr := acquire.Guidance{Body: []byte("* @Bob\n"), Witness: req.Guidance.Witness}
	req.Guidance = &pr
	mustRefuse(t, req, "")
	req.Guidance = nil // confirmed missing is different from unverified
	mustRefuse(t, req, config.OwnershipMissing)
}
func TestWitnessAndMetadataCannotBePromoted(t *testing.T) {
	baseline := request(t, "* @Alice\n")
	cases := map[string]func(*Request){
		"PR pin":                func(r *Request) { r.Pin.DefaultBranch = "feature" },
		"changed SHA":           func(r *Request) { r.Pin.Commit = strings.Repeat("b", 40) },
		"different repo":        func(r *Request) { r.Pin.Repository = "Other/repo" },
		"wrong path":            func(r *Request) { r.Pin.Path = "README.md" },
		"mutated witness":       func(r *Request) { g := *r.Guidance; g.Witness.Path = "CODEOWNERS"; r.Guidance = &g },
		"mutated bytes":         func(r *Request) { g := *r.Guidance; g.Body = []byte("* @Bob\n"); r.Guidance = &g },
		"unapproved metadata":   func(r *Request) { r.Maintainers.Approved = false },
		"other metadata repo":   func(r *Request) { r.Maintainers.Repository = "Other/repo" },
		"duplicate metadata":    func(r *Request) { r.Maintainers.Logins = []string{"Alice", "alice"} },
		"no approved candidate": func(r *Request) { r.Maintainers.Logins = []string{"Bob"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := baseline
			mutate(&req)
			if name == "no approved candidate" {
				mustRefuse(t, req, config.OwnershipMalformed)
			} else {
				mustRefuse(t, req, "")
			}
		})
	}
}
func TestMalformedUnsupportedAndAmbiguous(t *testing.T) {
	malformed := []string{
		"[bad] @Alice\n", "!docs @Alice\n", "/docs/** @Alice\n", "/docs/ @org/team\n", "/docs/ @Alice @Bob\n",
		"/docs/ @Alice #comment\n", "docs/ @Alice\n", "/docs/ @Alice\nother @Bob\n", "/docs/ @Mallory\n",
		"* @Alice\n/../docs/ @Bob\n", "* @Alice\n/dir/ @bad--name\n",
	}
	for _, body := range malformed {
		t.Run(body, func(t *testing.T) {
			req := request(t, body)
			mustRefuse(t, req, config.OwnershipMalformed)
		})
	}
	req := request(t, "*.go @Alice\n/src/*.go @Bob\n")
	req.Paths = []string{"src/a.go"}
	mustOwner(t, req, "Bob", "")
	req.Paths = []string{"src/nested/a.go"}
	mustOwner(t, req, "Alice", "")
	req.Paths = []string{"src/nested/a.go", "src/b.go"}
	mustRefuse(t, req, config.OwnershipAmbiguous)
	req.Paths = []string{"src/b.txt"}
	mustRefuse(t, req, config.OwnershipUnmatched)
	req.Paths = []string{"../outside"}
	mustRefuse(t, req, "")
	req.Paths = nil
	mustRefuse(t, req, "")
	req.Kind = "issue"
	mustRefuse(t, req, config.OwnershipUnmatched)
	req.Paths = []string{"src/nested/a.go"}
	mustOwner(t, req, "Alice", "")
}
func TestFallbackGapAndNonEscalation(t *testing.T) {
	req := request(t, "* @Alice\n")
	policy := config.OwnershipFallback{
		Missing:             config.OwnershipApprovedMaintainers,
		Malformed:           config.OwnershipApprovedMaintainers,
		Ambiguous:           config.OwnershipApprovedMaintainers,
		Unmatched:           config.OwnershipApprovedMaintainers,
		ApprovedMaintainers: []string{"Bob"},
	}
	req.Profile.OwnershipFallback = policy
	req.Guidance = nil
	mustOwner(t, req, "Bob", config.OwnershipMissing)
	req = request(t, "bad @Alice\n")
	req.Profile.OwnershipFallback = policy
	mustOwner(t, req, "Bob", config.OwnershipMalformed)
	req = request(t, "*.go @Alice\n")
	req.Profile.OwnershipFallback = policy
	mustOwner(t, req, "Bob", config.OwnershipUnmatched)
	req = request(t, "/docs/ @Alice\n/src/ @Bob\n")
	req.Profile.OwnershipFallback = policy
	req.Paths = []string{"docs/readme.md", "src/x.go"}
	mustRefuse(t, req, config.OwnershipAmbiguous) // fallback cannot override a known owner
	req.Maintainers.Logins = []string{"Alice"}
	mustRefuse(t, req, config.OwnershipMalformed)
	req.Maintainers.Logins = []string{"Alice", "Bob"}
	req.Profile.OwnershipFallback.ApprovedMaintainers = []string{"Alice", "Bob"}
	mustRefuse(t, req, config.OwnershipAmbiguous) // don't arbitrarily pick first
	req.Profile.OwnershipFallback.ApprovedMaintainers = []string{"Bob"}
	req.Pin.Commit = strings.Repeat("b", 40)
	mustRefuse(t, req, "") // invalid witness cannot trigger fallback
}
func TestAllPathsBeforeFallback(t *testing.T) {
	policy := config.OwnershipFallback{
		Malformed:           config.OwnershipApprovedMaintainers,
		Unmatched:           config.OwnershipApprovedMaintainers,
		Ambiguous:           config.OwnershipApprovedMaintainers,
		ApprovedMaintainers: []string{"Bob"},
	}
	for _, tc := range []struct {
		name, body, gapPath string
	}{
		{"unmatched", "/docs @Alice\n", "other/file.go"},
		{"untrusted owner", "/docs @Alice\n/other/ @Mallory\n", "other/file.go"},
	} {
		for _, reversed := range []bool{false, true} {
			name := tc.name
			if reversed {
				name += " reversed"
			}
			t.Run(name, func(t *testing.T) {
				req := request(t, tc.body)
				req.Profile.OwnershipFallback = policy
				req.Paths = []string{"docs/nested/file.md", tc.gapPath}
				if reversed {
					req.Paths[0], req.Paths[1] = req.Paths[1], req.Paths[0]
				}
				mustRefuse(t, req, config.OwnershipAmbiguous)
			})
		}
	}
	// A fallback agreeing with the pinned owner does not invent a conflict.
	req := request(t, "/docs @Alice\n")
	req.Profile.OwnershipFallback = policy
	req.Profile.OwnershipFallback.ApprovedMaintainers = []string{"Alice"}
	req.Paths = []string{"other/file.go", "docs/nested/file.md"}
	mustOwner(t, req, "Alice", config.OwnershipUnmatched)
}

func TestAnchoredDirectoryWithoutTrailingSlash(t *testing.T) {
	req := request(t, "/docs @Alice\n")
	req.Profile.OwnershipFallback = config.OwnershipFallback{
		Unmatched:           config.OwnershipApprovedMaintainers,
		ApprovedMaintainers: []string{"Bob"},
	}
	for _, p := range []string{"docs", "docs/readme.md", "docs/nested/readme.md"} {
		req.Paths = []string{p}
		mustOwner(t, req, "Alice", "")
	}
	for _, p := range []string{"docs-old/readme.md", "other/docs/readme.md"} {
		req.Paths = []string{p}
		mustOwner(t, req, "Bob", config.OwnershipUnmatched)
	}
	// Last matching rule wins over a slash-directory rule.
	req = request(t, "/docs @Alice\n/docs/nested/ @Bob\n")
	req.Paths = []string{"docs/nested/readme.md"}
	mustOwner(t, req, "Bob", "")
	// Unsupported syntax must not be interpreted as a narrower valid rule.
	req = request(t, "/docs @Alice\n/docs/** @Bob\n")
	req.Paths = []string{"docs/readme.md"}
	mustRefuse(t, req, config.OwnershipMalformed)
}

func TestBounds(t *testing.T) {
	for _, body := range []string{strings.Repeat("#\n", maxLines+1), strings.Repeat("x", maxLineBytes+1), strings.Repeat("* @Alice\n", maxRules+1)} {
		req := request(t, body)
		mustRefuse(t, req, config.OwnershipMalformed)
	}
	req := request(t, "* @Alice\n")
	req.Paths = make([]string, maxPaths+1)
	mustRefuse(t, req, "")
}
