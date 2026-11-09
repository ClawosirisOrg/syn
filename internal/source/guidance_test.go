// SPDX-License-Identifier: AGPL-3.0-or-later
package source

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
)

const pinnedCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const pinnedPath = ".github/CODEOWNERS"

var pinnedBody = []byte("* @maintainer")

type guidanceClient func(string) ([]byte, error)

func (f guidanceClient) GET(_ context.Context, p string, _ int64) ([]byte, error) { return f(p) }
func acquiredGuidance(t *testing.T) acquire.Guidance {
	t.Helper()
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(pinnedBody))
	h.Write(pinnedBody)
	blob := hex.EncodeToString(h.Sum(nil))
	client := guidanceClient(func(p string) ([]byte, error) {
		var v any
		switch p {
		case "/repos/ClawOsirisOrg/syn":
			v = map[string]any{"full_name": testTarget.Repository, "default_branch": "main"}
		case "/repos/ClawOsirisOrg/syn/branches/main":
			v = map[string]any{"name": "main", "commit": map[string]any{"sha": pinnedCommit}}
		case "/repos/ClawOsirisOrg/syn/contents/.github/CODEOWNERS?ref=" + pinnedCommit:
			v = map[string]any{"type": "file", "path": pinnedPath, "sha": blob, "size": len(pinnedBody), "encoding": "base64", "content": base64.StdEncoding.EncodeToString(pinnedBody)}
		default:
			return nil, fmt.Errorf("unexpected fixed-path read")
		}
		return json.Marshal(v)
	})
	g, err := acquire.Acquire(context.Background(), client, acquire.Approved{Repository: testTarget.Repository, DefaultBranch: "main"}, pinnedPath)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func pinnedFixture(t *testing.T) ([]Selection, []Acquired) {
	t.Helper()
	g := acquiredGuidance(t)
	return []Selection{{ID: "guide", Type: "guidance", Locator: "default:" + pinnedPath, Trust: "pinned_guidance", PinnedCommit: pinnedCommit, DefaultBranch: "main"}}, []Acquired{{ID: "guide", Body: append([]byte(nil), g.Body...), AcquiredAt: testTime, Complete: true, Stable: true, Guidance: &g}}
}

func TestWitnessRefusal(t *testing.T) {
	tests := map[string]func([]Selection, []Acquired){
		"body mismatch":   func(_ []Selection, a []Acquired) { a[0].Body = []byte("different") },
		"commit mismatch": func(s []Selection, _ []Acquired) { s[0].PinnedCommit = strings.Repeat("b", 40) },
		"missing branch":  func(s []Selection, _ []Acquired) { s[0].DefaultBranch = "" },
		"branch mismatch": func(s []Selection, _ []Acquired) { s[0].DefaultBranch = "release" },
		"path mismatch":   func(s []Selection, _ []Acquired) { s[0].Locator = "default:AGENTS.md" },
		"missing witness": func(_ []Selection, a []Acquired) { a[0].Guidance = nil },
		"witness repository": func(_ []Selection, a []Acquired) {
			g := *a[0].Guidance
			g.Witness.Repository = "Other/repo"
			a[0].Guidance = &g
		},
		"witness commit": func(_ []Selection, a []Acquired) {
			g := *a[0].Guidance
			g.Witness.Commit = strings.Repeat("b", 40)
			a[0].Guidance = &g
		},
		"witness path": func(_ []Selection, a []Acquired) {
			g := *a[0].Guidance
			g.Witness.Path = "AGENTS.md"
			a[0].Guidance = &g
		},
		"changed witness bytes": func(_ []Selection, a []Acquired) {
			copyBody := append([]byte(nil), a[0].Guidance.Body...)
			copyBody[0] = '!'
			a[0].Guidance.Body = copyBody
			a[0].Body = copyBody
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			s, a := pinnedFixture(t)
			mutate(s, a)
			if _, err := Build(testTarget, s, a, Limits{}); err == nil {
				t.Fatal("accepted provenance mismatch")
			}
		})
	}
	s, a := pinnedFixture(t)
	other := testTarget
	other.Repository = "DifferentOrg/syn"
	if _, err := Build(other, s, a, Limits{}); err == nil {
		t.Fatal("accepted repo mismatch")
	}
	s, a = pinnedFixture(t)
	s[0].Trust = "untrusted"
	s[0].PinnedCommit = ""
	s[0].DefaultBranch = ""
	if _, err := Build(testTarget, s, a, Limits{}); err == nil {
		t.Fatal("witness on untrusted source")
	}
}

func TestWitnessCannotBeReconstructed(t *testing.T) {
	s, a := pinnedFixture(t)
	original := a[0].Guidance
	// The public witness fields and blob digest are insufficient to reconstruct
	// the private provenance seal set by acquire.Acquire.
	forged := acquire.Guidance{Body: append([]byte(nil), original.Body...), Witness: original.Witness}
	a[0].Guidance = &forged
	if _, err := Build(testTarget, s, a, Limits{}); err == nil {
		t.Fatal("accepted manually constructed witness")
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded acquire.Guidance
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	a[0].Guidance = &decoded
	if _, err := Build(testTarget, s, a, Limits{}); err == nil {
		t.Fatal("accepted serialized witness")
	}
}

func unverifiedWitness() *acquire.Guidance { return &acquire.Guidance{} }

func TestBranchBoundToSnapshotHash(t *testing.T) {
	s, a := pinnedFixture(t)
	snapshot, err := Build(testTarget, s, a, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if err = snapshot.Verify(); err != nil {
		t.Fatal(err)
	}
	snapshot.branches["guide"] = "different"
	if err = snapshot.Verify(); err == nil {
		t.Fatal("snapshot hash omitted approved branch")
	}
}
