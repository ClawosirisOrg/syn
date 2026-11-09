// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClawOsirisOrg/syn/internal/contracts"
	"github.com/ClawOsirisOrg/syn/internal/recordstore"
)

const recID contracts.Hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const snapshot contracts.Hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const bundle contracts.Hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func fixture() contracts.CanonicalRecord {
	target := contracts.Target{Repository: "Owner/Repo", Kind: "issue", Number: 12}
	ctx := &contracts.ProjectContextManifest{
		SchemaVersion: 1, Target: target, SnapshotHash: snapshot, BundleHash: bundle,
		Entries: []contracts.ContextEntry{
			{SourceID: "a", Origin: "admitted_source", Trust: "untrusted", Version: "v1", ContentHash: snapshot, Retention: "attempt_only"},
			{SourceID: "policy:p1", Origin: "policy", Trust: "policy", Version: "p1", ContentHash: snapshot, Retention: "retained_reference"},
			{SourceID: "profile:v1", Origin: "profile", Trust: "policy", Version: "v1", ContentHash: snapshot, Retention: "retained_reference"},
		}, TruncationReasons: []string{},
		Prior: contracts.PriorRecordProjection{SchemaVersion: 1, Target: target, Records: []contracts.PriorRecordRef{}, TruncationReasons: []string{}},
	}
	return contracts.CanonicalRecord{
		SchemaVersion: 1, RecordID: recID, Target: target,
		Trigger:      contracts.Trigger{DeliveryID: "d1", Event: "issues", Action: "opened", InstallationID: 1, ActorID: 2},
		ManifestHash: snapshot, ContextBundleHash: bundle, Context: ctx, SnapshotHash: snapshot,
		PolicyVersion: "p1", ProfileVersion: "v1", GateVersion: "g1",
		Safety:             contracts.SafetyResult{SchemaVersion: 1, SnapshotHash: snapshot, GateVersion: "g1", Outcome: "pass", Findings: []contracts.Finding{}},
		Ownership:          &contracts.ResolvedOwnership{ReviewOwnerID: "team:maintainers", PublisherAppID: 7},
		TerminalErrorClass: "none", PublicationIntent: "advisory_comment", RuntimeOutcome: "reviewed",
		Decision: &contracts.ReviewDecision{SchemaVersion: 1, SnapshotHash: snapshot, Verdict: "no_findings", Findings: []contracts.Finding{}},
		Runner:   &contracts.Runner{Name: "fixture", Version: "v1", Provider: "local", Model: "fixture", Adapter: "fixture", AdapterVersion: "v1"},
	}
}
func newStore(t *testing.T) (*recordstore.Store, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := recordstore.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}
func TestStableStoredPreview(t *testing.T) {
	s, _ := newStore(t)
	r := fixture()
	if err := s.Put(r); err != nil {
		t.Fatal(err)
	}
	first, err := CreatePreview(s, recID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CreatePreview(s, recID)
	if err != nil || first != second {
		t.Fatalf("unstable: %v", err)
	}
	expectedHash := sha256.Sum256([]byte("owner/repo#12"))
	expected := "<!-- syn-review:v1 key=" + hex.EncodeToString(expectedHash[:]) + " -->"
	if first.Marker != expected || strings.Count(first.Body, expected) != 1 || first.RecordID != recID {
		t.Fatalf("marker mismatch: %+v", first)
	}
	if !strings.Contains(first.Body, "advisory feedback") || !strings.Contains(first.Body, "Schema version: 1") || !strings.Contains(first.Body, string(snapshot)) || len(first.Body) > maxBodyBytes {
		t.Fatalf("missing metadata or unbounded body: %q", first.Body)
	}
	other := r.Target
	other.Repository = "owner/repo"
	other.Kind = "pull_request"
	if markerFor(other) != first.Marker {
		t.Fatal("case or item kind changed marker")
	}
	other.Number++
	if markerFor(other) == first.Marker {
		t.Fatal("item identity did not change marker")
	}
}
func TestOnlyCountsNotSpoofableFields(t *testing.T) {
	s, _ := newStore(t)
	r := fixture()
	r.Target.Repository = "Private.Host/SecretRepo"
	r.Context.Target = r.Target
	r.Context.Prior.Target = r.Target
	r.Trigger.DeliveryID = "private.host/receiver"
	r.Runner.Provider = "private.host/receiver"
	r.Runner.Model = "token_like_secret"
	r.Ownership.ReviewOwnerID = "private.host/owner"
	r.PolicyVersion = "private.host/policy"
	r.Context.Entries[1].Version = r.PolicyVersion
	r.Decision.Verdict = "findings"
	r.Decision.Findings = []contracts.Finding{{Class: "review_issue", SourceID: "private.host/source", ReferenceHash: snapshot}}
	r.Safety.Outcome = "pass_with_redactions"
	r.Safety.Findings = []contracts.Finding{{Class: "redaction", SourceID: "private.host/source", ReferenceHash: snapshot}}
	if err := s.Put(r); err != nil {
		t.Fatal(err)
	}
	p, err := CreatePreview(s, recID)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"private.host", "SecretRepo", "token_like_secret", "source", "receiver", "Owner"} {
		if strings.Contains(p.Body, bad) {
			t.Fatalf("leaked %q", bad)
		}
	}
	if !strings.Contains(p.Body, "Review issue findings: 1") || !strings.Contains(p.Body, "Redaction findings: 1") {
		t.Fatal("finding counts missing")
	}
}
func TestUnsafeRecordsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*contracts.CanonicalRecord)
	}{
		{"quarantined", func(r *contracts.CanonicalRecord) {
			r.Safety.Outcome = "quarantine"
			r.RuntimeOutcome = "quarantined"
			stop(r)
		}},
		{"refused", func(r *contracts.CanonicalRecord) { r.Safety.Outcome = "refuse"; r.RuntimeOutcome = "refused"; stop(r) }},
		{"runner_failed", func(r *contracts.CanonicalRecord) {
			r.RuntimeOutcome = "runner_failed"
			r.TerminalErrorClass = "runner"
			r.Decision = nil
			r.PublicationIntent = "none"
		}},
		{"blocked", func(r *contracts.CanonicalRecord) {
			r.RuntimeOutcome = "blocked"
			r.TerminalErrorClass = "policy"
			r.Decision = nil
			r.Runner = nil
			r.Context = nil
			r.ContextBundleHash = ""
			r.PublicationIntent = "none"
		}},
		{"held", func(r *contracts.CanonicalRecord) {
			r.RuntimeOutcome = "decision_restricted"
			r.Assessment = &contracts.DecisionAssessment{EngineID: "disabled", EngineVersion: "v1", Disposition: "hold"}
			r.Decision = nil
			r.Runner = nil
			r.Context = nil
			r.ContextBundleHash = ""
			r.PublicationIntent = "none"
		}},
		{"no_intent", func(r *contracts.CanonicalRecord) { r.PublicationIntent = "none" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newStore(t)
			r := fixture()
			tc.mutate(&r)
			if err := s.Put(r); err != nil {
				t.Fatalf("invalid test fixture: %v", err)
			}
			p, err := CreatePreview(s, recID)
			if !errors.Is(err, ErrNotRenderable) || p.Body != "" {
				t.Fatalf("unsafe preview: %+v %v", p, err)
			}
		})
	}
}
func stop(r *contracts.CanonicalRecord) {
	r.TerminalErrorClass = "safety"
	r.Decision = nil
	r.Runner = nil
	r.Context = nil
	r.ContextBundleHash = ""
	r.Ownership = nil
	r.PublicationIntent = "none"
}
func TestMissingCorruptAndInvalidID(t *testing.T) {
	s, dir := newStore(t)
	if p, err := CreatePreview(nil, recID); err == nil || p.Body != "" {
		t.Fatal("nil store accepted")
	}
	if p, err := CreatePreview(s, recID); !errors.Is(err, os.ErrNotExist) || p.Body != "" {
		t.Fatalf("missing: %v", err)
	}
	if p, err := CreatePreview(s, "../bad"); err == nil || p.Body != "" {
		t.Fatal("bad ID accepted")
	}
	r := fixture()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, string(recID)+".json")
	for _, bad := range [][]byte{[]byte("not JSON"), append(data, '\n'), []byte("{}")} {
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if p, err := CreatePreview(s, recID); !errors.Is(err, recordstore.ErrCorrupt) || p.Body != "" {
			t.Fatalf("corrupt: %v", err)
		}
	}
}
