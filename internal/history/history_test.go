// SPDX-License-Identifier: AGPL-3.0-or-later

package history

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ClawOsirisOrg/syn/internal/contracts"
	"github.com/ClawOsirisOrg/syn/internal/recordstore"
)

const snapshot = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func target() contracts.Target {
	return contracts.Target{Repository: "owner/repo", Kind: "issue", Number: 12}
}

func record(n byte) contracts.CanonicalRecord {
	id := contracts.Hash(strings.Repeat(string(n), 64))
	t := target()
	context := contracts.ProjectContextManifest{
		SchemaVersion: 1, Target: t, SnapshotHash: snapshot, BundleHash: snapshot,
		Entries: []contracts.ContextEntry{
			{SourceID: "a", Origin: "admitted_source", Trust: "untrusted", Version: "v1", ContentHash: snapshot, Retention: "attempt_only"},
			{SourceID: "policy", Origin: "policy", Trust: "policy", Version: "p1", ContentHash: snapshot, Retention: "attempt_only"},
			{SourceID: "profile", Origin: "profile", Trust: "policy", Version: "r1", ContentHash: snapshot, Retention: "attempt_only"},
		},
		TruncationReasons: []string{}, Prior: contracts.PriorRecordProjection{
			SchemaVersion: 1, Target: t, Records: []contracts.PriorRecordRef{}, TruncationReasons: []string{},
		},
	}
	return contracts.CanonicalRecord{
		SchemaVersion: 1, RecordID: id, Target: t,
		Trigger:      contracts.Trigger{DeliveryID: "delivery", Event: "issues", Action: "opened", InstallationID: 1, ActorID: 2},
		ManifestHash: snapshot, SnapshotHash: snapshot, Context: &context, ContextBundleHash: snapshot,
		PolicyVersion: "p1", ProfileVersion: "r1", GateVersion: "g1",
		Safety:             contracts.SafetyResult{SchemaVersion: 1, SnapshotHash: snapshot, GateVersion: "g1", Outcome: "pass", Findings: []contracts.Finding{}},
		Ownership:          &contracts.ResolvedOwnership{ReviewOwnerID: "team", PublisherAppID: 5},
		TerminalErrorClass: "none", PublicationIntent: "advisory_comment", RuntimeOutcome: "reviewed",
		Decision: &contracts.ReviewDecision{SchemaVersion: 1, SnapshotHash: snapshot, Verdict: "no_findings", Findings: []contracts.Finding{}},
		Runner:   &contracts.Runner{Name: "fake", Version: "v1", Provider: "local", Model: "fake", Adapter: "fake", AdapterVersion: "v1"},
	}
}

func setup(t *testing.T) (*recordstore.Store, string) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := recordstore.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func put(t *testing.T, s *recordstore.Store, r contracts.CanonicalRecord) {
	t.Helper()
	if err := s.Put(r); err != nil {
		t.Fatal(err)
	}
}

func stopped(r contracts.CanonicalRecord, outcome string) contracts.CanonicalRecord {
	r.Context, r.Decision, r.Runner, r.Ownership = nil, nil, nil, nil
	r.ContextBundleHash = ""
	r.PublicationIntent = "none"
	r.RuntimeOutcome = outcome
	r.TerminalErrorClass = "safety"
	r.Safety.Outcome = "refuse"
	if outcome == "quarantined" {
		r.Safety.Outcome = "quarantine"
	}
	return r
}

func TestProjectionOrderHashAndEvidenceTrust(t *testing.T) {
	s, _ := setup(t)
	old := stopped(record('1'), "refused")
	newer := record('2')
	// A canonical finding's source ID is syntactically valid but can be a
	// private URL or a credential-looking string. Neither is safe to replay.
	secret := "https://private.example/token/ghp_SUPERSECRET"
	newer.Context.Entries[0].Version = "private-source-locator-ghp_SUPERSECRET"
	newer.Runner.Model = "private-runner-metadata-ghp_SUPERSECRET"
	newer.Decision.Verdict = "findings"
	newer.Decision.Findings = []contracts.Finding{{Class: "review_issue", SourceID: secret, ReferenceHash: snapshot}}
	newest := stopped(record('3'), "quarantined")
	for _, r := range []contracts.CanonicalRecord{old, newer, newest} {
		put(t, s, r)
	}
	ids := []contracts.Hash{newest.RecordID, newer.RecordID, old.RecordID}
	p, entries, err := Project(s, target(), 3, ids)
	if err != nil {
		t.Fatal(err)
	}
	if p.CompletedCycles != 3 || p.OmittedCycles != 0 || p.Truncated || !reflect.DeepEqual(p.TruncationReasons, []string{}) {
		t.Fatalf("coverage: %+v", p)
	}
	for i, id := range ids {
		if p.Records[i].RecordID != id {
			t.Fatalf("unexpected order: %+v", p.Records)
		}
	}
	if p.Records[0].Verdict != "" || len(p.Records[0].Findings) != 0 || p.Records[2].Verdict != "" {
		t.Fatalf("stopped cycles gained findings: %+v", p)
	}
	got := p.Records[1].Findings[0].SourceID
	wantBytes := sha256.Sum256([]byte("syn-prior-source-v1\x00" + string(newer.RecordID) + "\x00" + secret))
	if got != "prior:"+hex.EncodeToString(wantBytes[:]) {
		t.Fatalf("unstable opaque source ref: %q", got)
	}
	if len(entries) != 3 || entries[0].SourceID != string(old.RecordID) || entries[2].SourceID != string(newest.RecordID) {
		t.Fatalf("entries not sorted: %+v", entries)
	}
	for _, e := range entries {
		if e.Trust != "prior_record" || e.Origin != "prior_record" || e.Retention != "retained_reference" || e.Version != e.SourceID || e.Repository != "" {
			t.Fatalf("evidence promoted: %+v", e)
		}
	}
	b, _ := json.Marshal(newer)
	digest := sha256.Sum256(b)
	if entries[1].ContentHash != contracts.Hash(hex.EncodeToString(digest[:])) {
		t.Fatal("entry content hash not canonical record hash")
	}
	a, _ := json.Marshal(struct {
		P contracts.PriorRecordProjection
		E []contracts.ContextEntry
	}{p, entries})
	if bytes.Contains(a, []byte(secret)) || bytes.Contains(a, []byte("ghp_")) || bytes.Contains(a, []byte("private.example")) || bytes.Contains(a, []byte("private-runner")) {
		t.Fatal("private source ID retained")
	}
	p2, e2, err := Project(s, target(), 3, ids)
	if err != nil || !reflect.DeepEqual(p, p2) || !reflect.DeepEqual(entries, e2) {
		t.Fatalf("projection not deterministic: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOmissionCoverageAndEmpty(t *testing.T) {
	s, _ := setup(t)
	p, e, err := Project(s, target(), 0, nil)
	if err != nil || len(e) != 0 || p.Records == nil || p.TruncationReasons == nil || p.Validate() != nil {
		t.Fatalf("empty coverage: %+v %v", p, err)
	}
	ids := make([]contracts.Hash, 0, 8)
	for n := byte('1'); n <= '8'; n++ {
		r := stopped(record(n), "refused")
		put(t, s, r)
		ids = append(ids, r.RecordID)
	}
	p, e, err = Project(s, target(), 1_000_000, ids)
	if err != nil || len(e) != 8 || len(p.Records) != 8 || p.OmittedCycles != 999_992 || !p.Truncated || !reflect.DeepEqual(p.TruncationReasons, []string{"cycles"}) || p.Validate() != nil {
		t.Fatalf("truncated coverage: %+v %v", p, err)
	}
}

func TestRejectBadInputsAndNoPartialOutput(t *testing.T) {
	s, path := setup(t)
	r := record('b')
	put(t, s, r)
	id := r.RecordID
	other := target()
	other.Number++
	for name, tc := range map[string]struct {
		store  *recordstore.Store
		target contracts.Target
		count  uint32
		ids    []contracts.Hash
	}{
		"nil store":                       {nil, target(), 1, []contracts.Hash{id}},
		"wrong target":                    {s, other, 1, []contracts.Hash{id}},
		"invalid target with empty count": {s, contracts.Target{}, 0, nil},
		"insufficient IDs":                {s, target(), 1, nil},
		"extra IDs":                       {s, target(), 0, []contracts.Hash{id}},
		"inconsistent count":              {s, target(), 9, []contracts.Hash{id}},
		"excessive count":                 {s, target(), 1_000_001, []contracts.Hash{id}},
		"duplicate IDs":                   {s, target(), 2, []contracts.Hash{id, id}},
		"malformed ID":                    {s, target(), 1, []contracts.Hash{"not-a-hash"}},
		"missing ID":                      {s, target(), 1, []contracts.Hash{snapshot}},
	} {
		t.Run(name, func(t *testing.T) {
			p, e, err := Project(tc.store, tc.target, tc.count, tc.ids)
			if err == nil || len(e) != 0 || p.Records != nil {
				t.Fatalf("accepted invalid input: %+v %+v %v", p, e, err)
			}
		})
	}
	// Store.Get must reject malformed persisted bytes; do not bypass it.
	if err := os.WriteFile(filepath.Join(path, string(id)+".json"), []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if p, e, err := Project(s, target(), 1, []contracts.Hash{id}); err == nil || p.Records != nil || e != nil {
		t.Fatalf("accepted corrupt record: %+v %+v %v", p, e, err)
	}
}

func TestRejectOversizedFindingsAndUnsupportedOutcome(t *testing.T) {
	s, _ := setup(t)
	r := record('c')
	r.Decision.Verdict = "findings"
	for i := 0; i < 11; i++ {
		r.Decision.Findings = append(r.Decision.Findings, contracts.Finding{Class: "review_issue", SourceID: "source", ReferenceHash: snapshot})
	}
	put(t, s, r) // Canonical record allows more than the projection's bound.
	if p, e, err := Project(s, target(), 1, []contracts.Hash{r.RecordID}); err == nil || p.Records != nil || e != nil {
		t.Fatalf("accepted oversized findings: %+v %+v %v", p, e, err)
	}
	r = record('d')
	r.Context, r.Decision, r.Runner = nil, nil, nil
	r.ContextBundleHash = ""
	r.Assessment = &contracts.DecisionAssessment{EngineID: "engine", EngineVersion: "1", Disposition: "hold"}
	r.RuntimeOutcome, r.PublicationIntent = "decision_restricted", "none"
	put(t, s, r)
	if p, e, err := Project(s, target(), 1, []contracts.Hash{r.RecordID}); err == nil || p.Records != nil || e != nil {
		t.Fatalf("misrepresented unsupported state: %+v %+v %v", p, e, err)
	}
}

func TestOtherStoppedStatesRemainEvidenceOnly(t *testing.T) {
	s, _ := setup(t)
	blocked := record('e')
	blocked.Context, blocked.Decision, blocked.Runner = nil, nil, nil
	blocked.ContextBundleHash = ""
	blocked.RuntimeOutcome, blocked.PublicationIntent, blocked.TerminalErrorClass = "blocked", "none", "policy"
	put(t, s, blocked)
	failed := record('f')
	failed.Decision = nil
	failed.RuntimeOutcome, failed.PublicationIntent, failed.TerminalErrorClass = "runner_failed", "none", "runner"
	put(t, s, failed)
	p, e, err := Project(s, target(), 2, []contracts.Hash{failed.RecordID, blocked.RecordID})
	if err != nil || p.Validate() != nil || len(e) != 2 {
		t.Fatalf("stopped projection: %+v %+v %v", p, e, err)
	}
	for _, ref := range p.Records {
		if ref.Verdict != "" || ref.Findings == nil || len(ref.Findings) != 0 {
			t.Fatalf("fabricated stopped review: %+v", ref)
		}
	}
}
