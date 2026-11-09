// SPDX-License-Identifier: AGPL-3.0-or-later

package contracts

import (
	"encoding/json"
	"strings"
	"testing"
)

const priorID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func truncatedContext() ProjectContextManifest {
	m := contextFixture()
	m.Prior.Records = []PriorRecordRef{{RecordID: priorID, SnapshotHash: digest, Disposition: "reviewed", Verdict: "findings", Findings: []Finding{{Class: "review_issue", SourceID: "a", ReferenceHash: digest2}}}}
	m.Prior.CompletedCycles = 3
	m.Prior.OmittedCycles = 2
	m.Prior.Truncated = true
	m.Prior.TruncationReasons = []string{"age", "cycles"}
	m.Truncated = true
	m.TruncationReasons = []string{"history"}
	m.Entries = append([]ContextEntry{m.Entries[0], {SourceID: priorID, Origin: "prior_record", Trust: "prior_record", Version: priorID, ContentHash: digest, Retention: "retained_reference"}}, m.Entries[1:]...)
	return m
}
func TestContextRoundTripAndCoverage(t *testing.T) {
	for _, m := range []ProjectContextManifest{contextFixture(), truncatedContext()} {
		if err := roundTrip(m); err != nil {
			t.Fatal(err)
		}
		if err := roundTrip(m.Prior); err != nil {
			t.Fatal(err)
		}
		r := record()
		r.Context = &m
		r.ContextBundleHash = m.BundleHash
		if err := roundTrip(r); err != nil {
			t.Fatal(err)
		}
	}
}
func TestBundleCoverage(t *testing.T) {
	m := contextFixture()
	m.OmittedEntries = 2
	m.Truncated = true
	m.TruncationReasons = []string{"bytes"}
	if err := roundTrip(m); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ProjectContextManifest){
		"unmarked omission":              func(m *ProjectContextManifest) { m.Truncated = false },
		"missing reason":                 func(m *ProjectContextManifest) { m.TruncationReasons = []string{} },
		"history without prior omission": func(m *ProjectContextManifest) { m.TruncationReasons = []string{"bytes", "history"} },
		"duplicate reason":               func(m *ProjectContextManifest) { m.TruncationReasons = []string{"bytes", "bytes"} },
		"over limit":                     func(m *ProjectContextManifest) { m.OmittedEntries = maxCompletedCycles + 1 },
	} {
		t.Run(name, func(t *testing.T) { v := m; change(&v); reject(t, v) })
	}
	m = truncatedContext()
	m.Truncated = false
	reject(t, m)
	m = truncatedContext()
	m.TruncationReasons = []string{"bytes"}
	reject(t, m)
	m = truncatedContext()
	m.OmittedEntries = 2
	m.TruncationReasons = []string{"bytes", "history"}
	if err := roundTrip(m); err != nil {
		t.Fatal(err)
	}
}

func TestContextTrustBoundaries(t *testing.T) {
	base := contextFixture()
	for name, change := range map[string]func(*ProjectContextManifest){
		"untrusted promoted":    func(m *ProjectContextManifest) { m.Entries[0].Trust = "policy" },
		"private memory origin": func(m *ProjectContextManifest) { m.Entries[0].Origin = "agent_memory" },
		"unbounded text":        func(m *ProjectContextManifest) { m.Entries[0].Version = "untrusted free form text" },
		"unknown trust":         func(m *ProjectContextManifest) { m.Entries[0].Trust = "admin" },
		"wrong guidance scope": func(m *ProjectContextManifest) {
			m.Entries[0] = ContextEntry{SourceID: "a", Origin: "pinned_guidance", Trust: "pinned_guidance", Version: "commit:" + strings.Repeat("a", 40), ContentHash: digest, Retention: "attempt_only", Repository: "other/repo"}
		},
		"unpinned guidance": func(m *ProjectContextManifest) {
			m.Entries[0] = ContextEntry{SourceID: "a", Origin: "pinned_guidance", Trust: "pinned_guidance", Version: "pr:42", ContentHash: digest, Retention: "retained_reference", Repository: target().Repository}
		},
		"prior claimed policy": func(m *ProjectContextManifest) { *m = truncatedContext(); m.Entries[1].Trust = "policy" },
		"duplicate source":     func(m *ProjectContextManifest) { m.Entries = append(m.Entries, m.Entries[1]) },
		"wrong snapshot":       func(m *ProjectContextManifest) { m.SnapshotHash = "not-sha256" },
		"future version":       func(m *ProjectContextManifest) { m.SchemaVersion = 2 },
		"future prior version": func(m *ProjectContextManifest) { m.Prior.SchemaVersion = 2 },
		"too many entries":     func(m *ProjectContextManifest) { m.Entries = make([]ContextEntry, maxContextEntries+1) },
	} {
		t.Run(name, func(t *testing.T) {
			m := base
			m.Entries = append([]ContextEntry(nil), base.Entries...)
			change(&m)
			reject(t, m)
		})
	}
	// Curated knowledge is accepted only when scoped to the same repository.
	m := contextFixture()
	m.Entries = append([]ContextEntry{m.Entries[0], {SourceID: "b", Origin: "maintainer_knowledge", Trust: "curated", Version: "commit:abc", ContentHash: digest, Retention: "retained_reference", Repository: target().Repository}}, m.Entries[1:]...)
	if err := roundTrip(m); err != nil {
		t.Fatal(err)
	}
	// Untrusted branch guidance remains admitted data, not pinned authority.
	m.Entries[0] = ContextEntry{SourceID: "a", Origin: "admitted_source", Trust: "untrusted", Version: "pr:42", ContentHash: digest, Retention: "attempt_only"}
	if err := roundTrip(m); err != nil {
		t.Fatal(err)
	}
	// Pinned guidance needs a matching repository scope and distinct trust.
	m.Entries[1] = ContextEntry{SourceID: "b", Origin: "pinned_guidance", Trust: "pinned_guidance", Version: "commit:" + strings.Repeat("a", 40), ContentHash: digest2, Retention: "retained_reference", Repository: target().Repository}
	if err := roundTrip(m); err != nil {
		t.Fatal(err)
	}
}
func TestStoppedPriorRecordProjection(t *testing.T) {
	m := truncatedContext()
	ref := &m.Prior.Records[0]
	ref.Disposition = "quarantined"
	ref.Verdict = ""
	ref.Findings = []Finding{}
	if err := roundTrip(m); err != nil {
		t.Fatal(err)
	}
	ref.Findings = []Finding{{Class: "review_issue", SourceID: "a", ReferenceHash: digest2}}
	reject(t, m)
	ref.Findings = []Finding{}
	ref.Verdict = "no_findings"
	reject(t, m)
	ref.Verdict = ""
	ref.Disposition = "published"
	reject(t, m)
}

func TestPriorProjectionCoverage(t *testing.T) {
	base := truncatedContext()
	for name, change := range map[string]func(*ProjectContextManifest){
		"omitted count lies":      func(m *ProjectContextManifest) { m.Prior.OmittedCycles = 1 },
		"truncation lies":         func(m *ProjectContextManifest) { m.Prior.Truncated = false },
		"missing reasons":         func(m *ProjectContextManifest) { m.Prior.TruncationReasons = []string{} },
		"duplicate reason":        func(m *ProjectContextManifest) { m.Prior.TruncationReasons = []string{"age", "age"} },
		"unknown reason":          func(m *ProjectContextManifest) { m.Prior.TruncationReasons = []string{"memory"} },
		"missing reference entry": func(m *ProjectContextManifest) { m.Entries = []ContextEntry{m.Entries[0], m.Entries[2], m.Entries[3]} },
		"wrong entry version":     func(m *ProjectContextManifest) { m.Entries[1].Version = "other" },
		"duplicate prior record": func(m *ProjectContextManifest) {
			m.Prior.Records = append(m.Prior.Records, m.Prior.Records[0])
			m.Prior.CompletedCycles++
		},
		"fabricated no findings":    func(m *ProjectContextManifest) { m.Prior.Records[0].Verdict = "no_findings" },
		"raw security finding":      func(m *ProjectContextManifest) { m.Prior.Records[0].Findings[0].Class = "secret" },
		"too many findings":         func(m *ProjectContextManifest) { m.Prior.Records[0].Findings = make([]Finding, maxPriorFindings+1) },
		"wrong item":                func(m *ProjectContextManifest) { m.Prior.Target.Number++ },
		"future projection version": func(m *ProjectContextManifest) { m.Prior.SchemaVersion = 2 },
	} {
		t.Run(name, func(t *testing.T) { m := truncatedContext(); change(&m); reject(t, m) })
	}
	if err := roundTrip(base); err != nil {
		t.Fatal(err)
	}
}
func TestContextRecordLink(t *testing.T) {
	for name, change := range map[string]func(*CanonicalRecord){
		"missing context":          func(r *CanonicalRecord) { r.Context = nil; r.ContextBundleHash = "" },
		"missing bundle hash":      func(r *CanonicalRecord) { r.ContextBundleHash = "" },
		"wrong bundle hash":        func(r *CanonicalRecord) { r.ContextBundleHash = digest },
		"wrong target":             func(r *CanonicalRecord) { r.Context.Target.Number++ },
		"wrong snapshot":           func(r *CanonicalRecord) { r.Context.SnapshotHash = digest2 },
		"policy version mismatch":  func(r *CanonicalRecord) { r.PolicyVersion = "p2" },
		"profile version mismatch": func(r *CanonicalRecord) { r.ProfileVersion = "r2" },
		"self history": func(r *CanonicalRecord) {
			m := truncatedContext()
			r.RecordID = priorID
			r.Context = &m
			r.ContextBundleHash = m.BundleHash
		},
	} {
		t.Run(name, func(t *testing.T) { r := record(); change(&r); reject(t, r) })
	}
	r := record()
	r.Safety.Outcome = "quarantine"
	r.Decision = nil
	r.Runner = nil
	r.Ownership = nil
	r.PublicationIntent = "none"
	r.RuntimeOutcome = "quarantined"
	r.TerminalErrorClass = "safety"
	reject(t, r) // A stopped safety record must omit the review context bundle.
}
func TestNoRawMemoryFields(t *testing.T) {
	m := truncatedContext()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"session":     strings.Replace(string(b), `"bundle_hash":`, `"session":"resume","bundle_hash":`, 1),
		"raw memory":  strings.Replace(string(b), `"retention":"attempt_only"`, `"retention":"attempt_only","raw_agent_memory":"private"`, 1),
		"prior prose": strings.Replace(string(b), `"verdict":"findings"`, `"verdict":"findings","prose":"private"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode[ProjectContextManifest]([]byte(bad)); err == nil {
				t.Fatal("accepted raw or resumable data")
			}
		})
	}
}
