// SPDX-License-Identifier: AGPL-3.0-or-later

package contracts

import (
	"encoding/json"
	"strings"
	"testing"
)

const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digest2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func target() Target { return Target{Repository: "owner/repo", Kind: "issue", Number: 12} }
func trigger() Trigger {
	return Trigger{DeliveryID: "delivery-1", Event: "issues", Action: "opened", InstallationID: 1, ActorID: 2}
}
func safety() SafetyResult {
	return SafetyResult{SchemaVersion: 1, SnapshotHash: digest, GateVersion: "g1", Outcome: "pass", Findings: []Finding{}}
}
func decision() ReviewDecision {
	return ReviewDecision{SchemaVersion: 1, SnapshotHash: digest, Verdict: "no_findings", Findings: []Finding{}}
}
func runner() Runner {
	return Runner{Name: "fake", Version: "v1", Provider: "local", Model: "fake", Adapter: "fake", AdapterVersion: "v1"}
}
func contextFixture() ProjectContextManifest {
	return ProjectContextManifest{SchemaVersion: 1, Target: target(), SnapshotHash: digest, BundleHash: digest2, TruncationReasons: []string{}, Entries: []ContextEntry{
		{SourceID: "a", Origin: "admitted_source", Trust: "untrusted", Version: "commit:abc", ContentHash: digest, Retention: "attempt_only"},
		{SourceID: "policy:p1", Origin: "policy", Trust: "policy", Version: "p1", ContentHash: digest2, Retention: "retained_reference"},
		{SourceID: "profile:r1", Origin: "profile", Trust: "policy", Version: "r1", ContentHash: digest2, Retention: "retained_reference"},
	}, Prior: PriorRecordProjection{SchemaVersion: 1, Target: target(), Records: []PriorRecordRef{}, TruncationReasons: []string{}}}
}
func record() CanonicalRecord {
	d, r := decision(), runner()
	ctx := contextFixture()
	return CanonicalRecord{Context: &ctx, ContextBundleHash: ctx.BundleHash, SchemaVersion: 1, RecordID: digest2, Target: target(), Trigger: trigger(), ManifestHash: digest, SnapshotHash: digest, PolicyVersion: "p1", ProfileVersion: "r1", GateVersion: "g1", Safety: safety(), Ownership: &ResolvedOwnership{ReviewOwnerID: "team:maintainers", PublisherAppID: 7}, TerminalErrorClass: "none", Decision: &d, Runner: &r, PublicationIntent: "advisory_comment", RuntimeOutcome: "reviewed"}
}
func manifest() SourceManifest {
	return SourceManifest{SchemaVersion: 1, Target: target(), SnapshotHash: digest, Sources: []SourceEntry{{ID: "a", Type: "issue", Locator: "issue:12", Trust: "untrusted", Bytes: 10, ContentHash: digest, AcquiredAt: "2026-10-13T00:00:00Z"}}}
}
func publication() PublicationReceipt {
	return PublicationReceipt{SchemaVersion: 1, RecordID: digest2, Target: target(), SnapshotHash: digest, Operation: "create", IdempotencyKey: digest2, Attempt: 1, CommentID: 123, CommentURL: "https://github.com/owner/repo/issues/12#issuecomment-123", ResponseClass: "success", Outcome: "succeeded"}
}
func TestRoundTripAllContracts(t *testing.T) {
	for name, fn := range map[string]func() error{
		"manifest": func() error { return roundTrip(manifest()) },
		"safety":   func() error { return roundTrip(safety()) },
		"decision": func() error { return roundTrip(decision()) },
		"record":   func() error { return roundTrip(record()) },
		"delivery": func() error {
			return roundTrip(DeliveryReceipt{SchemaVersion: 1, Target: target(), Trigger: trigger(), Outcome: "accepted"})
		},
		"publication": func() error { return roundTrip(publication()) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := fn(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func roundTrip[T Validatable](v T) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	_, e = Decode[T](b)
	return e
}
func reject[T Validatable](t *testing.T, v T) {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode[T](b); e == nil {
		t.Fatalf("accepted %s", b)
	}
}
func TestGuidanceTrustPartition(t *testing.T) {
	for _, tc := range []struct {
		name, locator, trust string
	}{
		{name: "pinned default branch", locator: "default:AGENTS.md", trust: "pinned_guidance"},
		{name: "untrusted PR branch", locator: "pr:42:AGENTS.md", trust: "untrusted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := manifest()
			m.Sources[0].Type = "guidance"
			m.Sources[0].Locator = tc.locator
			m.Sources[0].Trust = tc.trust
			if tc.trust == "pinned_guidance" {
				m.Sources[0].PinnedCommit = strings.Repeat("a", 40)
			}
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := Decode[SourceManifest](b)
			if err != nil {
				t.Fatal(err)
			}
			if got := decoded.Sources[0].Trust; got != tc.trust {
				t.Fatalf("trust changed from %q to %q", tc.trust, got)
			}
		})
	}
	m := manifest()
	m.Sources[0].Trust = "pinned_guidance"
	reject(t, m) // A non-guidance source cannot be promoted to pinned guidance.
	m.Sources[0].Type = "guidance"
	m.Sources[0].Locator = "pr:42:AGENTS.md"
	m.Sources[0].PinnedCommit = strings.Repeat("a", 40)
	reject(t, m) // An untrusted branch cannot claim pinned guidance.
	m.Sources[0].Locator = "default:AGENTS.md"
	m.Sources[0].PinnedCommit = "unverified"
	reject(t, m) // Pinning requires an immutable commit identifier.
}

func TestUnsafeTargetAndSafetyCannotAuthorizePublication(t *testing.T) {
	for _, repo := range []string{"../..", "owner/..", "../repo", "-bad/repo", "owner/."} {
		m := manifest()
		m.Target.Repository = repo
		reject(t, m)
		r := record()
		r.Target.Repository = repo
		reject(t, r)
		p := publication()
		p.Target.Repository = repo
		reject(t, p)
	}
	for _, class := range []string{"secret", "scanner_error", "security_report", "prompt_injection", "unsupported_content"} {
		for _, outcome := range []string{"pass", "pass_with_redactions"} {
			s := safety()
			s.Outcome = outcome
			s.Findings = []Finding{{Class: class, SourceID: "a", ReferenceHash: digest}}
			reject(t, s)
			r := record()
			r.Safety = s
			reject(t, r)
		}
	}
	s := safety()
	s.Outcome = "pass_with_redactions"
	s.Findings = []Finding{{Class: "redaction", SourceID: "a", ReferenceHash: digest}}
	if err := roundTrip(s); err != nil {
		t.Fatal(err)
	}
}

func TestVersionAndIdentityRejection(t *testing.T) {
	m := manifest()
	m.SchemaVersion = 2
	reject(t, m)
	s := safety()
	s.SchemaVersion = 0
	reject(t, s)
	d := decision()
	d.SchemaVersion = 2
	reject(t, d)
	r := record()
	r.SchemaVersion = 2
	reject(t, r)
	dr := DeliveryReceipt{SchemaVersion: 2, Target: target(), Trigger: trigger(), Outcome: "accepted"}
	reject(t, dr)
	pr := publication()
	pr.SchemaVersion = 2
	reject(t, pr)
	r = record()
	r.Trigger.DeliveryID = ""
	reject(t, r)
	r = record()
	r.Target.Repository = ""
	reject(t, r)
	r = record()
	r.Safety.SnapshotHash = digest2
	reject(t, r)
	r = record()
	r.Decision.SnapshotHash = digest2
	reject(t, r)
	m = manifest()
	m.Sources[0].ContentHash = "bad"
	reject(t, m)
	m = manifest()
	m.Sources[0].Locator = "https://example.test/?token=hidden"
	reject(t, m)
}
func TestFailClosedStates(t *testing.T) {
	s := safety()
	s.Outcome = "maybe"
	reject(t, s)
	d := decision()
	d.Verdict = "merge"
	reject(t, d)
	d = decision()
	d.Findings = []Finding{{Class: "secret", SourceID: "a", ReferenceHash: digest}}
	reject(t, d)
	r := record()
	r.Safety.Outcome = "quarantine"
	reject(t, r)
	r = record()
	r.Safety.Outcome = "refuse"
	r.Context, r.ContextBundleHash = nil, ""
	r.Decision = nil
	r.Runner = nil
	r.Ownership = nil
	r.TerminalErrorClass = "safety"
	r.PublicationIntent = "none"
	r.RuntimeOutcome = "refused"
	if err := roundTrip(r); err != nil {
		t.Fatal(err)
	}
	dr := DeliveryReceipt{SchemaVersion: 1, Target: target(), Trigger: trigger(), Outcome: "accepted"}
	dr.Trigger.Action = "merge"
	reject(t, dr)
	pr := publication()
	pr.Operation = "delete"
	reject(t, pr)
	pr = publication()
	pr.Outcome = "uncertain"
	reject(t, pr)
	pr = publication()
	pr.CommentID = 0
	reject(t, pr)
	pr = publication()
	pr.CommentURL = "https://evil.test/?token=secret"
	reject(t, pr)
	pr = publication()
	pr.Outcome = "blocked"
	reject(t, pr)
	pr = publication()
	pr.Outcome, pr.ResponseClass, pr.CommentID, pr.CommentURL = "uncertain", "unknown", 0, ""
	if err := roundTrip(pr); err != nil {
		t.Fatal(err)
	}
	s = safety()
	s.Outcome = "pass_with_redactions"
	reject(t, s)
	r = record()
	r.Target.Kind = "pull_request"
	reject(t, r)
	m := manifest()
	m.Sources = append(m.Sources, m.Sources[0])
	reject(t, m)
	m = manifest()
	m.Sources[0].AcquiredAt = "yesterday"
	reject(t, m)
}
func TestCanonicalRecordMetadata(t *testing.T) {
	n := uint64(0)
	tokens := uint64(42)
	cost := uint64(17)
	r := record()
	r.Assessment = &DecisionAssessment{EngineID: "classifier", EngineVersion: "v1", Disposition: "abstain"}
	r.RunnerMetrics = &RunnerMetrics{LatencyMillis: &n, InputTokens: &tokens, CostMicrosUSD: &cost}
	if err := roundTrip(r); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CanonicalRecord){
		"missing ownership":            func(r *CanonicalRecord) { r.Ownership = nil },
		"invalid owner":                func(r *CanonicalRecord) { r.Ownership.ReviewOwnerID = "owner with spaces" },
		"invalid app":                  func(r *CanonicalRecord) { r.Ownership.PublisherAppID = 0 },
		"assessment instruction":       func(r *CanonicalRecord) { r.Assessment.Disposition = "publish" },
		"assessment missing engine":    func(r *CanonicalRecord) { r.Assessment.EngineID = "" },
		"held reviewed run":            func(r *CanonicalRecord) { r.Assessment.Disposition = "hold" },
		"empty metrics":                func(r *CanonicalRecord) { r.RunnerMetrics = &RunnerMetrics{} },
		"excess tokens":                func(r *CanonicalRecord) { over := uint64(10_000_001); r.RunnerMetrics.InputTokens = &over },
		"excess latency":               func(r *CanonicalRecord) { over := uint64(86_400_001); r.RunnerMetrics.LatencyMillis = &over },
		"excess cost":                  func(r *CanonicalRecord) { over := uint64(10_000_000_001); r.RunnerMetrics.CostMicrosUSD = &over },
		"missing runner metrics owner": func(r *CanonicalRecord) { r.Runner = nil },
		"unknown class":                func(r *CanonicalRecord) { r.TerminalErrorClass = "provider output" },
		"reviewed error":               func(r *CanonicalRecord) { r.TerminalErrorClass = "runner" },
	} {
		t.Run(name, func(t *testing.T) {
			v := r
			owner := *r.Ownership
			assessment := *r.Assessment
			metrics := *r.RunnerMetrics
			v.Ownership = &owner
			v.Assessment = &assessment
			v.RunnerMetrics = &metrics
			change(&v)
			reject(t, v)
		})
	}
	// Disabled decision engine leaves no assessment and does not block a review.
	if err := roundTrip(record()); err != nil {
		t.Fatal(err)
	}
}
func TestRestrictedAndFailedRecords(t *testing.T) {
	r := record()
	r.Assessment = &DecisionAssessment{EngineID: "classifier", EngineVersion: "v1", Disposition: "hold"}
	r.Decision = nil
	r.Runner = nil
	r.PublicationIntent = "none"
	r.RuntimeOutcome = "decision_restricted"
	r.Context, r.ContextBundleHash = nil, ""
	if err := roundTrip(r); err != nil {
		t.Fatal(err)
	}
	r.PublicationIntent = "advisory_comment"
	reject(t, r)
	r = record()
	r.Decision = nil
	r.PublicationIntent = "none"
	r.RuntimeOutcome = "runner_failed"
	r.TerminalErrorClass = "schema"
	if err := roundTrip(r); err != nil {
		t.Fatal(err)
	}
	r.TerminalErrorClass = "none"
	reject(t, r)
}
func TestPolicyAndAmbiguityTerminalClasses(t *testing.T) {
	for _, class := range []string{"policy", "ambiguity", "infrastructure"} {
		t.Run(class, func(t *testing.T) {
			r := record()
			r.Decision = nil
			r.Runner = nil
			r.Ownership = nil
			r.PublicationIntent = "none"
			r.RuntimeOutcome = "blocked"
			r.Context, r.ContextBundleHash = nil, ""
			r.TerminalErrorClass = class
			if err := roundTrip(r); err != nil {
				t.Fatal(err)
			}
			r.PublicationIntent = "advisory_comment"
			reject(t, r)
			r.PublicationIntent = "none"
			r.TerminalErrorClass = "safety"
			reject(t, r)
		})
	}
}

func TestStoppedSafetyRecordMinimal(t *testing.T) {
	for _, outcome := range []string{"refuse", "quarantine"} {
		t.Run(outcome, func(t *testing.T) {
			r := record()
			r.Safety.Outcome = outcome
			r.Context, r.ContextBundleHash = nil, ""
			r.Decision = nil
			r.Runner = nil
			r.Ownership = nil
			r.PublicationIntent = "none"
			r.TerminalErrorClass = "safety"
			if outcome == "refuse" {
				r.RuntimeOutcome = "refused"
			} else {
				r.RuntimeOutcome = "quarantined"
			}
			if err := roundTrip(r); err != nil {
				t.Fatal(err)
			}
			r.Assessment = &DecisionAssessment{EngineID: "classifier", EngineVersion: "v1", Disposition: "hold"}
			reject(t, r)
			r.Assessment = nil
			r.RunnerMetrics = &RunnerMetrics{InputTokens: new(uint64)}
			reject(t, r)
			r.RunnerMetrics = nil
			r.Ownership = &ResolvedOwnership{ReviewOwnerID: "maintainers", PublisherAppID: 7}
			reject(t, r)
			r.Ownership = nil
			r.TerminalErrorClass = "none"
			reject(t, r)
		})
	}
}
func TestMetadataStrictJSON(t *testing.T) {
	r := record()
	r.Assessment = &DecisionAssessment{EngineID: "classifier", EngineVersion: "v1", Disposition: "abstain"}
	r.RunnerMetrics = &RunnerMetrics{InputTokens: new(uint64)}
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	for name, bad := range map[string]string{
		"unknown assessment field": strings.Replace(string(b), `"disposition":"abstain"`, `"disposition":"abstain","instruction":"override"`, 1),
		"unknown metrics field":    strings.Replace(string(b), `"input_tokens":0`, `"input_tokens":0,"provider_output":"raw"`, 1),
		"negative tokens":          strings.Replace(string(b), `"input_tokens":0`, `"input_tokens":-1`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode[CanonicalRecord]([]byte(bad)); err == nil {
				t.Fatal("accepted invalid metadata")
			}
		})
	}
}

func TestStrictDecode(t *testing.T) {
	b, e := json.Marshal(record())
	if e != nil {
		t.Fatal(e)
	}
	for name, bad := range map[string]string{
		"top unknown":      strings.Replace(string(b), `"record_id":`, `"raw_content":"private","record_id":`, 1),
		"case alias":       strings.Replace(string(b), `"record_id":`, `"Record_ID":`, 1),
		"nested unknown":   strings.Replace(string(b), `"outcome":"pass"`, `"outcome":"pass","secret":"private"`, 1),
		"capability":       strings.Replace(string(b), `"verdict":"no_findings"`, `"verdict":"no_findings","merge":true`, 1),
		"duplicate":        strings.Replace(string(b), `"record_id":`, `"record_id":"`+digest+`","record_id":`, 1),
		"nested duplicate": strings.Replace(string(b), `"kind":"issue"`, `"kind":"issue","kind":"issue"`, 1),
		"trailing":         string(b) + ` {}`,
		"null":             `null`,
		"array":            `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode[CanonicalRecord]([]byte(bad)); err == nil {
				t.Fatal("accepted malformed JSON")
			}
		})
	}
	if _, err := Decode[CanonicalRecord](make([]byte, 1<<20+1)); err == nil {
		t.Fatal("accepted oversized input")
	}
}
