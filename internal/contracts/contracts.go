// SPDX-License-Identifier: AGPL-3.0-or-later

// Package contracts defines metadata-only, version-one JSON boundaries. Call Decode
// on untrusted JSON before using a contract; encoding/json alone does not validate it.
package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const SchemaVersion = 1

// Hash is the lowercase SHA-256 digest of content, not the content itself.
type Hash string

// Target identifies the GitHub conversation; pull requests also use issue comments.
type Target struct {
	Repository string `json:"repository"`
	Kind       string `json:"kind"`
	Number     int64  `json:"number"`
}

// Trigger identifies the authenticated delivery and normalized event, without payloads.
type Trigger struct {
	DeliveryID     string `json:"delivery_id"`
	Event          string `json:"event"`
	Action         string `json:"action"`
	InstallationID int64  `json:"installation_id"`
	ActorID        int64  `json:"actor_id"`
	SubjectID      int64  `json:"subject_id,omitempty"`
}

// SourceEntry contains provenance and never the source body or URL query data.
type SourceEntry struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Locator      string `json:"locator"`
	PinnedCommit string `json:"pinned_commit,omitempty"`
	Trust        string `json:"trust"`
	Bytes        int64  `json:"bytes"`
	ContentHash  Hash   `json:"content_hash"`
	AcquiredAt   string `json:"acquired_at"`
}

type SourceManifest struct {
	SchemaVersion int           `json:"schema_version"`
	Target        Target        `json:"target"`
	SnapshotHash  Hash          `json:"snapshot_hash"`
	Sources       []SourceEntry `json:"sources"`
}

// Finding contains only a classification and an opaque provenance reference.
type Finding struct {
	Class         string `json:"class"`
	SourceID      string `json:"source_id"`
	ReferenceHash Hash   `json:"reference_hash"`
}

type SafetyResult struct {
	SchemaVersion int       `json:"schema_version"`
	SnapshotHash  Hash      `json:"snapshot_hash"`
	GateVersion   string    `json:"gate_version"`
	Outcome       string    `json:"outcome"`
	Findings      []Finding `json:"findings"`
}

// ReviewDecision is structured metadata, not free-form model output or instructions.
type ReviewDecision struct {
	SchemaVersion int       `json:"schema_version"`
	SnapshotHash  Hash      `json:"snapshot_hash"`
	Verdict       string    `json:"verdict"`
	Findings      []Finding `json:"findings"`
}

type Runner struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	Provider       string `json:"provider"`
	Model          string `json:"model"`
	Adapter        string `json:"adapter"`
	AdapterVersion string `json:"adapter_version"`
}

// ResolvedOwnership contains only authoritative, bounded identity references.
// It is absent when safety stops before ownership is resolved.
type ResolvedOwnership struct {
	ReviewOwnerID  string `json:"review_owner_id"`
	PublisherAppID int64  `json:"publisher_app_id"`
}

// DecisionAssessment is optional. It cannot authorize a write or clear safety:
// abstain leaves deterministic policy in charge; hold blocks review/publication.
type DecisionAssessment struct {
	EngineID      string `json:"engine_id"`
	EngineVersion string `json:"engine_version"`
	Disposition   string `json:"disposition"`
}

// RunnerMetrics uses optional numeric observations rather than provider output.
// CostMicrosUSD is an accounting estimate in millionths of a US dollar.
type RunnerMetrics struct {
	LatencyMillis *uint64 `json:"latency_millis,omitempty"`
	InputTokens   *uint64 `json:"input_tokens,omitempty"`
	OutputTokens  *uint64 `json:"output_tokens,omitempty"`
	CostMicrosUSD *uint64 `json:"cost_micros_usd,omitempty"`
}

// CanonicalRecord holds a stopped safety run or a validated decision. Publication
// attempts are separate receipts and must never mutate this record.
type CanonicalRecord struct {
	SchemaVersion      int                     `json:"schema_version"`
	RecordID           Hash                    `json:"record_id"`
	Target             Target                  `json:"target"`
	Trigger            Trigger                 `json:"trigger"`
	ManifestHash       Hash                    `json:"manifest_hash"`
	ContextBundleHash  Hash                    `json:"context_bundle_hash,omitempty"`
	Context            *ProjectContextManifest `json:"context,omitempty"`
	SnapshotHash       Hash                    `json:"snapshot_hash"`
	PolicyVersion      string                  `json:"policy_version"`
	ProfileVersion     string                  `json:"profile_version"`
	GateVersion        string                  `json:"gate_version"`
	Safety             SafetyResult            `json:"safety"`
	Ownership          *ResolvedOwnership      `json:"ownership,omitempty"`
	Assessment         *DecisionAssessment     `json:"assessment,omitempty"`
	RunnerMetrics      *RunnerMetrics          `json:"runner_metrics,omitempty"`
	TerminalErrorClass string                  `json:"terminal_error_class"`
	Decision           *ReviewDecision         `json:"decision,omitempty"`
	Runner             *Runner                 `json:"runner,omitempty"`
	PublicationIntent  string                  `json:"publication_intent"`
	RuntimeOutcome     string                  `json:"runtime_outcome"`
}

type DeliveryReceipt struct {
	SchemaVersion int     `json:"schema_version"`
	Target        Target  `json:"target"`
	Trigger       Trigger `json:"trigger"`
	Outcome       string  `json:"outcome"`
}

type PublicationReceipt struct {
	SchemaVersion  int    `json:"schema_version"`
	RecordID       Hash   `json:"record_id"`
	Target         Target `json:"target"`
	SnapshotHash   Hash   `json:"snapshot_hash"`
	Operation      string `json:"operation"`
	IdempotencyKey Hash   `json:"idempotency_key"`
	Attempt        int    `json:"attempt"`
	CommentID      int64  `json:"comment_id,omitempty"`
	CommentURL     string `json:"comment_url,omitempty"`
	ResponseClass  string `json:"response_class"`
	Outcome        string `json:"outcome"`
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commitHex = regexp.MustCompile(`^[0-9a-f]{40}$`)
var repositoryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var opaqueID = regexp.MustCompile(`^[A-Za-z0-9_.:/@-]+$`)

func validHash(h Hash) bool { return sha256Hex.MatchString(string(h)) }
func validID(s string) bool { return len(s) <= 256 && opaqueID.MatchString(s) }
func oneOf(s string, choices ...string) bool {
	for _, c := range choices {
		if s == c {
			return true
		}
	}
	return false
}
func version(v int) error {
	if v != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", v)
	}
	return nil
}
func (t Target) validate() error {
	if !repositoryName.MatchString(t.Repository) || len(t.Repository) > 256 || !oneOf(t.Kind, "issue", "pull_request") || t.Number <= 0 {
		return errors.New("invalid target identity")
	}
	return nil
}
func (t Trigger) validate() error {
	if !validID(t.DeliveryID) || !oneOf(t.Event, "issues", "pull_request", "issue_comment", "pull_request_review", "pull_request_review_comment") || !oneOf(t.Action, "opened", "created", "submitted") || t.InstallationID <= 0 || t.ActorID <= 0 || t.SubjectID < 0 {
		return errors.New("invalid trigger identity")
	}
	switch t.Event {
	case "issues", "pull_request":
		if t.Action != "opened" || t.SubjectID != 0 {
			return errors.New("invalid event action or subject")
		}
	case "pull_request_review":
		if t.Action != "submitted" || t.SubjectID <= 0 {
			return errors.New("invalid event action or subject")
		}
	default:
		if t.Action != "created" || t.SubjectID <= 0 {
			return errors.New("invalid event action or subject")
		}
	}
	return nil
}
func (t Trigger) validateTarget(target Target) error {
	if t.Event == "issues" && target.Kind != "issue" || t.Event == "pull_request" && target.Kind != "pull_request" || (t.Event == "pull_request_review" || t.Event == "pull_request_review_comment") && target.Kind != "pull_request" {
		return errors.New("event/target mismatch")
	}
	return nil
}
func (e SourceEntry) validate() error {
	if !validID(e.ID) || !validID(e.Locator) || !oneOf(e.Type, "issue", "pull_request", "comment", "review", "review_comment", "diff", "guidance") || !oneOf(e.Trust, "untrusted", "pinned_guidance") || e.Bytes < 0 || !validHash(e.ContentHash) {
		return errors.New("invalid source entry")
	}
	// Repository guidance from an untrusted branch remains untrusted; only
	// guidance may carry the pinned_guidance trust class.
	if e.Trust == "pinned_guidance" {
		if e.Type != "guidance" || !strings.HasPrefix(e.Locator, "default:") || len(e.Locator) <= len("default:") || !commitHex.MatchString(e.PinnedCommit) {
			return errors.New("pinned guidance requires default-branch commit provenance")
		}
	} else if e.PinnedCommit != "" {
		return errors.New("untrusted source cannot claim pinned commit")
	}
	parsed, err := time.Parse(time.RFC3339Nano, e.AcquiredAt)
	if err != nil || parsed.IsZero() {
		return errors.New("invalid acquisition time")
	}
	return nil
}
func (m SourceManifest) Validate() error {
	if err := version(m.SchemaVersion); err != nil {
		return err
	}
	if err := m.Target.validate(); err != nil {
		return err
	}
	if !validHash(m.SnapshotHash) || len(m.Sources) == 0 {
		return errors.New("invalid manifest identity")
	}
	previous := ""
	for _, s := range m.Sources {
		if err := s.validate(); err != nil {
			return err
		}
		if s.ID <= previous {
			return errors.New("sources must have unique ascending ids")
		}
		previous = s.ID
	}
	return nil
}
func (f Finding) validate() error {
	if !oneOf(f.Class, "secret", "security_report", "prompt_injection", "exfiltration", "unsafe_path", "encoded_instruction", "unsupported_content", "scanner_error", "redaction", "review_issue") || !validID(f.SourceID) || !validHash(f.ReferenceHash) {
		return errors.New("invalid finding")
	}
	return nil
}
func validateFindings(fs []Finding) error {
	if fs == nil || len(fs) > 100 {
		return errors.New("findings must be present and bounded")
	}
	for _, f := range fs {
		if err := f.validate(); err != nil {
			return err
		}
	}
	return nil
}
func (s SafetyResult) Validate() error {
	if err := version(s.SchemaVersion); err != nil {
		return err
	}
	if !validHash(s.SnapshotHash) || !validID(s.GateVersion) || !oneOf(s.Outcome, "pass", "pass_with_redactions", "quarantine", "refuse") {
		return errors.New("invalid safety result")
	}
	if err := validateFindings(s.Findings); err != nil {
		return err
	}
	if s.Outcome == "pass" && len(s.Findings) != 0 {
		return errors.New("pass cannot contain findings")
	}
	if s.Outcome == "pass_with_redactions" {
		if len(s.Findings) == 0 {
			return errors.New("redaction requires finding")
		}
		for _, finding := range s.Findings {
			if finding.Class != "redaction" {
				return errors.New("redacted pass cannot contain blocking findings")
			}
		}
	}
	return nil
}
func (d ReviewDecision) Validate() error {
	if err := version(d.SchemaVersion); err != nil {
		return err
	}
	if !validHash(d.SnapshotHash) || !oneOf(d.Verdict, "no_findings", "findings") {
		return errors.New("invalid review decision")
	}
	if err := validateFindings(d.Findings); err != nil {
		return err
	}
	if d.Verdict == "no_findings" && len(d.Findings) != 0 || d.Verdict == "findings" && len(d.Findings) == 0 {
		return errors.New("verdict/findings mismatch")
	}
	for _, f := range d.Findings {
		if f.Class != "review_issue" {
			return errors.New("review finding must be review_issue")
		}
	}
	return nil
}
func (r Runner) validate() error {
	if !validID(r.Name) || !validID(r.Version) || !validID(r.Provider) || !validID(r.Model) || !validID(r.Adapter) || !validID(r.AdapterVersion) {
		return errors.New("invalid runner identity")
	}
	return nil
}
func (o ResolvedOwnership) validate() error {
	if !validID(o.ReviewOwnerID) || o.PublisherAppID <= 0 {
		return errors.New("invalid resolved ownership")
	}
	return nil
}
func (a DecisionAssessment) validate() error {
	if !validID(a.EngineID) || !validID(a.EngineVersion) || !oneOf(a.Disposition, "abstain", "hold") {
		return errors.New("invalid decision assessment")
	}
	return nil
}
func (m RunnerMetrics) validate() error {
	if m.LatencyMillis == nil && m.InputTokens == nil && m.OutputTokens == nil && m.CostMicrosUSD == nil {
		return errors.New("empty runner metrics")
	}
	// Hard ceilings bound retained observations; provider-reported values are not trusted.
	if m.LatencyMillis != nil && *m.LatencyMillis > 86_400_000 || m.InputTokens != nil && *m.InputTokens > 10_000_000 || m.OutputTokens != nil && *m.OutputTokens > 10_000_000 || m.CostMicrosUSD != nil && *m.CostMicrosUSD > 10_000_000_000 {
		return errors.New("runner metrics exceed bounds")
	}
	return nil
}
func (r CanonicalRecord) Validate() error {
	if err := version(r.SchemaVersion); err != nil {
		return err
	}
	if !validHash(r.RecordID) || !validHash(r.ManifestHash) || !validHash(r.SnapshotHash) {
		return errors.New("invalid record hashes")
	}
	if err := r.Target.validate(); err != nil {
		return err
	}
	if err := r.Trigger.validate(); err != nil {
		return err
	}
	if err := r.Trigger.validateTarget(r.Target); err != nil {
		return err
	}
	if !validID(r.PolicyVersion) || !validID(r.ProfileVersion) || !validID(r.GateVersion) || !oneOf(r.PublicationIntent, "none", "advisory_comment") || !oneOf(r.RuntimeOutcome, "reviewed", "quarantined", "refused", "runner_failed", "decision_restricted", "blocked") {
		return errors.New("invalid record versions or outcomes")
	}
	if err := r.Safety.Validate(); err != nil {
		return err
	}
	if r.Safety.SnapshotHash != r.SnapshotHash || r.Safety.GateVersion != r.GateVersion {
		return errors.New("safety identity mismatch")
	}
	if !oneOf(r.TerminalErrorClass, "none", "safety", "runner", "schema", "infrastructure", "policy", "ambiguity") {
		return errors.New("invalid terminal error class")
	}
	if r.Ownership != nil {
		if err := r.Ownership.validate(); err != nil {
			return err
		}
	}
	if r.Assessment != nil {
		if err := r.Assessment.validate(); err != nil {
			return err
		}
	}
	if r.RunnerMetrics != nil {
		if err := r.RunnerMetrics.validate(); err != nil {
			return err
		}
		if r.Runner == nil {
			return errors.New("metrics without runner")
		}
	}
	if r.Context != nil {
		if err := r.Context.Validate(); err != nil {
			return err
		}
		for _, entry := range r.Context.Entries {
			if entry.Origin == "policy" && entry.Version != r.PolicyVersion || entry.Origin == "profile" && entry.Version != r.ProfileVersion {
				return errors.New("context policy/profile version mismatch")
			}
		}
		if r.Context.BundleHash != r.ContextBundleHash || r.Context.Target != r.Target || r.Context.SnapshotHash != r.SnapshotHash {
			return errors.New("context record identity mismatch")
		}
		for _, ref := range r.Context.Prior.Records {
			if ref.RecordID == r.RecordID {
				return errors.New("record cannot include itself as prior context")
			}
		}
	} else if r.ContextBundleHash != "" {
		return errors.New("context hash without bundle")
	}
	if r.Safety.Outcome == "quarantine" || r.Safety.Outcome == "refuse" {
		if r.Decision != nil || r.Runner != nil || r.Ownership != nil || r.Assessment != nil || r.RunnerMetrics != nil || r.Context != nil || r.TerminalErrorClass != "safety" || r.PublicationIntent != "none" || (r.Safety.Outcome == "quarantine" && r.RuntimeOutcome != "quarantined") || (r.Safety.Outcome == "refuse" && r.RuntimeOutcome != "refused") {
			return errors.New("unsafe record contains review or publication intent")
		}
		return nil
	}
	if r.RuntimeOutcome == "blocked" {
		if r.Decision != nil || r.Runner != nil || r.Assessment != nil || r.RunnerMetrics != nil || r.Context != nil || r.PublicationIntent != "none" || !oneOf(r.TerminalErrorClass, "policy", "ambiguity", "infrastructure") || r.TerminalErrorClass == "ambiguity" && r.Ownership != nil {
			return errors.New("blocked record cannot review or publish")
		}
		return nil
	}
	if r.Ownership == nil {
		return errors.New("safe run requires resolved ownership")
	}
	if r.RuntimeOutcome == "decision_restricted" {
		if r.Assessment == nil || r.Assessment.Disposition != "hold" || r.Decision != nil || r.Runner != nil || r.RunnerMetrics != nil || r.Context != nil || r.PublicationIntent != "none" || r.TerminalErrorClass != "none" {
			return errors.New("restricted decision cannot review or publish")
		}
		return nil
	}
	if r.Assessment != nil && r.Assessment.Disposition == "hold" {
		return errors.New("held decision cannot invoke runner")
	}
	if r.RuntimeOutcome == "runner_failed" {
		if r.Context == nil {
			return errors.New("runner attempt requires context bundle")
		}
		if r.Runner != nil {
			if err := r.Runner.validate(); err != nil {
				return err
			}
		}
		if r.Decision != nil || r.PublicationIntent != "none" || !oneOf(r.TerminalErrorClass, "runner", "schema", "infrastructure") {
			return errors.New("failed runner cannot publish")
		}
		return nil
	}
	if r.RuntimeOutcome != "reviewed" || r.Decision == nil || r.Runner == nil || r.Context == nil || r.TerminalErrorClass != "none" {
		return errors.New("reviewed record requires runner and decision")
	}
	if err := r.Decision.Validate(); err != nil {
		return err
	}
	if err := r.Runner.validate(); err != nil {
		return err
	}
	if r.Decision.SnapshotHash != r.SnapshotHash {
		return errors.New("decision snapshot mismatch")
	}
	return nil
}
func (r DeliveryReceipt) Validate() error {
	if err := version(r.SchemaVersion); err != nil {
		return err
	}
	if err := r.Target.validate(); err != nil {
		return err
	}
	if err := r.Trigger.validate(); err != nil {
		return err
	}
	if err := r.Trigger.validateTarget(r.Target); err != nil {
		return err
	}
	if !oneOf(r.Outcome, "accepted", "noop", "rejected", "dead_letter") {
		return errors.New("invalid delivery outcome")
	}
	return nil
}
func (r PublicationReceipt) Validate() error {
	if err := version(r.SchemaVersion); err != nil {
		return err
	}
	if err := r.Target.validate(); err != nil {
		return err
	}
	if !validHash(r.RecordID) || !validHash(r.SnapshotHash) || !validHash(r.IdempotencyKey) || !oneOf(r.Operation, "none", "create", "update") || r.Attempt < 0 || r.CommentID < 0 || !oneOf(r.ResponseClass, "none", "success", "client_error", "server_error", "timeout", "unknown") || !oneOf(r.Outcome, "blocked", "uncertain", "succeeded", "failed") {
		return errors.New("invalid publication receipt")
	}
	if r.CommentID == 0 && r.CommentURL != "" {
		return errors.New("comment URL without comment identity")
	}
	if r.CommentID > 0 {
		path := "issues"
		if r.Target.Kind == "pull_request" {
			path = "pull"
		}
		expected := fmt.Sprintf("https://github.com/%s/%s/%d#issuecomment-%d", r.Target.Repository, path, r.Target.Number, r.CommentID)
		if r.CommentURL != expected {
			return errors.New("invalid comment URL")
		}
	}
	if r.Operation == "none" && (r.Outcome != "blocked" || r.Attempt != 0 || r.CommentID != 0 || r.ResponseClass != "none") {
		return errors.New("blocked receipt must not include write")
	}
	if r.Operation != "none" && (r.Attempt == 0 || r.Outcome == "blocked") || r.Outcome == "succeeded" && (r.ResponseClass != "success" || r.CommentID == 0) || r.Outcome == "uncertain" && r.ResponseClass != "unknown" || r.Outcome == "failed" && (r.ResponseClass == "success" || r.ResponseClass == "none") {
		return errors.New("invalid publication state")
	}
	return nil
}

type Validatable interface{ Validate() error }

// Decode rejects unknown or case-variant fields, trailing JSON, duplicate object
// keys (including nested ones), and unsupported versions. Always decode into a fresh destination.
func Decode[T Validatable](data []byte) (T, error) {
	var out T
	if typ := reflect.TypeOf(out); typ == nil || typ.Kind() != reflect.Struct {
		return out, errors.New("decode requires a contract struct type")
	}
	if len(data) == 0 || len(data) > 1<<20 {
		return out, errors.New("contract exceeds size limit or is empty")
	}
	if err := checkShape(json.NewDecoder(bytes.NewReader(data)), reflect.TypeOf(out)); err != nil {
		return out, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return out, errors.New("trailing JSON")
	}
	if err := out.Validate(); err != nil {
		return out, err
	}
	return out, nil
}
func checkShape(d *json.Decoder, typ reflect.Type) error {
	if err := scanValue(d, typ); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func scanValue(d *json.Decoder, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		if typ.Kind() != reflect.Struct {
			return errors.New("unexpected object")
		}
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if seen[s] {
				return fmt.Errorf("duplicate field %q", s)
			}
			seen[s] = true
			var fieldType reflect.Type
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				if name == s {
					fieldType = f.Type
					break
				}
			}
			if fieldType == nil {
				return fmt.Errorf("unknown field %q", s)
			}
			if err := scanValue(d, fieldType); err != nil {
				return err
			}
		}
		_, err := d.Token()
		return err
	case '[':
		if typ.Kind() != reflect.Slice {
			return errors.New("unexpected array")
		}
		for d.More() {
			if err := scanValue(d, typ.Elem()); err != nil {
				return err
			}
		}
		_, err := d.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}
