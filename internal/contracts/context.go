// SPDX-License-Identifier: AGPL-3.0-or-later

package contracts

import (
	"errors"
	"strings"
)

const maxContextEntries = 128
const maxPriorRecords = 8
const maxPriorFindings = 10
const maxCompletedCycles = 1_000_000

// ContextEntry is a provenance reference, never an instruction or source body.
// Origin and Trust are separate: a prior model record stays evidence, not policy.
type ContextEntry struct {
	SourceID    string `json:"source_id"`
	Origin      string `json:"origin"`
	Trust       string `json:"trust"`
	Version     string `json:"version"`
	ContentHash Hash   `json:"content_hash"`
	Retention   string `json:"retention"`
	Repository  string `json:"repository,omitempty"`
}

// PriorRecordRef is a bounded structured projection; no prior reviewer prose,
// private authoring memory, or resumable session can be encoded in this shape.
type PriorRecordRef struct {
	RecordID     Hash      `json:"record_id"`
	SnapshotHash Hash      `json:"snapshot_hash"`
	Disposition  string    `json:"disposition"`
	Verdict      string    `json:"verdict"`
	Findings     []Finding `json:"findings"`
}

// PriorRecordProjection counts all completed earlier cycles, not just selected
// references; omitted count and truncation reasons prevent false absence claims.
type PriorRecordProjection struct {
	SchemaVersion     int              `json:"schema_version"`
	Target            Target           `json:"target"`
	Records           []PriorRecordRef `json:"records"`
	CompletedCycles   uint32           `json:"completed_cycles"`
	OmittedCycles     uint32           `json:"omitted_cycles"`
	Truncated         bool             `json:"truncated"`
	TruncationReasons []string         `json:"truncation_reasons"`
}

// ProjectContextManifest describes the selected metadata-only review bundle.
// BundleHash is supplied by the deterministic bundle builder, not computed here.
type ProjectContextManifest struct {
	SchemaVersion     int                   `json:"schema_version"`
	Target            Target                `json:"target"`
	SnapshotHash      Hash                  `json:"snapshot_hash"`
	BundleHash        Hash                  `json:"bundle_hash"`
	Entries           []ContextEntry        `json:"entries"`
	OmittedEntries    uint32                `json:"omitted_entries"`
	Truncated         bool                  `json:"truncated"`
	TruncationReasons []string              `json:"truncation_reasons"`
	Prior             PriorRecordProjection `json:"prior"`
}

func (e ContextEntry) validate(target Target) error {
	if !validID(e.SourceID) || !validID(e.Version) || !validHash(e.ContentHash) || !oneOf(e.Retention, "attempt_only", "retained_reference") {
		return errors.New("invalid context entry metadata")
	}
	if !oneOf(e.Origin, "admitted_source", "policy", "profile", "pinned_guidance", "maintainer_knowledge", "prior_record") {
		return errors.New("unsupported context origin")
	}
	switch e.Origin {
	case "admitted_source":
		if e.Trust != "untrusted" || e.Repository != "" {
			return errors.New("invalid admitted-source trust")
		}
	case "policy", "profile":
		if e.Trust != "policy" || e.Repository != "" {
			return errors.New("invalid policy trust")
		}
	case "pinned_guidance":
		if e.Trust != "pinned_guidance" || e.Repository != target.Repository || !strings.HasPrefix(e.Version, "commit:") || !commitHex.MatchString(strings.TrimPrefix(e.Version, "commit:")) {
			return errors.New("invalid pinned guidance provenance")
		}
	case "maintainer_knowledge":
		if e.Trust != "curated" || e.Repository != target.Repository {
			return errors.New("invalid curated knowledge scope")
		}
	case "prior_record":
		if e.Trust != "prior_record" || e.Repository != "" || e.Retention != "retained_reference" {
			return errors.New("prior record must remain evidence")
		}
	}
	return nil
}
func (p PriorRecordProjection) Validate() error {
	if err := version(p.SchemaVersion); err != nil {
		return err
	}
	if err := p.Target.validate(); err != nil {
		return err
	}
	if p.Records == nil || len(p.Records) > maxPriorRecords || p.CompletedCycles > maxCompletedCycles || p.OmittedCycles > maxCompletedCycles {
		return errors.New("invalid prior record coverage")
	}
	if uint64(p.CompletedCycles) != uint64(len(p.Records))+uint64(p.OmittedCycles) || p.Truncated != (p.OmittedCycles > 0) {
		return errors.New("inconsistent prior history coverage")
	}
	if p.TruncationReasons == nil || len(p.TruncationReasons) > 3 || p.Truncated != (len(p.TruncationReasons) > 0) {
		return errors.New("inconsistent truncation reasons")
	}
	previous := ""
	for _, reason := range p.TruncationReasons {
		if !oneOf(reason, "age", "bytes", "cycles") || reason <= previous {
			return errors.New("invalid or unordered truncation reasons")
		}
		previous = reason
	}
	seen := make(map[Hash]bool, len(p.Records))
	for _, ref := range p.Records {
		if !validHash(ref.RecordID) || !validHash(ref.SnapshotHash) || seen[ref.RecordID] || !oneOf(ref.Disposition, "reviewed", "refused", "quarantined", "blocked", "runner_failed") || ref.Findings == nil || len(ref.Findings) > maxPriorFindings {
			return errors.New("invalid prior record reference")
		}
		seen[ref.RecordID] = true
		if ref.Disposition == "reviewed" && (!oneOf(ref.Verdict, "no_findings", "findings") || ref.Verdict == "no_findings" && len(ref.Findings) != 0 || ref.Verdict == "findings" && len(ref.Findings) == 0) || ref.Disposition != "reviewed" && (ref.Verdict != "" || len(ref.Findings) != 0) {
			return errors.New("prior verdict/findings mismatch")
		}
		for _, finding := range ref.Findings {
			if err := finding.validate(); err != nil {
				return err
			}
			if finding.Class != "review_issue" {
				return errors.New("prior finding is not review evidence")
			}
		}
	}
	return nil
}
func (m ProjectContextManifest) Validate() error {
	if err := version(m.SchemaVersion); err != nil {
		return err
	}
	if err := m.Target.validate(); err != nil {
		return err
	}
	if !validHash(m.SnapshotHash) || !validHash(m.BundleHash) || len(m.Entries) == 0 || len(m.Entries) > maxContextEntries {
		return errors.New("invalid context bundle metadata")
	}
	if err := m.Prior.Validate(); err != nil {
		return err
	}
	if m.Prior.Target != m.Target {
		return errors.New("prior projection target mismatch")
	}
	if m.OmittedEntries > maxCompletedCycles || m.Truncated != (m.OmittedEntries > 0 || m.Prior.Truncated) || m.TruncationReasons == nil || m.Truncated != (len(m.TruncationReasons) > 0) || len(m.TruncationReasons) > 4 {
		return errors.New("invalid context coverage")
	}
	previousReason := ""
	history, omittedReason := false, false
	for _, reason := range m.TruncationReasons {
		if !oneOf(reason, "age", "bytes", "entries", "history") || reason <= previousReason {
			return errors.New("invalid context truncation reasons")
		}
		if reason == "history" {
			history = true
		} else {
			omittedReason = true
		}
		previousReason = reason
	}
	if history != m.Prior.Truncated || omittedReason != (m.OmittedEntries > 0) {
		return errors.New("context coverage reason mismatch")
	}
	prior := make(map[Hash]bool, len(m.Prior.Records))
	for _, ref := range m.Prior.Records {
		prior[ref.RecordID] = true
	}
	previous := ""
	seenPrior := make(map[Hash]bool)
	counts := make(map[string]int)
	for _, entry := range m.Entries {
		if err := entry.validate(m.Target); err != nil {
			return err
		}
		if entry.SourceID <= previous {
			return errors.New("context entries must have unique ascending ids")
		}
		previous = entry.SourceID
		counts[entry.Origin]++
		if entry.Origin == "prior_record" {
			id := Hash(entry.SourceID)
			if !prior[id] || seenPrior[id] || entry.Version != string(id) {
				return errors.New("prior context entry lacks matching projection")
			}
			seenPrior[id] = true
		}
	}
	if counts["admitted_source"] == 0 || counts["policy"] != 1 || counts["profile"] != 1 {
		return errors.New("context requires one policy, one profile and admitted source")
	}
	if len(seenPrior) != len(prior) {
		return errors.New("prior projection missing context entry")
	}
	return nil
}
