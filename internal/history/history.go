// SPDX-License-Identifier: AGPL-3.0-or-later

// Package history projects explicit canonical record IDs into bounded, metadata-only
// prior evidence. The caller owns the authoritative cycle index and its ordering;
// this package neither discovers records nor proves freshness.
package history

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/ClawOsirisOrg/syn/internal/contracts"
	"github.com/ClawOsirisOrg/syn/internal/recordstore"
)

const maxRecords = 8
const maxFindings = 10
const maxCycles = 1_000_000

// Project reads exactly the supplied latest-first IDs through Store.Get. The
// authoritative completed count includes every earlier completed cycle, even
// those not selected; exactly min(count, 8) IDs are required. An upstream
// cycle index must establish that they actually are the latest for this target.
// Entries are sorted by source ID for use in a ProjectContextManifest, while
// projection records retain newest-first order. Nothing here grants policy trust.
func Project(store *recordstore.Store, target contracts.Target, completed uint32, latest []contracts.Hash) (contracts.PriorRecordProjection, []contracts.ContextEntry, error) {
	var empty contracts.PriorRecordProjection
	if store == nil || completed > maxCycles {
		return empty, nil, errors.New("missing record store or invalid authoritative cycle count")
	}
	selected := int(completed)
	if selected > maxRecords {
		selected = maxRecords
	}
	if len(latest) != selected {
		return empty, nil, errors.New("latest record IDs do not match authoritative cycle count")
	}
	p := contracts.PriorRecordProjection{
		SchemaVersion: contracts.SchemaVersion, Target: target,
		Records:         make([]contracts.PriorRecordRef, 0, selected),
		CompletedCycles: completed, OmittedCycles: completed - uint32(selected),
		TruncationReasons: []string{},
	}
	if p.OmittedCycles > 0 {
		p.Truncated = true
		p.TruncationReasons = []string{"cycles"}
	}
	// Validate an empty projection, so a bad target is rejected even when
	// there is no record to compare against.
	check := p
	check.Records = []contracts.PriorRecordRef{}
	check.CompletedCycles, check.OmittedCycles, check.Truncated = 0, 0, false
	check.TruncationReasons = []string{}
	if err := check.Validate(); err != nil {
		return empty, nil, fmt.Errorf("invalid history target: %w", err)
	}
	entries := make([]contracts.ContextEntry, 0, selected)
	seen := make(map[contracts.Hash]bool, selected)
	for _, id := range latest {
		if seen[id] {
			return empty, nil, errors.New("duplicate prior record ID")
		}
		seen[id] = true
		r, err := store.Get(id)
		if err != nil {
			return empty, nil, fmt.Errorf("read prior canonical record: %w", err)
		}
		if err := r.Validate(); err != nil || r.RecordID != id || r.Target != target {
			return empty, nil, errors.New("invalid or mismatched prior canonical record")
		}
		ref := contracts.PriorRecordRef{RecordID: id, SnapshotHash: r.SnapshotHash, Disposition: r.RuntimeOutcome, Findings: []contracts.Finding{}}
		switch r.RuntimeOutcome {
		case "reviewed":
			if r.Decision == nil || len(r.Decision.Findings) > maxFindings {
				return empty, nil, errors.New("prior review findings exceed projection bound")
			}
			ref.Verdict = r.Decision.Verdict
			for _, f := range r.Decision.Findings {
				// A valid canonical record may carry an arbitrary source ID, including
				// a credential-looking identifier. Never propagate its original bytes.
				f.SourceID = opaqueSource(id, f.SourceID)
				ref.Findings = append(ref.Findings, f)
			}
		case "refused", "quarantined", "blocked", "runner_failed":
			// Stopped cycles have no review findings or verdict.
		default:
			return empty, nil, errors.New("unsupported prior record disposition")
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			return empty, nil, errors.New("cannot encode prior canonical record")
		}
		content := sha256.Sum256(encoded)
		p.Records = append(p.Records, ref)
		entries = append(entries, contracts.ContextEntry{
			SourceID: string(id), Origin: "prior_record", Trust: "prior_record",
			Version: string(id), ContentHash: contracts.Hash(hex.EncodeToString(content[:])),
			Retention: "retained_reference",
		})
	}
	if err := p.Validate(); err != nil {
		return empty, nil, fmt.Errorf("invalid prior projection: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].SourceID < entries[j].SourceID })
	return p, entries, nil
}

func opaqueSource(id contracts.Hash, source string) string {
	h := sha256.New()
	h.Write([]byte("syn-prior-source-v1\x00"))
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write([]byte(source))
	return "prior:" + hex.EncodeToString(h.Sum(nil))
}
