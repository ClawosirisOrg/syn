// SPDX-License-Identifier: AGPL-3.0-or-later

// Package render projects a persisted canonical record into a local advisory
// preview. It has no GitHub client or publication authority.
package render

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ClawOsirisOrg/syn/internal/contracts"
	"github.com/ClawOsirisOrg/syn/internal/recordstore"
)

const maxBodyBytes = 2048

var ErrNotRenderable = errors.New("record is not eligible for an advisory preview")

// Preview is a dry-run CREATE candidate, not an authorization to create or
// update a comment. A publisher must independently check policy, freshness,
// ownership, reference provenance and the existing marker/author state.
type Preview struct {
	Body     string
	Marker   string
	RecordID contracts.Hash
}

// CreatePreview reads a validated persisted record by ID before projecting it.
// It deliberately never interpolates source identifiers, provenance, runner
// metadata, version strings, target names, or model text into visible Markdown.
func CreatePreview(store *recordstore.Store, id contracts.Hash) (Preview, error) {
	if store == nil {
		return Preview{}, errors.New("record store required")
	}
	record, err := store.Get(id)
	if err != nil {
		return Preview{}, fmt.Errorf("read stored record: %w", err)
	}
	if err := record.Validate(); err != nil {
		return Preview{}, fmt.Errorf("invalid stored record: %w", err)
	}
	if record.RecordID != id || record.RuntimeOutcome != "reviewed" ||
		record.PublicationIntent != "advisory_comment" ||
		record.TerminalErrorClass != "none" ||
		(record.Safety.Outcome != "pass" && record.Safety.Outcome != "pass_with_redactions") ||
		record.Decision == nil || record.Ownership == nil || record.Context == nil {
		return Preview{}, ErrNotRenderable
	}
	// Only enum counts are exposed. Validate restricts reviewed findings to
	// review_issue and redacted-pass findings to redaction. Fail closed here too.
	for _, f := range record.Decision.Findings {
		if f.Class != "review_issue" {
			return Preview{}, ErrNotRenderable
		}
	}
	for _, f := range record.Safety.Findings {
		if f.Class != "redaction" {
			return Preview{}, ErrNotRenderable
		}
	}
	marker := markerFor(record.Target)
	body := fmt.Sprintf("## Syn advisory review\n\nThis is automated advisory feedback, not an approval, security clearance, or instruction to change the item. Maintainers should verify findings independently.\n\n- Review issue findings: %d\n- Redaction findings: %d\n- Schema version: %d\n- Snapshot SHA-256: %s\n\n%s\n",
		len(record.Decision.Findings), len(record.Safety.Findings), record.SchemaVersion, record.SnapshotHash, marker)
	if len(body) > maxBodyBytes {
		return Preview{}, errors.New("advisory preview exceeds size limit")
	}
	return Preview{Body: body, Marker: marker, RecordID: id}, nil
}

// markerFor hashes the lowercased repository and shared Issues item number.
// Hashing avoids reflecting even a syntactically valid private repository name.
// Issues and pull requests share a numbering/Issues-comment namespace.
func markerFor(target contracts.Target) string {
	key := strings.ToLower(target.Repository) + "#" + strconv.FormatInt(target.Number, 10)
	digest := sha256.Sum256([]byte(key))
	return "<!-- syn-review:v1 key=" + hex.EncodeToString(digest[:]) + " -->"
}
