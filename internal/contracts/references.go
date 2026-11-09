// SPDX-License-Identifier: AGPL-3.0-or-later

package contracts

import "errors"

// ValidateReferences checks provenance references across validated metadata.
// It does not authenticate GitHub acquisition or recompute snapshot/manifest
// hashes; those are required separate gates before rendering or publication.
func ValidateReferences(manifest SourceManifest, safety SafetyResult, decision *ReviewDecision, context *ProjectContextManifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if err := safety.Validate(); err != nil {
		return err
	}
	if manifest.SnapshotHash != safety.SnapshotHash {
		return errors.New("safety snapshot mismatch")
	}
	known := make(map[string]SourceEntry, len(manifest.Sources))
	for _, src := range manifest.Sources {
		known[src.ID] = src
	}
	for _, finding := range safety.Findings {
		if _, ok := known[finding.SourceID]; !ok {
			return errors.New("safety finding references missing source")
		}
	}
	if decision != nil {
		if err := decision.Validate(); err != nil {
			return err
		}
		if decision.SnapshotHash != manifest.SnapshotHash {
			return errors.New("decision snapshot mismatch")
		}
		if safety.Outcome != "pass" && safety.Outcome != "pass_with_redactions" {
			return errors.New("unsafe result cannot have review decision")
		}
		for _, finding := range decision.Findings {
			if _, ok := known[finding.SourceID]; !ok {
				return errors.New("review finding references missing source")
			}
		}
	}
	if context != nil {
		if err := context.Validate(); err != nil {
			return err
		}
		if context.Target != manifest.Target || context.SnapshotHash != manifest.SnapshotHash {
			return errors.New("context snapshot or target mismatch")
		}
		seen := make(map[string]bool, len(manifest.Sources))
		for _, entry := range context.Entries {
			switch entry.Origin {
			case "admitted_source", "pinned_guidance":
				src, ok := known[entry.SourceID]
				if !ok || src.ContentHash != entry.ContentHash {
					return errors.New("context source missing or content hash mismatch")
				}
				if entry.Origin == "admitted_source" {
					if src.Trust != "untrusted" {
						return errors.New("context promoted source trust")
					}
				} else if src.Type != "guidance" || src.Trust != "pinned_guidance" || entry.Version != "commit:"+src.PinnedCommit {
					return errors.New("context guidance pin mismatch")
				}
				seen[entry.SourceID] = true
			}
		}
		for _, src := range manifest.Sources {
			if src.Trust == "untrusted" && !seen[src.ID] {
				return errors.New("context omitted admitted source")
			}
		}
	}
	return nil
}
