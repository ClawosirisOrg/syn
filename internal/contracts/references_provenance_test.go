// SPDX-License-Identifier: AGPL-3.0-or-later

package contracts

import (
	"strings"
	"testing"
)

func TestContextManifestProvenance(t *testing.T) {
	baseManifest, baseContext := manifest(), contextFixture()
	commit := strings.Repeat("a", 40)
	baseManifest.Sources = append(baseManifest.Sources, SourceEntry{
		ID: "guidance", Type: "guidance", Locator: "default:AGENTS.md",
		Trust: "pinned_guidance", PinnedCommit: commit, Bytes: 10,
		ContentHash: digest2, AcquiredAt: "2026-10-13T00:00:00Z",
	})
	guidance := ContextEntry{SourceID: "guidance", Origin: "pinned_guidance", Trust: "pinned_guidance", Version: "commit:" + commit, ContentHash: digest2, Retention: "retained_reference", Repository: target().Repository}
	baseContext.Entries = append(baseContext.Entries[:1], append([]ContextEntry{guidance}, baseContext.Entries[1:]...)...)
	validate := func(m SourceManifest, c ProjectContextManifest) error {
		return ValidateReferences(m, safety(), nil, &c)
	}
	if err := validate(baseManifest, baseContext); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SourceManifest, *ProjectContextManifest){
		"admitted hash mismatch": func(_ *SourceManifest, c *ProjectContextManifest) { c.Entries[0].ContentHash = digest2 },
		"guidance missing":       func(m *SourceManifest, _ *ProjectContextManifest) { m.Sources = m.Sources[:1] },
		"guidance hash mismatch": func(_ *SourceManifest, c *ProjectContextManifest) { c.Entries[1].ContentHash = digest },
		"guidance commit mismatch": func(_ *SourceManifest, c *ProjectContextManifest) {
			c.Entries[1].Version = "commit:" + strings.Repeat("b", 40)
		},
		"guidance trust promotion": func(m *SourceManifest, _ *ProjectContextManifest) {
			m.Sources[1].Trust = "untrusted"
			m.Sources[1].PinnedCommit = ""
		},
		"admitted source promoted": func(m *SourceManifest, _ *ProjectContextManifest) {
			m.Sources[0].Type = "guidance"
			m.Sources[0].Locator = "default:AGENTS.md"
			m.Sources[0].Trust = "pinned_guidance"
			m.Sources[0].PinnedCommit = commit
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, c := baseManifest, baseContext
			m.Sources = append([]SourceEntry(nil), m.Sources...)
			c.Entries = append([]ContextEntry(nil), c.Entries...)
			mutate(&m, &c)
			if err := validate(m, c); err == nil {
				t.Fatal("provenance mismatch accepted")
			}
		})
	}
}
