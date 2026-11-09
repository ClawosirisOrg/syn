// SPDX-License-Identifier: AGPL-3.0-or-later

package contracts

import "testing"

func TestReferenceMembership(t *testing.T) {
	m, s, d, c := manifest(), safety(), decision(), contextFixture()
	if err := ValidateReferences(m, s, &d, &c); err != nil {
		t.Fatal(err)
	}
	s.Findings = []Finding{{Class: "scanner_error", SourceID: "missing", ReferenceHash: digest}}
	s.Outcome = "refuse"
	if err := ValidateReferences(m, s, nil, nil); err == nil {
		t.Fatal("missing safety source accepted")
	}
	s.Findings[0].SourceID = "a"
	if err := ValidateReferences(m, s, &d, nil); err == nil {
		t.Fatal("unsafe review accepted")
	}
	s = safety()
	d.Verdict = "findings"
	d.Findings = []Finding{{Class: "review_issue", SourceID: "missing", ReferenceHash: digest}}
	if err := ValidateReferences(m, s, &d, &c); err == nil {
		t.Fatal("missing review source accepted")
	}
	d.Findings[0].SourceID = "a"
	c.Entries[0].SourceID = "missing"
	if err := ValidateReferences(m, s, &d, &c); err == nil {
		t.Fatal("missing context source accepted")
	}
	c = contextFixture()
	m.Sources = append(m.Sources, SourceEntry{ID: "b", Type: "comment", Locator: "comment:3", Trust: "untrusted", Bytes: 5, ContentHash: digest2, AcquiredAt: "2026-10-13T00:00:00Z"})
	if err := ValidateReferences(m, s, &d, &c); err == nil {
		t.Fatal("omitted admitted source accepted")
	}
	m = manifest()
	s.SnapshotHash = digest2
	if err := ValidateReferences(m, s, &d, &c); err == nil {
		t.Fatal("different snapshot accepted")
	}
}
