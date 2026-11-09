// SPDX-License-Identifier: AGPL-3.0-or-later

package fixture

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ClawOsirisOrg/syn/internal/contracts"
	"github.com/ClawOsirisOrg/syn/internal/history"
	"github.com/ClawOsirisOrg/syn/internal/review"
	"github.com/ClawOsirisOrg/syn/internal/source"
)

// Runner input must match the persisted context exactly, including empty-slice shape.
func sameContext(a, b contracts.ProjectContextManifest) bool { return reflect.DeepEqual(a, b) }

func TestExplicitPriorChangesSameSnapshotIdentity(t *testing.T) {
	in, fake := withFake(t, fixtureInput("issue", "Safe fixture."))
	store := privateStore(t)
	first, err := Run(context.Background(), in, store)
	if err != nil {
		t.Fatal(err)
	}
	in.Prior = &PriorHistory{CompletedCycles: 1, LatestRecordIDs: []contracts.Hash{first.Record.RecordID}}
	second, err := Run(context.Background(), in, store)
	if err != nil {
		t.Fatal(err)
	}
	if second.Record.SnapshotHash != first.Record.SnapshotHash || second.Record.ManifestHash != first.Record.ManifestHash || second.Record.ContextBundleHash == first.Record.ContextBundleHash || second.Record.RecordID == first.Record.RecordID {
		t.Fatal("prior history did not alter context and record identity for same snapshot")
	}
	p := second.Record.Context.Prior
	if p.CompletedCycles != 1 || p.OmittedCycles != 0 || p.Truncated || len(p.Records) != 1 || p.Records[0].RecordID != first.Record.RecordID || p.Records[0].Disposition != "reviewed" || p.Records[0].Verdict != "no_findings" {
		t.Fatalf("incorrect prior projection: %+v", p)
	}
	var entry *contracts.ContextEntry
	for i := range second.Record.Context.Entries {
		if second.Record.Context.Entries[i].Origin == "prior_record" {
			entry = &second.Record.Context.Entries[i]
		}
	}
	expectedPrior, expectedEntries, err := history.Project(store, in.Target, 1, in.Prior.LatestRecordIDs)
	if err != nil || len(expectedEntries) != 1 || entry == nil || *entry != expectedEntries[0] || !reflect.DeepEqual(p, expectedPrior) {
		t.Fatalf("prior projection/entry differs from history.Project: %+v %+v %v", p, entry, err)
	}
	expectedHash, err := hash("syn-fixture-context-v1", func() contracts.ProjectContextManifest { c := *second.Record.Context; c.BundleHash = ""; return c }())
	if err != nil || second.Record.ContextBundleHash != expectedHash {
		t.Fatalf("context hash did not bind prior: %v", err)
	}
	if !sameContext(fake.LastEnvelope().Context, *second.Record.Context) {
		t.Fatal("fake did not receive stored context")
	}
	stored, err := store.Get(second.Record.RecordID)
	if err != nil || !reflect.DeepEqual(stored, second.Record) {
		t.Fatalf("stored context mismatch: %v", err)
	}
	in.Prior = nil
	without, err := Run(context.Background(), in, store)
	if err != nil || without.Record.RecordID != first.Record.RecordID || without.Record.Context.Prior.CompletedCycles != 0 {
		t.Fatalf("nil prior did not retain zero-history default: %+v %v", without.Record, err)
	}
}

func TestPriorFindingsRemainEvidenceAndDoNotCopyRawSource(t *testing.T) {
	in := fixtureInput("issue", "Old safe fixture.")
	// The historical source is deliberately absent from the current snapshot.
	in.Selections[0] = source.Selection{ID: "comment:issue:17:101", Type: "comment", Locator: "comment:issue:17:101", Trust: "untrusted"}
	in.Acquired[0].ID = in.Selections[0].ID
	snap, err := source.Build(in.Target, in.Selections, in.Acquired, source.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	decision := contracts.ReviewDecision{SchemaVersion: contracts.SchemaVersion, SnapshotHash: snap.Manifest().SnapshotHash, Verdict: "findings", Findings: []contracts.Finding{{Class: "review_issue", SourceID: in.Selections[0].ID, ReferenceHash: snap.Manifest().SnapshotHash}}}
	response, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	in.Runner = review.NewFake(response)
	store := privateStore(t)
	old, err := Run(context.Background(), in, store)
	if err != nil {
		t.Fatal(err)
	}
	current, fake := withFake(t, fixtureInput("issue", "Current safe fixture."))
	current.Prior = &PriorHistory{CompletedCycles: 1, LatestRecordIDs: []contracts.Hash{old.Record.RecordID}}
	got, err := Run(context.Background(), current, store)
	if err != nil {
		t.Fatal(err)
	}
	ref := got.Record.Context.Prior.Records[0]
	if ref.Verdict != "findings" || len(ref.Findings) != 1 || ref.Findings[0].Class != "review_issue" || !strings.HasPrefix(ref.Findings[0].SourceID, "prior:") || ref.Findings[0].SourceID == decision.Findings[0].SourceID {
		t.Fatalf("prior finding was promoted or lost: %+v", ref)
	}
	b, err := json.Marshal(got.Record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "comment:issue:17:101") || strings.Contains(string(b), "Old safe fixture.") {
		t.Fatal("prior raw ID or content escaped into record")
	}
	if !sameContext(fake.LastEnvelope().Context, *got.Record.Context) {
		t.Fatal("runner/stored context mismatch")
	}
}

func TestPriorHistoryRejectsMismatchesBeforeRunner(t *testing.T) {
	in, fake := withFake(t, fixtureInput("issue", "Safe fixture."))
	store := privateStore(t)
	first, err := Run(context.Background(), in, store)
	if err != nil {
		t.Fatal(err)
	}
	other, otherFake := withFake(t, fixtureInput("pull_request", "Safe fixture."))
	otherRecord, err := Run(context.Background(), other, store)
	if err != nil {
		t.Fatal(err)
	}
	for name, prior := range map[string]PriorHistory{
		"missing ID":       {CompletedCycles: 1},
		"extra ID":         {CompletedCycles: 0, LatestRecordIDs: []contracts.Hash{first.Record.RecordID}},
		"wrong target":     {CompletedCycles: 1, LatestRecordIDs: []contracts.Hash{otherRecord.Record.RecordID}},
		"unknown ID":       {CompletedCycles: 1, LatestRecordIDs: []contracts.Hash{contracts.Hash(strings.Repeat("a", 64))}},
		"duplicate IDs":    {CompletedCycles: 2, LatestRecordIDs: []contracts.Hash{first.Record.RecordID, first.Record.RecordID}},
		"over bound count": {CompletedCycles: 1_000_001, LatestRecordIDs: []contracts.Hash{first.Record.RecordID}},
		"nine IDs":         {CompletedCycles: 9, LatestRecordIDs: append([]contracts.Hash{first.Record.RecordID}, make([]contracts.Hash, 8)...)},
	} {
		t.Run(name, func(t *testing.T) {
			before := fake.Invocations()
			in.Prior = &prior
			got, err := Run(context.Background(), in, store)
			if err == nil || got.Record.RecordID != "" || fake.Invocations() != before {
				t.Fatalf("accepted bad prior: %+v %v", got, err)
			}
		})
	}
	if otherFake.Invocations() != 1 {
		t.Fatal("unexpected cross-target runner call")
	}
}

func TestPriorHistoryBeyondEightMarksCoverage(t *testing.T) {
	in, fake := withFake(t, fixtureInput("issue", "Safe fixture."))
	store := privateStore(t)
	ids := make([]contracts.Hash, 0, 8)
	for i := 0; i < 9; i++ {
		in.Trigger.DeliveryID = fmt.Sprintf("cycle-%d", i)
		r, err := Run(context.Background(), in, store)
		if err != nil {
			t.Fatal(err)
		}
		ids = append([]contracts.Hash{r.Record.RecordID}, ids...)
		if len(ids) > 8 {
			ids = ids[:8]
		}
	}
	in.Trigger.DeliveryID = "current-cycle"
	in.Prior = &PriorHistory{CompletedCycles: 9, LatestRecordIDs: ids}
	got, err := Run(context.Background(), in, store)
	if err != nil {
		t.Fatal(err)
	}
	c := got.Record.Context
	if c.Prior.CompletedCycles != 9 || c.Prior.OmittedCycles != 1 || len(c.Prior.Records) != 8 || !c.Prior.Truncated || !reflect.DeepEqual(c.Prior.TruncationReasons, []string{"cycles"}) || !c.Truncated || !reflect.DeepEqual(c.TruncationReasons, []string{"history"}) || c.OmittedEntries != 0 || c.Prior.Records[0].RecordID != ids[0] {
		t.Fatalf("history coverage not truthful: %+v", c)
	}
	if !sameContext(fake.LastEnvelope().Context, *c) {
		t.Fatal("envelope differs from stored context")
	}
}
