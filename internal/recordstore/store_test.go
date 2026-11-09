// SPDX-License-Identifier: AGPL-3.0-or-later

package recordstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ClawOsirisOrg/syn/internal/contracts"
)

const id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func fixture() contracts.CanonicalRecord {
	return contracts.CanonicalRecord{
		SchemaVersion: 1, RecordID: id,
		Target:       contracts.Target{Repository: "owner/repo", Kind: "issue", Number: 12},
		Trigger:      contracts.Trigger{DeliveryID: "d1", Event: "issues", Action: "opened", InstallationID: 1, ActorID: 2},
		ManifestHash: digest, SnapshotHash: digest, PolicyVersion: "p1", ProfileVersion: "r1", GateVersion: "g1",
		Safety:             contracts.SafetyResult{SchemaVersion: 1, SnapshotHash: digest, GateVersion: "g1", Outcome: "refuse", Findings: []contracts.Finding{}},
		TerminalErrorClass: "safety", PublicationIntent: "none", RuntimeOutcome: "refused",
	}
}
func setup(t *testing.T) (*Store, string) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}
func TestPutGetRetryAndConflict(t *testing.T) {
	s, path := setup(t)
	r := fixture()
	if err := s.Put(r); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(r); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(r.RecordID)
	if err != nil || got.RecordID != r.RecordID || got.RuntimeOutcome != r.RuntimeOutcome {
		t.Fatalf("get: %v", err)
	}
	other := r
	other.PolicyVersion = "p2"
	if err := s.Put(other); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	got, err = s.Get(r.RecordID)
	if err != nil || got.PolicyVersion != "p1" {
		t.Fatalf("overwritten: %v", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 || entries[0].Name() != id+".json" {
		t.Fatalf("unexpected files: %v %v", entries, err)
	}
}
func TestConcurrentWritersNeverOverwrite(t *testing.T) {
	s, _ := setup(t)
	first := fixture()
	second := first
	second.PolicyVersion = "p2"
	var wg sync.WaitGroup
	results := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				results <- s.Put(first)
			} else {
				results <- s.Put(second)
			}
		}(i)
	}
	wg.Wait()
	close(results)
	good, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			good++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Errorf("unexpected concurrent error: %v", err)
		}
	}
	if good == 0 || conflicts == 0 {
		t.Fatalf("successes=%d conflicts=%d", good, conflicts)
	}
	got, err := s.Get(first.RecordID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicyVersion != "p1" && got.PolicyVersion != "p2" {
		t.Fatalf("wrong winner: %q", got.PolicyVersion)
	}
}
func TestInvalidInputsNeverWritten(t *testing.T) {
	s, path := setup(t)
	cases := []contracts.CanonicalRecord{fixture(), fixture(), fixture(), fixture()}
	cases[0].RecordID = "../../escape"
	cases[1].Safety.Outcome = "pass"
	cases[2].Trigger.DeliveryID = "https://host/?secret=x"
	cases[3].Safety.Findings = []contracts.Finding{{Class: "invalid", SourceID: "a", ReferenceHash: digest}}
	for _, r := range cases {
		if err := s.Put(r); err == nil {
			t.Error("accepted invalid record")
		}
	}
	for _, bad := range []contracts.Hash{"../escape", contracts.Hash(strings.ToUpper(id)), "", id + "/../x"} {
		if _, err := s.Get(bad); err == nil {
			t.Errorf("accepted invalid ID")
		}
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("invalid writes: %v %v", entries, err)
	}
}
func TestCorruptAndUnsafeStoredFiles(t *testing.T) {
	s, path := setup(t)
	r := fixture()
	name := filepath.Join(path, id+".json")
	good, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty": {}, "malformed": []byte("{"), "trailing": append(bytes.Clone(good), []byte(" {}")...),
		"whitespace": append(bytes.Clone(good), '\n'),
		"unknown":    bytes.Replace(good, []byte("\"record_id\""), []byte("\"unknown\":1,\"record_id\""), 1),
		"duplicate":  bytes.Replace(good, []byte("\"record_id\""), []byte("\"record_id\":\"x\",\"record_id\""), 1),
		"wrong id":   bytes.Replace(good, []byte(id), []byte(digest), 1),
		"oversized":  bytes.Repeat([]byte("x"), maxRecordBytes+1),
	}
	for label, data := range cases {
		t.Run(label, func(t *testing.T) {
			if err := os.WriteFile(name, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Get(r.RecordID); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Get: %v", err)
			}
			if err := s.Put(r); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Put: %v", err)
			}
		})
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, good, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(r.RecordID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("public record: %v", err)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(r.RecordID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("directory record: %v", err)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, good, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, name); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(r.RecordID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("symlink Get: %v", err)
	}
	if err := s.Put(r); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("symlink Put: %v", err)
	}
	contents, err := os.ReadFile(outside)
	if err != nil || !bytes.Equal(contents, good) {
		t.Fatal("external file changed")
	}
}
func TestRootProtection(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("missing root")
	}
	if _, err := New("relative"); err == nil {
		t.Fatal("relative root")
	}
	if _, err := New(dir + "/../" + filepath.Base(dir)); err == nil {
		t.Fatal("unclean root")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(link); err == nil {
		t.Fatal("symlink root")
	}
	if _, err := New(filepath.Join(link, "child")); err == nil {
		t.Fatal("symlink parent")
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir); err == nil {
		t.Fatal("public root")
	}
}
