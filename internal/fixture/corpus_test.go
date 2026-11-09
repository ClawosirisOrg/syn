// SPDX-License-Identifier: AGPL-3.0-or-later

package fixture

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ClawOsirisOrg/syn/internal/review"
	"github.com/ClawOsirisOrg/syn/internal/safety"
	"github.com/ClawOsirisOrg/syn/internal/source"
)

// Corpus files are generated test data, not authenticated acquisitions.
func corpusBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 || len(b) > 1024 {
		t.Fatalf("fixture %s is missing or unbounded", name)
	}
	return b
}

type corpusPart struct{ path, sourceType, id string }

func corpusInput(t *testing.T, kind string, parts ...corpusPart) Input {
	t.Helper()
	if len(parts) == 0 {
		t.Fatal("empty corpus source set")
	}
	in := fixtureInput(kind, string(corpusBytes(t, parts[0].path)))
	for _, part := range parts[1:] {
		body := corpusBytes(t, part.path)
		in.Selections = append(in.Selections, source.Selection{ID: part.id, Type: part.sourceType, Locator: part.id, Trust: "untrusted"})
		in.Acquired = append(in.Acquired, source.Acquired{ID: part.id, Body: body, Complete: true, Stable: true, AcquiredAt: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)})
	}
	return in
}

func TestSyntheticCorpusAdmitted(t *testing.T) {
	cases := []struct {
		name, kind string
		parts      []corpusPart
	}{
		{"via-issue", "issue", []corpusPart{{path: "benign/via-issue.txt"}, {"benign/via-comment.txt", "comment", "comment:issue:17:101"}}},
		{"via-pr", "pull_request", []corpusPart{{path: "benign/via-pr.txt"}, {"benign/via-pr.diff", "diff", "diff:pull:17"}, {"benign/via-review.txt", "review", "review:pull:17:201"}}},
		{"alert-proxy", "issue", []corpusPart{{path: "benign/alert-issue.txt"}, {"benign/alert-comment.txt", "comment", "comment:issue:17:102"}}},
		{"lookalike-prose", "issue", []corpusPart{{path: "benign/lookalike-policy.txt"}, {"benign/lookalike-url.txt", "comment", "comment:issue:17:103"}}},
		{"lookalike-diff", "pull_request", []corpusPart{{path: "benign/via-pr.txt"}, {"benign/lookalike.diff", "diff", "diff:pull:17"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, fake := withFake(t, corpusInput(t, tc.kind, tc.parts...))
			store := privateStore(t)
			first, err := Run(context.Background(), in, store)
			if err != nil {
				t.Fatal(err)
			}
			second, err := Run(context.Background(), in, store)
			if err != nil {
				t.Fatal(err)
			}
			if fake.Invocations() != 2 || first.Record.RuntimeOutcome != "reviewed" || first.Record.Safety.Outcome != "pass" || first.Preview == nil || second.Preview == nil {
				t.Fatalf("benign corpus was not reviewed: outcome=%s calls=%d", first.Record.RuntimeOutcome, fake.Invocations())
			}
			if first.Record.RecordID != second.Record.RecordID || first.Record.SnapshotHash != second.Record.SnapshotHash || first.Preview.Marker != second.Preview.Marker || first.Preview.Body != second.Preview.Body || first.Preview.RecordID != first.Record.RecordID {
				t.Fatal("local record or preview is nondeterministic")
			}
			got, err := store.Get(first.Record.RecordID)
			if err != nil || !reflect.DeepEqual(got, first.Record) {
				t.Fatalf("record was not persisted: %v", err)
			}
			envelope := fake.LastEnvelope()
			if len(envelope.Sources) != len(in.Selections) || envelope.SnapshotHash != first.Record.SnapshotHash || envelope.Context.BundleHash != first.Record.ContextBundleHash {
				t.Fatal("fake runner received incomplete or divergent provenance")
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			for _, part := range tc.parts {
				raw := strings.TrimSpace(string(corpusBytes(t, part.path)))
				if strings.Contains(string(encoded), raw) || strings.Contains(first.Preview.Body, raw) {
					t.Fatalf("source text escaped into record or preview: %s", part.path)
				}
			}
		})
	}
}

func TestSyntheticCorpusUnsafeStopsBeforeRunner(t *testing.T) {
	cases := []struct {
		name, kind, path, class string
		indirect                bool
	}{
		{"direct", "issue", "adversarial/direct.txt", "prompt_injection", false},
		{"indirect-review", "pull_request", "adversarial/indirect-review.txt", "prompt_injection", true},
		{"base64", "issue", "adversarial/encoded-base64.txt", "encoded_instruction", false},
		{"private-url", "issue", "adversarial/private-url.txt", "unsafe_path", false},
		{"credential-url", "issue", "adversarial/credential-url.txt", "exfiltration", false},
		{"secret", "issue", "adversarial/secret.txt", "secret", false},
		{"security-report", "issue", "adversarial/security-report.txt", "security_report", false},
		{"unsafe-path", "issue", "adversarial/unsafe-path.txt", "unsafe_path", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var in Input
			if tc.indirect {
				in = corpusInput(t, tc.kind, corpusPart{path: "benign/via-pr.txt"}, corpusPart{tc.path, "review", "review:pull:17:202"})
			} else {
				in = corpusInput(t, tc.kind, corpusPart{path: tc.path})
			}
			in, fake := withFake(t, in)
			store := privateStore(t)
			got, err := Run(context.Background(), in, store)
			if err != nil {
				t.Fatal(err)
			}
			if fake.Invocations() != 0 || got.Preview != nil || got.Record.RuntimeOutcome != "quarantined" || got.Record.Safety.Outcome != "quarantine" {
				t.Fatalf("unsafe corpus reached runner or preview: outcome=%s calls=%d", got.Record.RuntimeOutcome, fake.Invocations())
			}
			found := false
			for _, f := range got.Record.Safety.Findings {
				if f.Class == tc.class {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing safety class %s: %+v", tc.class, got.Record.Safety.Findings)
			}
			r := got.Record
			if r.Context != nil || r.Decision != nil || r.Runner != nil || r.Ownership != nil || r.ContextBundleHash != "" || r.PublicationIntent != "none" {
				t.Fatal("unsafe body produced reviewed context or publication intent")
			}
			persisted, err := store.Get(r.RecordID)
			if err != nil || !reflect.DeepEqual(persisted, r) {
				t.Fatalf("stopped record not persisted: %v", err)
			}
			serialized, err := json.Marshal(persisted)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(serialized), strings.TrimSpace(string(corpusBytes(t, tc.path)))) {
				t.Fatal("unsafe source retained in record")
			}
		})
	}
}

func TestSyntheticCorpusUnsupportedFailsBeforeRunner(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*testing.T) Input
	}{
		{"binary-diff", func(t *testing.T) Input {
			return corpusInput(t, "pull_request", corpusPart{path: "benign/via-pr.txt"}, corpusPart{"unsupported/binary.diff", "diff", "diff:pull:17"})
		}},
		{"textual-binary-diff", func(t *testing.T) Input {
			return corpusInput(t, "pull_request", corpusPart{path: "benign/via-pr.txt"}, corpusPart{"unsupported/textual-binary.diff", "diff", "diff:pull:17"})
		}},
		{"unsafe-diff-path", func(t *testing.T) Input {
			return corpusInput(t, "pull_request", corpusPart{path: "benign/via-pr.txt"}, corpusPart{"unsupported/unsafe-path.diff", "diff", "diff:pull:17"})
		}},
		{"binary-body", func(t *testing.T) Input {
			return corpusInput(t, "issue", corpusPart{path: "unsupported/binary-body.bin"})
		}},
		{"oversized", func(t *testing.T) Input {
			in := corpusInput(t, "issue", corpusPart{path: "unsupported/oversized-seed.txt"})
			in.Acquired[0].Body = []byte(strings.Repeat(string(in.Acquired[0].Body), safety.MaxSourceBytes/len(in.Acquired[0].Body)+1))
			return in
		}},
		{"incomplete", func(t *testing.T) Input {
			in := corpusInput(t, "issue", corpusPart{path: "unsupported/incomplete-seed.txt"})
			in.Acquired[0].Complete = false
			return in
		}},
		{"missing", func(t *testing.T) Input {
			in := corpusInput(t, "issue", corpusPart{path: "unsupported/incomplete-seed.txt"})
			in.Acquired = nil
			return in
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.prepare(t)
			fake := review.NewFake(nil)
			in.Runner = fake
			got, err := Run(context.Background(), in, privateStore(t))
			if err == nil || got.Preview != nil || got.Record.RecordID != "" || fake.Invocations() != 0 {
				t.Fatalf("unsupported source was admitted: err=%v calls=%d", err, fake.Invocations())
			}
		})
	}
}
