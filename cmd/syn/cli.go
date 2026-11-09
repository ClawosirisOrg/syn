// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ClawOsirisOrg/syn/internal/config"
	"github.com/ClawOsirisOrg/syn/internal/contracts"
	"github.com/ClawOsirisOrg/syn/internal/fixture"
	"github.com/ClawOsirisOrg/syn/internal/recordstore"
	"github.com/ClawOsirisOrg/syn/internal/review"
	"github.com/ClawOsirisOrg/syn/internal/source"
)

const maxFixtureBytes = 256 << 10

type policies struct {
	service config.ServiceConfig
	org     config.OrganizationPolicy
	profile config.RepositoryProfile
}

func boundedFile(path string, max int) ([]byte, error) {
	if path == "" || path == "-" {
		return nil, errors.New("explicit regular file required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > int64(max) {
		return nil, errors.New("file empty, nonregular, or oversized")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || len(b) > max || int64(len(b)) != st.Size() {
		return nil, errors.New("file changed or oversized")
	}
	return b, nil
}
func loadPolicies(servicePath, orgPath, profilePath string) (policies, error) {
	return loadPoliciesContext(context.Background(), servicePath, orgPath, profilePath)
}
func loadPoliciesContext(ctx context.Context, servicePath, orgPath, profilePath string) (policies, error) {
	var p policies
	for i, path := range []string{servicePath, orgPath, profilePath} {
		if err := ctx.Err(); err != nil {
			return policies{}, err
		}
		b, err := boundedFile(path, 1<<20)
		if ctx.Err() != nil {
			return policies{}, ctx.Err()
		}
		if err != nil {
			return policies{}, fmt.Errorf("policy file %d: %w", i+1, err)
		}
		format := strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
		switch i {
		case 0:
			p.service, err = config.ParseService(b, format)
		case 1:
			p.org, err = config.ParseOrganization(b, format)
		case 2:
			p.profile, err = config.ParseRepository(b, format)
		}
		if ctx.Err() != nil {
			return policies{}, ctx.Err()
		}
		if err != nil {
			return policies{}, fmt.Errorf("invalid policy %d: %w", i+1, err)
		}
	}
	return p, nil
}
func policyFlags(f *flag.FlagSet) (service, org, profile *string) {
	service = f.String("service", "", "explicit service YAML/JSON file")
	org = f.String("organization", "", "explicit organization YAML/JSON file")
	profile = f.String("profile", "", "explicit repository YAML/JSON file")
	return
}
func parseFlags(f *flag.FlagSet, args []string, errout io.Writer) bool {
	f.SetOutput(errout)
	return f.Parse(args) == nil && f.NArg() == 0
}
func fail(errout io.Writer, code int, reason string) int { fmt.Fprintln(errout, reason); return code }
func validateConfig(args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	service, org, profile := policyFlags(f)
	repository := f.String("repository", "", "repository owner/name")
	event := f.String("event", "", "event/action")
	dataClass := f.String("approved-data-class", "", "operator-approved data class for fixture eligibility")
	if !parseFlags(f, args, stderr) {
		return fail(stderr, 2, "invalid validate-config arguments")
	}
	if *repository == "" || *event == "" {
		return fail(stderr, 2, "repository and event required")
	}
	p, err := loadPolicies(*service, *org, *profile)
	if err != nil {
		return fail(stderr, 2, err.Error())
	}
	approved := []string{}
	if *dataClass != "" {
		approved = append(approved, *dataClass)
	}
	eff, err := config.Resolve(p.service, p.org, p.profile, *repository, *event, config.Credentials{}, config.Runtime{Phase: config.RolloutFixture, ApprovedDataClasses: approved})
	if err != nil {
		return fail(stderr, 2, "invalid effective policy references")
	}
	out := struct {
		Repository      string `json:"repository"`
		Event           string `json:"event"`
		FixtureReview   bool   `json:"fixture_review"`
		LiveIntake      bool   `json:"live_intake"`
		LivePublication bool   `json:"live_publication"`
	}{*repository, *event, eff.FixtureReview, false, false}
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		return fail(stderr, 5, "output failed")
	}
	return 0
}

type fixtureSource struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Body       string `json:"body"`
	AcquiredAt string `json:"acquired_at"`
}
type fixtureSpec struct {
	Target  contracts.Target  `json:"target"`
	Trigger contracts.Trigger `json:"trigger"`
	Sources []fixtureSource   `json:"sources"`
}

// Reject duplicate keys, null, excessive nesting and all unknown/noncanonical keys
// before decoding: encoding/json alone silently accepts duplicate/case-folded keys.
func checkJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 8 {
			return errors.New("nesting limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := k.(string)
				if !ok || seen[name] {
					return errors.New("duplicate or invalid key")
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case nil:
			return errors.New("null not allowed")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}
func exactKeys(data []byte, permitted map[string]any) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return errors.New("expected object")
	}
	for key, val := range fields {
		nested, ok := permitted[key]
		if !ok {
			return errors.New("unknown key")
		}
		switch v := nested.(type) {
		case map[string]any:
			if err := exactKeys(val, v); err != nil {
				return err
			}
		case []map[string]any:
			var list []json.RawMessage
			if err := json.Unmarshal(val, &list); err != nil {
				return err
			}
			for _, item := range list {
				if err := exactKeys(item, v[0]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func parseFixture(data []byte) (fixtureSpec, error) {
	var s fixtureSpec
	if len(data) == 0 || len(data) > maxFixtureBytes || !utf8.Valid(data) {
		return s, errors.New("invalid fixture size or encoding")
	}
	if err := checkJSON(data); err != nil {
		return s, err
	}
	keys := map[string]any{"target": map[string]any{"repository": nil, "kind": nil, "number": nil}, "trigger": map[string]any{"delivery_id": nil, "event": nil, "action": nil, "installation_id": nil, "actor_id": nil, "subject_id": nil}, "sources": []map[string]any{{"id": nil, "type": nil, "body": nil, "acquired_at": nil}}}
	if err := exactKeys(data, keys); err != nil {
		return s, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return s, err
	}
	if len(s.Sources) == 0 || len(s.Sources) > 16 {
		return s, errors.New("invalid source count")
	}
	total := 0
	for _, src := range s.Sources {
		if src.ID == "" || len(src.ID) > 100 || len(src.Body) > 32<<10 || src.AcquiredAt == "" {
			return s, errors.New("invalid source size or identity")
		}
		total += len(src.Body)
	}
	if total > 128<<10 {
		return s, errors.New("fixture source bytes exceed limit")
	}
	return s, nil
}
func reviewFixture(args []string, stdout, stderr io.Writer) int {
	return reviewFixtureWithDeadline(args, stdout, stderr, func(timeout time.Duration) (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), timeout)
	})
}

func reviewFixtureWithDeadline(args []string, stdout, stderr io.Writer, deadline func(time.Duration) (context.Context, context.CancelFunc)) int {
	f := flag.NewFlagSet("review-fixture", flag.ContinueOnError)
	service, org, profile := policyFlags(f)
	specPath := f.String("spec", "", "explicit bounded JSON fixture file")
	root := f.String("record-root", "", "existing private absolute operator-owned record directory")
	dataClass := f.String("approved-data-class", "", "explicit operator-approved data class")
	timeout := f.Duration("timeout", 5*time.Second, "local deadline (maximum 30s)")
	if !parseFlags(f, args, stderr) {
		return fail(stderr, 2, "invalid review-fixture arguments")
	}
	if *root == "" || *dataClass == "" || *timeout <= 0 || *timeout > 30*time.Second {
		return fail(stderr, 2, "record-root, approved-data-class and bounded timeout required")
	}
	ctx, cancel := deadline(*timeout)
	defer cancel()
	checkDeadline := func() bool { return ctx.Err() != nil }
	deadlineFailure := func() int { return fail(stderr, 124, "fixture deadline or cancellation") }
	if checkDeadline() {
		return deadlineFailure()
	}
	p, err := loadPoliciesContext(ctx, *service, *org, *profile)
	if checkDeadline() {
		return deadlineFailure()
	}
	if err != nil {
		return fail(stderr, 2, err.Error())
	}
	data, err := boundedFile(*specPath, maxFixtureBytes)
	if checkDeadline() {
		return deadlineFailure()
	}
	if err != nil {
		return fail(stderr, 2, "invalid fixture file")
	}
	spec, err := parseFixture(data)
	if checkDeadline() {
		return deadlineFailure()
	}
	if err != nil {
		return fail(stderr, 2, "invalid fixture JSON")
	}
	event := spec.Trigger.Event + "/" + spec.Trigger.Action
	eff, err := config.Resolve(p.service, p.org, p.profile, spec.Target.Repository, event, config.Credentials{}, config.Runtime{Phase: config.RolloutFixture, ApprovedDataClasses: []string{*dataClass}})
	if checkDeadline() {
		return deadlineFailure()
	}
	if err != nil || !eff.FixtureReview {
		return fail(stderr, 2, "fixture denied by effective policy")
	}
	in := fixture.Input{Service: p.service, Organization: p.org, Profile: p.profile, ApprovedDataClasses: []string{*dataClass}, Target: spec.Target, Trigger: spec.Trigger}
	for _, src := range spec.Sources {
		if checkDeadline() {
			return deadlineFailure()
		}
		at, err := time.Parse(time.RFC3339Nano, src.AcquiredAt)
		if checkDeadline() {
			return deadlineFailure()
		}
		if err != nil || at.IsZero() {
			return fail(stderr, 2, "invalid source acquisition time")
		}
		in.Selections = append(in.Selections, source.Selection{ID: src.ID, Type: src.Type, Locator: src.ID, Trust: "untrusted"})
		in.Acquired = append(in.Acquired, source.Acquired{ID: src.ID, Body: []byte(src.Body), AcquiredAt: at, Complete: true, Stable: true})
	}
	if checkDeadline() {
		return deadlineFailure()
	}
	snap, err := source.Build(in.Target, in.Selections, in.Acquired, source.Limits{MaxSources: 16, MaxSourceBytes: 32 << 10, MaxTotalBytes: 128 << 10})
	if checkDeadline() {
		return deadlineFailure()
	}
	if err != nil {
		return fail(stderr, 2, "invalid fixture source set")
	}
	response, err := review.NoFindingsJSON(snap.Manifest().SnapshotHash)
	if checkDeadline() {
		return deadlineFailure()
	}
	if err != nil {
		return fail(stderr, 5, "local runner setup failed")
	}
	in.Runner = review.NewFake(response)
	if checkDeadline() {
		return deadlineFailure()
	}
	store, err := recordstore.New(*root)
	if checkDeadline() {
		if err == nil {
			store.Close()
		}
		return deadlineFailure()
	}
	if err != nil {
		return fail(stderr, 2, "invalid private record root")
	}
	defer store.Close()
	if checkDeadline() {
		return deadlineFailure()
	}
	result, err := fixture.Run(ctx, in, store)
	if err != nil {
		if checkDeadline() {
			return deadlineFailure()
		}
		return fail(stderr, 5, "local fixture failed")
	}
	if checkDeadline() {
		return deadlineFailure()
	}
	path := filepath.Join(*root, string(result.Record.RecordID)+".json")
	out := struct {
		RecordID   contracts.Hash `json:"record_id"`
		RecordPath string         `json:"record_path"`
		Outcome    string         `json:"outcome"`
		DryRun     *struct {
			Operation string `json:"operation"`
			Body      string `json:"body"`
		} `json:"dry_run,omitempty"`
	}{RecordID: result.Record.RecordID, RecordPath: path, Outcome: result.Record.RuntimeOutcome}
	code := 3
	if result.Preview != nil && result.Record.RuntimeOutcome == "reviewed" {
		out.DryRun = &struct {
			Operation string `json:"operation"`
			Body      string `json:"body"`
		}{Operation: "CREATE", Body: result.Preview.Body}
		code = 0
	}
	if checkDeadline() {
		return deadlineFailure()
	}
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		return fail(stderr, 5, "output failed")
	}
	return code
}
