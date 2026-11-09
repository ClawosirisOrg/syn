// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fixture runs local synthetic, non-publishing reviews. Its inputs are
// not authenticated GitHub acquisitions or verified ownership.
package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/ClawOsirisOrg/syn/internal/config"
	"github.com/ClawOsirisOrg/syn/internal/contracts"
	"github.com/ClawOsirisOrg/syn/internal/history"
	"github.com/ClawOsirisOrg/syn/internal/recordstore"
	"github.com/ClawOsirisOrg/syn/internal/render"
	"github.com/ClawOsirisOrg/syn/internal/review"
	"github.com/ClawOsirisOrg/syn/internal/safety"
	"github.com/ClawOsirisOrg/syn/internal/source"
)

// Input is local fixture data only. Every source must remain untrusted.
// ApprovedDataClasses is a local operator choice, not an acquired permission.
type Input struct {
	Service             config.ServiceConfig
	Organization        config.OrganizationPolicy
	Profile             config.RepositoryProfile
	ApprovedDataClasses []string
	Target              contracts.Target
	Trigger             contracts.Trigger
	Selections          []source.Selection
	Acquired            []source.Acquired
	Safety              safety.Options
	Runner              *review.Fake
	Prior               *PriorHistory
}

// PriorHistory is supplied by a caller-owned authoritative cycle index. IDs
// must be the latest min(CompletedCycles, 8) records, newest first. This
// fixture validates records and coverage, but cannot establish freshness.
// A nil Prior leaves the local default at zero prior cycles.
type PriorHistory struct {
	CompletedCycles uint32
	LatestRecordIDs []contracts.Hash
}

// Result has no public body when review stops; Preview is a local dry run.
type Result struct {
	Record  contracts.CanonicalRecord
	Preview *render.Preview
}

func hash(domain string, value any) (contracts.Hash, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(append([]byte(domain+":"), b...))
	return contracts.Hash(hex.EncodeToString(d[:])), nil
}

func contextFor(m contracts.SourceManifest, policyVersion, profileVersion string, policyHash, profileHash contracts.Hash, prior contracts.PriorRecordProjection, priorEntries []contracts.ContextEntry) (contracts.ProjectContextManifest, error) {
	entries := []contracts.ContextEntry{
		{SourceID: "fixture:policy", Origin: "policy", Trust: "policy", Version: policyVersion, ContentHash: policyHash, Retention: "attempt_only"},
		{SourceID: "fixture:profile", Origin: "profile", Trust: "policy", Version: profileVersion, ContentHash: profileHash, Retention: "attempt_only"},
	}
	for _, s := range m.Sources {
		if s.Trust != "untrusted" {
			return contracts.ProjectContextManifest{}, errors.New("fixture cannot claim pinned guidance")
		}
		entries = append(entries, contracts.ContextEntry{SourceID: s.ID, Origin: "admitted_source", Trust: "untrusted", Version: "snapshot:" + string(m.SnapshotHash), ContentHash: s.ContentHash, Retention: "attempt_only"})
	}
	entries = append(entries, priorEntries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].SourceID < entries[j].SourceID })
	c := contracts.ProjectContextManifest{
		SchemaVersion: contracts.SchemaVersion, Target: m.Target, SnapshotHash: m.SnapshotHash, Entries: entries,
		TruncationReasons: []string{}, Prior: prior,
	}
	if prior.Truncated {
		c.Truncated = true
		c.TruncationReasons = []string{"history"}
	}
	var err error
	c.BundleHash, err = hash("syn-fixture-context-v1", c)
	if err != nil {
		return c, err
	}
	if err = c.Validate(); err != nil {
		return contracts.ProjectContextManifest{}, err
	}
	return c, nil
}

// canonicalFixtureID prevents caller-chosen source IDs from persisting arbitrary
// strings in safety findings or context entries. Build verifies the locator
// grammar, target binding and canonical numeric components separately.
func canonicalFixtureID(s source.Selection) bool {
	if s.ID != s.Locator || len(s.ID) > 100 {
		return false
	}
	switch s.Type {
	case "issue", "pull_request", "diff", "comment", "review", "review_comment":
		return true
	default:
		return false
	}
}

// Run has no GitHub, provider, or publisher client and only accepts the local
// fake runner. Custom safety detectors still require caller isolation and must
// not make external calls. Synthetic ownership grants no live authorization.
func Run(ctx context.Context, in Input, store *recordstore.Store) (Result, error) {
	if ctx == nil || store == nil || in.Runner == nil {
		return Result{}, errors.New("fixture requires context, store and local runner")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	// Check the caller-supplied shape before hashing, without treating its
	// delivery ID as authenticated. Never persist or print that raw string.
	if err := (contracts.DeliveryReceipt{SchemaVersion: contracts.SchemaVersion, Target: in.Target, Trigger: in.Trigger, Outcome: "accepted"}).Validate(); err != nil {
		return Result{}, err
	}
	deliveryHash, err := hash("syn-fixture-delivery-v1", in.Trigger.DeliveryID)
	if err != nil {
		return Result{}, err
	}
	trigger := in.Trigger
	trigger.DeliveryID = "fixture:" + string(deliveryHash)
	if err := (contracts.DeliveryReceipt{SchemaVersion: contracts.SchemaVersion, Target: in.Target, Trigger: trigger, Outcome: "accepted"}).Validate(); err != nil {
		return Result{}, err
	}
	// Direct Go config values bypass parser byte limits; impose the same local
	// ceiling before hashing/retaining their provenance.
	configBytes, err := json.Marshal(struct {
		Service      config.ServiceConfig
		Organization config.OrganizationPolicy
		Profile      config.RepositoryProfile
	}{in.Service, in.Organization, in.Profile})
	if err != nil || len(configBytes) > 1<<20 {
		return Result{}, errors.New("fixture policy metadata exceeds bound")
	}
	event := in.Trigger.Event + "/" + in.Trigger.Action
	eff, err := config.Resolve(in.Service, in.Organization, in.Profile, in.Target.Repository, event, config.Credentials{}, config.Runtime{Phase: config.RolloutFixture, ApprovedDataClasses: in.ApprovedDataClasses})
	if err != nil {
		return Result{}, err
	}
	if !eff.FixtureReview {
		return Result{}, errors.New("fixture review not allowed by effective policy")
	}
	// No implicit discovery: only explicit caller-owned history is considered.
	// Reject inconsistent counts/IDs before running the model.
	prior, priorEntries, err := history.Project(store, in.Target, 0, nil)
	if in.Prior != nil {
		prior, priorEntries, err = history.Project(store, in.Target, in.Prior.CompletedCycles, in.Prior.LatestRecordIDs)
	}
	if err != nil {
		return Result{}, fmt.Errorf("project fixture history: %w", err)
	}
	if len(in.Selections) == 0 || len(in.Selections) > safety.MaxSources {
		return Result{}, errors.New("fixture source count outside safety bound")
	}
	for _, s := range in.Selections {
		if s.Trust != "untrusted" || s.PinnedCommit != "" || s.DefaultBranch != "" || s.Type == "guidance" || !canonicalFixtureID(s) {
			return Result{}, errors.New("fixture requires untrusted canonical conversation source identities")
		}
	}
	for _, a := range in.Acquired {
		if a.Guidance != nil {
			return Result{}, errors.New("fixture cannot use guidance witness")
		}
	}
	snap, err := source.Build(in.Target, in.Selections, in.Acquired, source.Limits{MaxSources: safety.MaxSources, MaxSourceBytes: safety.MaxSourceBytes, MaxTotalBytes: safety.MaxTotalBytes})
	if err != nil {
		return Result{}, fmt.Errorf("build fixture snapshot: %w", err)
	}
	m := snap.Manifest()
	manifestHash, err := hash("syn-fixture-manifest-v1", m)
	if err != nil {
		return Result{}, err
	}
	policyHash, err := hash("syn-fixture-policy-v1", struct {
		Service      config.ServiceConfig
		Organization config.OrganizationPolicy
	}{in.Service, in.Organization})
	if err != nil {
		return Result{}, err
	}
	profileHash, err := hash("syn-fixture-profile-v1", in.Profile)
	if err != nil {
		return Result{}, err
	}
	policyVersion := "fixture-only-policy-v1:" + string(policyHash)
	profileVersion := "fixture-only-profile-v1:" + string(profileHash)
	c, err := contextFor(m, policyVersion, profileVersion, policyHash, profileHash, prior, priorEntries)
	if err != nil {
		return Result{}, err
	}
	r := contracts.CanonicalRecord{SchemaVersion: contracts.SchemaVersion, Target: in.Target, Trigger: trigger,
		ManifestHash: manifestHash, SnapshotHash: m.SnapshotHash, PolicyVersion: policyVersion, ProfileVersion: profileVersion,
		GateVersion: safety.GateVersion, PublicationIntent: "none", TerminalErrorClass: "safety"}
	decision, checked, err := review.Execute(ctx, snap, in.Safety, c, review.Disabled{}, in.Runner)
	r.Safety = checked.Safety
	if errors.Is(err, review.ErrNotAdmitted) {
		switch r.Safety.Outcome {
		case "quarantine":
			r.RuntimeOutcome = "quarantined"
		case "refuse":
			r.RuntimeOutcome = "refused"
		default:
			return Result{}, errors.New("non-safety review restriction")
		}
	} else if err != nil {
		return Result{}, fmt.Errorf("fixture review: %w", err)
	} else {
		if err := contracts.ValidateReferences(m, r.Safety, &decision, &c); err != nil {
			return Result{}, err
		}
		r.Context = &c
		r.ContextBundleHash = c.BundleHash
		// These are deliberately synthetic, non-authorizing fixture identities.
		r.Ownership = &contracts.ResolvedOwnership{ReviewOwnerID: "fixture-only", PublisherAppID: 1}
		r.Runner = &contracts.Runner{Name: "fixture-only", Version: "v1", Provider: "none", Model: "synthetic", Adapter: "fixture", AdapterVersion: "v1"}
		r.Decision = &decision
		r.TerminalErrorClass = "none"
		r.RuntimeOutcome = "reviewed"
		// render requires advisory_comment for preview. This is NEVER live
		// publication eligibility: see README.md for mandatory publisher gates.
		r.PublicationIntent = "advisory_comment"
	}
	r.RecordID, err = hash("syn-fixture-record-v1", r)
	if err != nil {
		return Result{}, err
	}
	if err := r.Validate(); err != nil {
		return Result{}, fmt.Errorf("fixture record: %w", err)
	}
	if err := store.Put(r); err != nil {
		return Result{}, fmt.Errorf("persist fixture record: %w", err)
	}
	stored, err := store.Get(r.RecordID)
	if err != nil {
		return Result{}, fmt.Errorf("read fixture record: %w", err)
	}
	result := Result{Record: stored}
	if r.RuntimeOutcome != "reviewed" {
		return result, nil
	}
	preview, err := render.CreatePreview(store, r.RecordID)
	if err != nil {
		return Result{}, fmt.Errorf("render stored fixture: %w", err)
	}
	result.Preview = &preview
	return result, nil
}
