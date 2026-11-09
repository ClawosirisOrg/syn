// SPDX-License-Identifier: AGPL-3.0-or-later

// Package review contains the non-networked Phase 1 decision and fixture runner
// seams. No GitHub or provider credential enters this package.
package review

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/ClawOsirisOrg/syn/internal/contracts"
	"github.com/ClawOsirisOrg/syn/internal/safety"
	"github.com/ClawOsirisOrg/syn/internal/source"
)

var ErrNotAdmitted = errors.New("review blocked by deterministic safety")

// DecisionEngine may make admission stricter, never more permissive.
type DecisionEngine interface {
	Assess(context.Context, contracts.SafetyResult) (contracts.DecisionAssessment, error)
}

// Disabled is a fully functional, non-authorizing default decision engine.
type Disabled struct{}

func (Disabled) Assess(ctx context.Context, safety contracts.SafetyResult) (contracts.DecisionAssessment, error) {
	if err := ctx.Err(); err != nil {
		return contracts.DecisionAssessment{}, err
	}
	if err := safety.Validate(); err != nil {
		return contracts.DecisionAssessment{}, err
	}
	return contracts.DecisionAssessment{EngineID: "disabled", EngineVersion: "v1", Disposition: "abstain"}, nil
}

// Envelope contains only preflight-sanctioned, provenance-labelled data. It has
// no credential, tool, filesystem or arbitrary network capability.
type Envelope struct {
	SnapshotHash contracts.Hash
	Sources      []safety.SanitizedSource
	Context      contracts.ProjectContextManifest
}

func (e Envelope) clone() Envelope {
	e.Sources = slices.Clone(e.Sources)
	e.Context.Entries = slices.Clone(e.Context.Entries)
	e.Context.TruncationReasons = slices.Clone(e.Context.TruncationReasons)
	e.Context.Prior.TruncationReasons = slices.Clone(e.Context.Prior.TruncationReasons)
	e.Context.Prior.Records = slices.Clone(e.Context.Prior.Records)
	for i := range e.Context.Prior.Records {
		e.Context.Prior.Records[i].Findings = slices.Clone(e.Context.Prior.Records[i].Findings)
	}
	return e
}

// Runner returns strict JSON rather than a Go value to exercise output validation.
// Real adapters must additionally prove process/credential/network isolation.
type Runner interface {
	Run(context.Context, Envelope) ([]byte, error)
}

// Fake is deterministic, local, and has an observable invocation count. The
// provided response is fixture data, not an authority or a capability grant.
type Fake struct {
	response []byte
	calls    atomic.Uint64
	mu       sync.Mutex
	last     Envelope
}

func NewFake(response []byte) *Fake {
	return &Fake{response: append([]byte(nil), response...)}
}

func (f *Fake) Invocations() uint64    { return f.calls.Load() }
func (f *Fake) LastEnvelope() Envelope { f.mu.Lock(); defer f.mu.Unlock(); return f.last.clone() }
func (f *Fake) Run(ctx context.Context, e Envelope) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.last = e.clone()
	f.mu.Unlock()
	f.calls.Add(1)
	return append([]byte(nil), f.response...), nil
}

// Execute derives preflight from an immutable local snapshot; a caller cannot
// provide a fabricated passing SafetyResult. Snapshot provenance still requires
// authoritative acquisition before this local-only fixture boundary is used.
// No decision, runner, or renderer may grant GitHub publication rights.
func Execute(ctx context.Context, snap source.Snapshot, opt safety.Options, contextManifest contracts.ProjectContextManifest, engine DecisionEngine, runner Runner) (contracts.ReviewDecision, safety.Result, error) {
	var zero contracts.ReviewDecision
	var stopped safety.Result
	if ctx == nil {
		return zero, stopped, errors.New("nil review context")
	}
	if err := ctx.Err(); err != nil {
		return zero, stopped, err
	}
	if err := snap.Verify(); err != nil {
		return zero, stopped, err
	}
	manifest := snap.Manifest()
	sources := make([]safety.Source, 0, len(manifest.Sources))
	for _, entry := range manifest.Sources {
		text, ok := snap.Text(entry.ID)
		if !ok {
			return zero, stopped, errors.New("missing snapshot body")
		}
		sources = append(sources, safety.Source{ID: entry.ID, Body: []byte(text), Complete: true})
	}
	result, err := safety.Check(ctx, manifest, sources, opt)
	if err != nil {
		return zero, stopped, err
	}
	stopped.Safety = result.Safety // failures never return a public envelope
	if err := contracts.ValidateReferences(manifest, result.Safety, nil, nil); err != nil {
		return zero, stopped, err
	}
	if result.Safety.Outcome != "pass" && result.Safety.Outcome != "pass_with_redactions" {
		return zero, stopped, ErrNotAdmitted
	}
	if err := contracts.ValidateReferences(manifest, result.Safety, nil, &contextManifest); err != nil {
		return zero, stopped, err
	}
	if engine == nil || runner == nil {
		return zero, stopped, errors.New("review engine and runner required")
	}
	assessment, err := engine.Assess(ctx, result.Safety)
	if err != nil {
		return zero, stopped, err
	}
	if assessment.Disposition == "hold" {
		return zero, stopped, ErrNotAdmitted
	}
	if assessment.EngineID == "" || assessment.EngineVersion == "" || assessment.Disposition != "abstain" {
		return zero, stopped, errors.New("unknown or authorizing decision assessment")
	}
	if len(result.Sources) != len(manifest.Sources) {
		return zero, stopped, errors.New("incomplete sanitized envelope")
	}
	envelope := Envelope{SnapshotHash: manifest.SnapshotHash, Sources: append([]safety.SanitizedSource(nil), result.Sources...), Context: contextManifest}
	data, err := runner.Run(ctx, envelope.clone())
	if err != nil {
		return zero, stopped, err
	}
	if err := ctx.Err(); err != nil {
		return zero, stopped, err
	}
	decision, err := contracts.Decode[contracts.ReviewDecision](data)
	if err != nil {
		return zero, stopped, err
	}
	if decision.SnapshotHash != manifest.SnapshotHash {
		return zero, stopped, errors.New("reviewed snapshot mismatch")
	}
	if err := contracts.ValidateReferences(manifest, result.Safety, &decision, nil); err != nil {
		return zero, stopped, err
	}
	return decision, result, nil
}

// NoFindingsJSON produces a fixed fixture response for an admitted snapshot.
func NoFindingsJSON(hash contracts.Hash) ([]byte, error) {
	return json.Marshal(contracts.ReviewDecision{SchemaVersion: 1, SnapshotHash: hash, Verdict: "no_findings", Findings: []contracts.Finding{}})
}
