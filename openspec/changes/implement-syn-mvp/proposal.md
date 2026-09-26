## Why

Repository maintainers need timely help reviewing issues and pull requests, but
the input being reviewed is attacker-controlled. A useful proof of concept must
therefore demonstrate automatic review and advisory feedback without giving a
model ambient credentials or allowing model output to mutate repository state.

GitHub issue [#3](https://github.com/ClawOsirisOrg/syn/issues/3) is the product
contract for that proof of concept. This change turns it into an implementation-
ready OpenSpec definition with explicit behavior, trust boundaries, architecture,
delivery phases, and verification gates.

## What Changes

- Add an authenticated webhook intake path for allowlisted new issues, pull
  requests, comments, submitted reviews, and review comments.
- Add durable delivery deduplication, bounded queueing, per-item ordering,
  retries, dead-letter state, and operator replay.
- Add immutable snapshots with provenance, deterministic safety preflight, an
  isolated review-runner interface, and a disabled decision-engine default.
- Add atomic, versioned canonical review records before any public projection.
- Add a separately credentialed deterministic publisher that creates or edits
  one Syn-owned marker-backed advisory conversation comment per item.
- Add hierarchical configuration, publication kill switches, health state,
  structured redacted telemetry, two pilot profiles, and an adversarial corpus.
- Preserve a hard service ceiling: no labels, state changes, pushes, repairs,
  approvals, merges, releases, workflow changes, or other GitHub writes.

## Capabilities

### New Capabilities

- `github-event-intake`: authenticate, allowlist, deduplicate, durably enqueue,
  serialize, replay, and refetch supported GitHub events.
- `configuration-and-policy`: validate layered policy and compute an effective
  action ceiling that lower layers cannot expand.
- `safety-and-review`: build bounded provenance-labelled snapshots, fail closed
  through deterministic preflight, and invoke a capability-limited runner.
- `canonical-review-records`: store versioned decisions atomically before any
  rendering or publication.
- `advisory-comment-publication`: render and safely create or update exactly one
  Syn-owned advisory conversation comment through an isolated publisher.
- `operations-and-pilots`: expose safe controls and telemetry and prove the same
  core against VIA-style and simple-alert-proxy fixtures.

### Modified Capabilities

None. This is the initial MVP capability definition.

## Impact

- Introduces the planned `internal/` service boundaries, configuration schemas,
  persistent state layout, CLI commands, fixtures, and operator documentation.
- Requires GitHub App webhook, read, and comment-publication credentials to be
  held in distinct components and environments.
- Requires a policy-approved real review backend before live publication; the
  deterministic fake remains limited to tests and approved synthetic repos.
- Makes issue #3 the implementation epic; this change specifies the work but
  does not mark the implementation complete or close the issue.
