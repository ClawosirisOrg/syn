# Operations and pilots

## ADDED Requirements

### Requirement: Expose independent operator controls

Syn SHALL provide a global intake/review kill switch, an independent publisher kill
switch, and per-organization and per-repository enable flags. Safe defaults SHALL be
disabled intake for unlisted targets and disabled publication.

#### Scenario: Emergency publication stop

- **GIVEN** workers are processing accepted reviews
- **WHEN** an operator disables the publisher
- **THEN** no subsequent GitHub write occurs while review records may still reach a non-published terminal state

### Requirement: Report safe health and readiness

Health output SHALL distinguish HTTP availability, webhook acceptance, review worker
readiness, and publisher enablement and SHALL expose queue depth and dead-letter count
without payload content, comment bodies, or credentials.

#### Scenario: Queue dependency unavailable

- **GIVEN** the HTTP process is running but durable queue state is unavailable
- **WHEN** readiness is queried
- **THEN** Syn reports HTTP health separately from inability to durably accept work

### Requirement: Emit redacted structured telemetry

Syn SHALL log delivery ID, run ID, repository/item identity, snapshot hash,
policy/profile/gate/schema versions, stage, outcome, attempt, latency, and record path
where available. It SHALL NOT log raw tokens, provider keys, sensitive findings,
quarantined inputs, raw private payloads, or comment bodies.

#### Scenario: Safety quarantine

- **GIVEN** a source is quarantined for a credential-like finding
- **WHEN** Syn emits logs and metrics
- **THEN** operators can identify the run, stage, and finding class without seeing the detected value

### Requirement: Support cleanup and auditable recovery

Syn SHALL provide a documented or CLI-driven cleanup procedure for proof-of-concept
state and a recovery procedure for receipts, queued work, dead letters, records, and
uncertain publications. Cleanup SHALL not silently delete evidence needed by an
active or unresolved run.

#### Scenario: Operator cleans expired records

- **GIVEN** configured retention has expired and no run or publication remains unresolved
- **WHEN** cleanup executes
- **THEN** Syn removes eligible state deterministically and reports what was removed

### Requirement: Verify both pilot profiles through one core

The fixture suite SHALL include sanitized VIA-style and simple-alert-proxy profiles.
VIA-style fixtures SHALL preserve authority, evidence, applicability, status, and
publication invariants. Simple-alert-proxy fixtures SHALL preserve alert state,
delivery state, routing, authentication, redaction, and template-safety boundaries.

#### Scenario: Pilot fixture conformance

- **GIVEN** both profile suites and their approved fixture data
- **WHEN** CI runs end-to-end review tests
- **THEN** both pass through the same binary, policy interfaces, safety gate, record schema, and renderer

### Requirement: Gate broader onboarding on measured evaluation

Before broader onboarding, maintainers SHALL evaluate 3-5 approved items for each
pilot profile and record usefulness, incorrectness, unsafe behavior, insufficient
evidence, false positives, refusals, latency, and cost, followed by a written go/no-go
decision.

#### Scenario: Safety invariant fails during pilot

- **GIVEN** quarantined content reaches a runner, a forbidden write occurs, a secret leaks, or duplicate/foreign comments are modified
- **WHEN** the failure is observed
- **THEN** publication is disabled immediately and broader onboarding is blocked pending documented review
