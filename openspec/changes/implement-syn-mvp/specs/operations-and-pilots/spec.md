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

### Requirement: Expose a terminal state for accepted deliveries

Every valid allowlisted accepted delivery SHALL reach an operator-visible
`published`, `refused`, `quarantined`, `superseded`, `failed`, or `dead-letter`
terminal state after bounded attempts. Terminal reasons SHALL be actionable without
revealing comment bodies, credentials, quarantined payloads, or secret findings.

#### Scenario: Publication exhausts bounded attempts

- **GIVEN** a safe publishable delivery repeatedly encounters a terminal or exhausted publication failure
- **WHEN** no attempts remain
- **THEN** Syn exposes `failed` or `dead-letter` with the stage and sanitized cause

### Requirement: Verify both pilot profiles through one core

The fixture suite SHALL include sanitized VIA-style and simple-alert-proxy profiles.
VIA-style fixtures SHALL preserve authority, evidence, applicability, status, and
publication invariants. Simple-alert-proxy fixtures SHALL preserve alert state,
delivery state, routing, authentication, redaction, and template-safety boundaries.

#### Scenario: Pilot fixture conformance

- **GIVEN** both profile suites and their approved fixture data
- **WHEN** CI runs end-to-end review tests
- **THEN** both pass through the same binary, policy interfaces, safety gate, record schema, and renderer

#### Scenario: Private repository fixture is added

- **GIVEN** fixture input was derived from a private repository
- **WHEN** it is admitted to the test corpus
- **THEN** its provenance records that it is synthetic or explicitly sanitized and contains no private raw payload

### Requirement: Gate broader onboarding on measured evaluation

Before broader onboarding, maintainers SHALL evaluate 3-5 approved items for each
pilot profile and record usefulness, incorrectness, unsafe behavior, insufficient
evidence, false positives, refusals, latency, and cost, followed by a written go/no-go
decision.

#### Scenario: Safety invariant fails during pilot

- **GIVEN** quarantined content reaches a runner, a forbidden write occurs, a secret leaks, or duplicate/foreign comments are modified
- **WHEN** the failure is observed
- **THEN** publication is disabled immediately and broader onboarding is blocked pending documented review

### Requirement: Enforce quantitative proof-of-concept gates

For the approved evaluation set, Syn SHALL block broader onboarding unless known
secret/security-shaped fixtures, stale/incomplete snapshots, invalid signatures, and
unallowlisted deliveries are stopped at their required boundaries; no forbidden
GitHub write, self-triggered review, duplicate Syn comment, raw secret, quarantined
payload, or core target-specific branch occurs; and at least 80 percent of approved
non-security pilot reviews are rated useful or useful-with-edits. Median fixture
latency and model cost SHALL be recorded.

#### Scenario: A required zero-tolerance measure is nonzero

- **GIVEN** evaluation observes a forbidden write, self-triggered review, duplicate comment, data leak, or target-specific core branch
- **WHEN** maintainers assess the pilot
- **THEN** the result is no-go regardless of usefulness ratings

#### Scenario: Evaluation meets the safety gates

- **GIVEN** all boundary measures pass and usefulness is at least 80 percent
- **WHEN** maintainers complete the pilot report
- **THEN** they record measured latency and cost and may issue a documented go recommendation

### Requirement: Fail closed on activation prerequisites

Syn SHALL require recorded service/App/publisher ownership, webhook endpoint and
secret custody, delivery retention, and rotation procedures before automatic intake.
It SHALL additionally require provider/data-class approval, private-inference rules,
full retention policy, budget/latency limits, a private security route, and incident
ownership before enabling a real reviewer or private repository.

#### Scenario: Webhook ownership is not recorded

- **GIVEN** otherwise valid automatic-intake configuration without endpoint or secret custody
- **WHEN** Syn evaluates activation
- **THEN** intake remains disabled

#### Scenario: Private security route is ambiguous

- **GIVEN** a real reviewer or private repository would process a data class without an approved private escalation route
- **WHEN** activation or routing is evaluated
- **THEN** Syn fails closed and does not send the content to the reviewer

### Requirement: Stop on trust-boundary violations

Syn SHALL disable publication and fall back to fixture/dry-run mode when a safety or
credential boundary is crossed, a forbidden or unsafe comment write occurs, sensitive
data leaks, stale advice renders as current, target behavior requires a core fork, a
provider violates data policy, or intake cannot authenticate and durably deduplicate.

#### Scenario: Publisher credential reaches the runner

- **GIVEN** monitoring or a test detects the publisher credential in a runner boundary
- **WHEN** Syn applies its stop policy
- **THEN** publication is disabled immediately, affected credentials are treated as exposed, and live operation cannot resume without documented review
