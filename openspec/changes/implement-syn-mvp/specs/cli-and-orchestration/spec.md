# CLI and orchestration

## ADDED Requirements

### Requirement: Expose the required command surface

Syn SHALL provide `serve`, `review-fixture`, `review-github`, `replay-delivery`,
`validate-config`, and `version` commands that use the same configuration, policy,
safety, review, record, and rendering interfaces where applicable.

#### Scenario: Validate configuration without processing content

- **GIVEN** service, organization, and repository configuration files
- **WHEN** an operator runs `validate-config`
- **THEN** Syn validates schemas, references, allowlists, and effective policy without accepting an event, invoking a runner, or acquiring a publisher credential

#### Scenario: Report build identity

- **GIVEN** an installed Syn binary
- **WHEN** an operator runs `version`
- **THEN** Syn reports a machine-readable build version without loading review or publication credentials

### Requirement: Review fixtures through the production pipeline

`review-fixture` SHALL validate configuration, create a normalized immutable snapshot,
run mandatory preflight, invoke the configured runner only when permitted, atomically
write a canonical record, and print the intended advisory body plus record path in
dry-run mode.

#### Scenario: Safe sanitized fixture

- **GIVEN** a supported sanitized fixture and valid policy/profile
- **WHEN** an operator runs `review-fixture`
- **THEN** Syn uses the shared pipeline, stores the canonical record, prints the exact dry-run projection, and performs no GitHub write

#### Scenario: Unsafe fixture

- **GIVEN** a fixture that preflight quarantines or refuses
- **WHEN** an operator runs `review-fixture`
- **THEN** Syn stores a minimal safety record, does not invoke the runner, emits no public comment body, and returns the documented policy-result code

### Requirement: Keep manual live-item review read-only

`review-github` SHALL use a read-only credential to fetch only allowlisted sources and
SHALL run the shared snapshot, preflight, review, record, and dry-run rendering stages.
It SHALL NOT acquire a publisher credential or invoke a GitHub write API.

#### Scenario: Review an allowlisted live item

- **GIVEN** an allowlisted live issue or pull request and valid read-only credentials
- **WHEN** an operator runs `review-github`
- **THEN** Syn writes a canonical local record and exact dry-run preview without modifying GitHub

### Requirement: Replay only durable accepted deliveries

`replay-delivery` SHALL select an existing sanitized durable receipt, preserve its
verified event identity, and requeue it through normal ordering, deduplication,
freshness, policy, and attempt controls. It SHALL NOT accept a replacement raw body.

#### Scenario: Replay a dead-lettered delivery

- **GIVEN** an operator selects an eligible dead-letter receipt
- **WHEN** replay is authorized
- **THEN** Syn records the replay relationship and requeues current authoritative state without changing the original event identity

### Requirement: Default to no publication

All command invocations SHALL default to dry-run or no-write behavior. Only `serve`
MAY publish, and only with an explicit runtime switch plus service, organization,
repository, comment-class, credential, rollout-phase, runner, and freshness approval.

#### Scenario: Runtime publication switch omitted

- **GIVEN** all policy files otherwise permit publication
- **WHEN** `serve` starts without the explicit publication switch
- **THEN** safe reviews stop after the stored record and dry-run intent with no GitHub write

### Requirement: Bound and classify command execution

Commands SHALL honor context cancellation and a hard per-run deadline and SHALL
return documented, stable codes for success, configuration error, safety refusal,
quarantine, stale state, runner failure, and record failure. Human-readable reasons
SHALL identify the stage and class without leaking sensitive content.

#### Scenario: Hard deadline expires

- **GIVEN** a review exceeds its configured hard deadline
- **WHEN** cancellation propagates
- **THEN** Syn stops downstream work, records a bounded timeout outcome, and returns the documented failure code

#### Scenario: Safety refusal exit

- **GIVEN** deterministic preflight refuses input
- **WHEN** the command terminates
- **THEN** it returns the documented refusal code and does not invoke the runner or publisher
