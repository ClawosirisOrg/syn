# Canonical review records

## ADDED Requirements

### Requirement: Store a versioned canonical record

Syn SHALL store a schema-versioned record containing target and trigger identity,
policy/profile/gate/schema versions, immutable snapshot and manifest references,
resolved ownership, safety outcome, optional decision assessment, validated review
decision, runner metadata, publication intent, runtime outcome, and record identity.

#### Scenario: Safe completed review

- **GIVEN** a runner returns a schema-valid decision for a safe snapshot
- **WHEN** review execution completes
- **THEN** Syn creates an inspectable JSON record containing every required version and identity

#### Scenario: Review stops before runner invocation

- **GIVEN** preflight refuses or quarantines a snapshot
- **WHEN** the run terminates
- **THEN** Syn writes a minimal canonical safety record without fabricated review output

### Requirement: Persist records atomically before projection

Syn SHALL atomically and durably write the canonical review record to a deterministic
filesystem path before rendering a comment or invoking the publisher.

#### Scenario: Record write succeeds

- **GIVEN** a validated decision ready for storage
- **WHEN** Syn writes and durably commits its canonical record
- **THEN** rendering and publication MAY proceed using that stored record

#### Scenario: Record write fails

- **GIVEN** a validated decision whose record cannot be committed atomically
- **WHEN** storage fails
- **THEN** Syn returns a record failure and does not render or publish a comment

### Requirement: Minimize sensitive retained data

Canonical records SHALL NOT contain raw secrets, quarantined payloads, provider
credentials, private receiver URLs, or full sensitive findings. They SHALL use
bounded hashes, stable locators, classifications, and redaction references.

#### Scenario: Quarantined secret finding

- **GIVEN** preflight detects a token-like value
- **WHEN** the safety record and logs are stored
- **THEN** they identify the source and finding class without reproducing the token

### Requirement: Preserve immutable decisions and linked publication receipts

Publication attempts SHALL NOT rewrite the canonical review decision. Syn SHALL
append or link a durable receipt containing operation, idempotency key, snapshot
hash, attempt, GitHub comment ID and URL when known, response class, and outcome.

#### Scenario: Comment update succeeds

- **GIVEN** a stored record and successful update of the verified Syn comment
- **WHEN** the GitHub response is processed
- **THEN** Syn durably links a success receipt to the record and reviewed snapshot

#### Scenario: Publication outcome is uncertain

- **GIVEN** GitHub may have accepted a write but the response was lost
- **WHEN** Syn records the attempt
- **THEN** the receipt remains uncertain until marker reconciliation determines the terminal outcome
