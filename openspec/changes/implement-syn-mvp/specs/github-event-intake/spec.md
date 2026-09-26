# GitHub event intake

## ADDED Requirements

### Requirement: Authenticate before interpretation

The service SHALL verify `X-Hub-Signature-256` over the exact bounded raw body
using the configured webhook secret and constant-time comparison before decoding
JSON, consulting repository policy, queueing work, or making an external call.

#### Scenario: Valid signed delivery

- **GIVEN** a body within the configured limit with valid signature, event, and delivery headers
- **WHEN** the webhook endpoint receives the request
- **THEN** Syn MAY parse and classify the verified payload
- **AND** it records no raw secret value

#### Scenario: Invalid or oversized delivery

- **GIVEN** a missing or invalid signature, malformed required header, or oversized body
- **WHEN** the webhook endpoint receives the request
- **THEN** Syn rejects it before JSON interpretation, GitHub access, queue insertion, or runner invocation

### Requirement: Admit only supported allowlisted events

The service SHALL accept work only for `issues/opened`, `pull_request/opened`,
`issue_comment/created`, `pull_request_review/submitted`, and
`pull_request_review_comment/created` when the installation, organization,
repository, event, and item state satisfy explicit policy allowlists.

#### Scenario: Allowed new human comment

- **GIVEN** a verified `issue_comment/created` delivery from a human on an allowlisted open item
- **WHEN** effective policy permits that event and repository
- **THEN** Syn accepts one review trigger bound to the delivery, actor, and comment identifier

#### Scenario: Unsupported or unallowlisted event

- **GIVEN** a verified delivery outside the event/action or repository allowlist
- **WHEN** Syn classifies it
- **THEN** Syn records an auditable no-op without GitHub fetch or runner invocation

### Requirement: Suppress publication feedback loops

The service SHALL treat a comment or review authored by the configured Syn GitHub
App as a no-op. A marker from any other actor SHALL remain untrusted content and
SHALL NOT prove ownership.

#### Scenario: Syn receives its own comment event

- **GIVEN** a verified allowed event whose author is the configured Syn App identity
- **WHEN** intake classifies the event
- **THEN** Syn records a self-event no-op and does not schedule a review

#### Scenario: Human spoofs the marker

- **GIVEN** a human-authored comment containing a valid-looking Syn marker
- **WHEN** intake classifies the event
- **THEN** Syn treats the marker as untrusted source text and schedules normal review if otherwise allowed

### Requirement: Durably accept and deduplicate deliveries

The service SHALL persist a minimal receipt and durable queue entry before
acknowledging an accepted delivery. It SHALL deduplicate by GitHub delivery ID and
normalized event identity across retries and process restarts.

#### Scenario: First accepted delivery

- **GIVEN** a valid allowed delivery not present in durable state
- **WHEN** acceptance succeeds
- **THEN** its receipt and work item are durable before Syn returns success

#### Scenario: Identical redelivery after restart

- **GIVEN** an already accepted delivery ID with the same normalized identity
- **WHEN** GitHub redelivers it after Syn restarts
- **THEN** Syn does not create a second review attempt or canonical event identity

#### Scenario: Conflicting reuse of delivery ID

- **GIVEN** an existing delivery ID associated with different normalized metadata
- **WHEN** another verified payload reuses that ID
- **THEN** Syn refuses the replay conflict and exposes an operator-visible security outcome

### Requirement: Bound queue execution and replay

The service SHALL enforce queue depth, per-repository concurrency, maximum attempts,
exponential backoff with jitter, and a terminal dead-letter state. Operators SHALL
be able to replay a sanitized durable receipt without supplying replacement payload
content.

#### Scenario: Retriable worker failure

- **GIVEN** an accepted work item whose infrastructure dependency fails transiently
- **WHEN** attempts remain
- **THEN** Syn reschedules it with bounded backoff and records the attempt

#### Scenario: Retry limit reached

- **GIVEN** a work item at its maximum attempt count
- **WHEN** processing fails again
- **THEN** Syn writes a dead-letter record and exposes a terminal state without an infinite retry loop

### Requirement: Refetch authoritative state and preserve ordering

The service SHALL refetch approved issue, pull-request, conversation, review, diff,
and default-branch guidance sources with read-only GitHub credentials. It SHALL
serialize or safely coalesce concurrent events for one item so the newest accepted
state is not dropped and older work cannot publish as current.

#### Scenario: New comment arrives during review

- **GIVEN** a review is in progress and a newer human comment delivery is durably accepted for the same item
- **WHEN** the older run reaches its freshness gate
- **THEN** Syn marks the older run stale and reviews the newest authoritative state

#### Scenario: Webhook payload omits current context

- **GIVEN** a valid webhook contains only partial item context
- **WHEN** Syn acquires the review snapshot
- **THEN** it uses the read-only GitHub API rather than treating the payload as the complete review source
