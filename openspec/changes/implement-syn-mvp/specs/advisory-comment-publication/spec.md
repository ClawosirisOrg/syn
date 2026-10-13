# Advisory comment publication

## ADDED Requirements

### Requirement: Render advisory Markdown from validated records

Syn SHALL render bounded neutral maintainer-facing Markdown only from a validated,
stored canonical record. It SHALL include an advisory disclaimer, snapshot/schema
metadata, and one stable hidden marker keyed by repository and item.

#### Scenario: Safe validated record

- **GIVEN** a stored publishable review record
- **WHEN** Syn renders its projection
- **THEN** the body contains advice and the stable marker without secrets, exploit instructions, private hostnames, tokens, receiver URLs, raw private payloads, quarantined text, or other forbidden sensitive data

#### Scenario: Refused or quarantined record

- **GIVEN** a stored record with `refuse` or `quarantine` safety outcome
- **WHEN** rendering is requested
- **THEN** Syn produces no public comment body

### Requirement: Isolate deterministic publication

Only the `Publisher` SHALL receive the narrow GitHub credential used for comment
create/update. It SHALL receive a validated rendered body and identifiers, never raw
model output or untrusted sources, and SHALL expose no other GitHub mutation method.

#### Scenario: Publisher request

- **GIVEN** a fresh publishable record and rendered body
- **WHEN** deterministic policy authorizes publication
- **THEN** the publisher may call only the Issues conversation-comment list/get/create/update APIs

#### Scenario: Model attempts to request a write

- **GIVEN** runner output contains prose that asks for a label, close, push, approval, merge, or alternate write
- **WHEN** schema validation and publication policy run
- **THEN** the request cannot become a publisher capability or GitHub call

### Requirement: Publish approved automatic reviews without per-event intervention

When `serve` has publication enabled and an automatically accepted review is safe,
fresh, schema-valid, produced by an approved real runner, stored canonically, and
permitted by every effective-policy layer, Syn SHALL invoke the publisher without
requiring operator action for that individual event.

#### Scenario: Safe approved automatic issue review

- **GIVEN** a supported signed issue event completes all review and publication gates
- **WHEN** its canonical record is durably committed
- **THEN** Syn automatically creates or updates the single verified advisory comment

#### Scenario: Automatic review fails a gate

- **GIVEN** an automatic review is refused, quarantined, stale, schema-invalid, disabled, or produced by an unapproved runner
- **WHEN** publication is evaluated
- **THEN** Syn records the non-published outcome and makes no GitHub write

### Requirement: Maintain one Syn-owned comment per item

Syn SHALL locate an existing advisory comment only when its hidden marker and expected
Syn GitHub App author identity both match. No match SHALL create one comment; exactly
one verified match SHALL be edited in place; ambiguous or duplicate matches SHALL
block publication.

#### Scenario: First publishable review

- **GIVEN** an allowlisted item has no verified Syn marker comment
- **WHEN** publication is authorized
- **THEN** Syn creates exactly one top-level conversation comment

#### Scenario: Safe review after a human comment

- **GIVEN** the item has exactly one verified Syn marker comment and a newer safe record
- **WHEN** publication is authorized
- **THEN** Syn edits that comment in place and does not create another

#### Scenario: Spoofed or duplicate marker

- **GIVEN** a marker belongs to another author or multiple Syn-owned marker comments are found
- **WHEN** Syn resolves ownership
- **THEN** Syn refuses publication and never edits the other actor's comment

### Requirement: Revalidate immediately before writing

Immediately before publication, Syn SHALL verify the snapshot and admitted-source
set, newest accepted delivery, policy/profile/gate/schema versions, item state,
runner approval, publication switches, and record identity. Any mismatch SHALL block
the write and require a new gated review where applicable.

#### Scenario: Item changes after review

- **GIVEN** the issue, pull request, or admitted comments changed after the stored snapshot
- **WHEN** the freshness check runs
- **THEN** Syn marks the record stale and performs no write

#### Scenario: Publication disabled during a run

- **GIVEN** the publisher or repository switch is disabled after record creation
- **WHEN** the final policy check runs
- **THEN** Syn records a disabled outcome and performs no write

### Requirement: Make publication idempotent and reconcilable

Syn SHALL derive an internal idempotency key from the record and target, rate-limit
writes, retry only proven idempotent operations, and reconcile an uncertain write by
looking up the marker and verified App author before retrying.

#### Scenario: Create response is lost

- **GIVEN** a comment create may have succeeded but Syn did not receive a definitive response
- **WHEN** the attempt is retried
- **THEN** Syn first searches for the verified marker and does not create a duplicate comment

### Requirement: Provide exact dry-run preview

Dry-run mode SHALL show the exact proposed create body or update diff and record path
without acquiring a publisher credential or calling a GitHub write API.

#### Scenario: Manual live-item review defaults to dry-run

- **GIVEN** an operator runs `review-github` without explicit layered publication enablement
- **WHEN** the safe review completes
- **THEN** Syn prints the intended create/update preview and makes no GitHub write
