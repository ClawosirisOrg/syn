## Context

Syn receives untrusted GitHub content and may publish advisory output back to the
same issue or pull request. The dangerous shortcut is to let a model operate with
a GitHub token or to publish its prose directly. The MVP instead treats review as
a staged transaction: authenticate an event, freeze and classify its source set,
run deterministic safety checks, ask a constrained reviewer for structured output,
store the canonical decision, then independently decide whether a comment may be
created or updated.

The implementation must serve both automatic webhook processing and manual fixture
or live-item review without creating a second, less-protected pipeline. Filesystem
state is acceptable for the single-instance proof of concept, but receipt, queue,
record, and publication transitions must survive restart and remain inspectable.

## Goals

- Automatically reach a terminal state for each supported signed event.
- Fail closed before reviewer invocation and again before publication.
- Keep webhook, GitHub read, model-provider, and GitHub comment credentials in
  separate capability domains.
- Produce deterministic identities, immutable evidence, and an auditable record.
- Publish useful advice by creating or editing one stable Syn-owned comment.
- Demonstrate organization-neutral behavior with two profiles and one core.

## Non-goals

- Any GitHub mutation other than creating or editing the one advisory conversation
  comment owned by the Syn App.
- Running untrusted repository code, following arbitrary URLs, or fetching
  unapproved attachments.
- Hosted multi-tenancy, high availability, horizontal workers, or a dashboard.
- Autonomous repair, coding, approval, merge, release, or decision-model enforcement.

## Architecture

```text
GitHub webhook
  -> raw-body verifier and event allowlist
  -> durable delivery receipt and bounded work queue
  -> per-item coordinator
  -> read-only GitHub snapshot acquisition
  -> source normalizer, provenance manifest, and snapshot hash
  -> deterministic safety preflight
  -> optional DecisionEngine (disabled by default)
  -> ReviewRunner (no GitHub credential)
  -> strict output validation
  -> atomic canonical review record
  -> freshness and effective-policy revalidation
  -> deterministic renderer
  -> Publisher (comment credential only)
  -> durable publication receipt
```

Manual `review-fixture` and `review-github` commands enter at snapshot acquisition
and use the same policy, preflight, runner, record, freshness, and rendering code.
`review-github` defaults to dry-run. `replay-delivery` requeues an existing sanitized
receipt rather than accepting arbitrary replacement payload data.

## Component boundaries

### Intake and queue

The HTTP handler reads a bounded raw body, verifies `X-Hub-Signature-256` using
constant-time comparison, then parses JSON. It validates the delivery ID, event,
action, installation, repository, item, actor, and triggering comment/review ID.
Unsupported or unallowlisted deliveries become recorded no-ops.

An accepted receipt and work item are made durable before a success response. The
queue uses an explicit maximum depth, attempt count, exponential backoff with
jitter, and dead-letter transition. Delivery ID is the transport deduplication key;
a normalized event identity protects against conflicting replay. A receipt that
reuses a delivery ID with different verified identity is refused and alerted.

A coordinator serializes work by repository plus item kind plus item number. It may
coalesce queued events only if it retains every receipt and guarantees that the
newest item state is reviewed. Once a newer delivery is accepted, an older in-flight
run cannot publish.

### Snapshot acquisition

The webhook payload identifies work but is not the authoritative review source. A
read-only GitHub App installation token refetches the item, selected conversation
history, approved review data, pull-request metadata and diffs, and pinned guidance
from the default branch. Links remain text. Pull-request code is never checked out.

Each source entry has a stable locator, source type, trust class, byte count,
content hash, and acquisition timestamp. Ordering is canonical. The aggregate hash
covers the normalized manifest and content hashes, while runtime timestamps are
excluded from deterministic identity. The triggering receipt and actor remain bound
to the record even when multiple deliveries observe equivalent content.

### Safety and review

The preflight normalizes supported encodings, enforces source and aggregate limits,
partitions pinned policy from untrusted data, and runs independent detectors. Its
only outcomes are `pass`, `pass_with_redactions`, `quarantine`, and `refuse`.
Scanner failure, timeout, ambiguous Unicode, incomplete source data, or unsupported
content fails closed. Findings store locations, hashes, and redaction references,
not sensitive values.

Only `pass` or `pass_with_redactions` creates a bounded review envelope. Untrusted
text is represented as quoted, provenance-labelled data and never interpolated into
system, developer, tool, or policy instructions.

`ReviewRunner` accepts that envelope plus trusted profile instructions and returns a
strict `ReviewDecision`. The deterministic fake supports tests. Live publication
requires a configured backend approved for the repository data class, with provider,
model, and adapter versions recorded. The runner has no GitHub token, unrelated
secrets, shell, arbitrary tools, or unrestricted network path. The initial adapter
may use direct OpenAI-compatible HTTP through a destination allowlist.

`DecisionEngine` is a separate optional interface. The `disabled` implementation is
the normal MVP setting. Any future engine may only restrict routing and can never
clear a deterministic finding or authorize publication.

### Records and publication

The record identity is derived from repository/item identity, snapshot hash, policy
and profile versions, gate version, runner identity/version, schema version, and
normalized triggering event identity. Records are immutable JSON written with a
temporary file, fsync, atomic rename, and parent-directory sync. A canonical record
must exist before rendering or any GitHub write.

Publication status is an append-only or separately linked receipt so the review
decision does not change after storage. It records the intended operation, internal
idempotency key, comment ID and URL, snapshot hash, attempt, GitHub response class,
and terminal outcome.

The renderer accepts a validated stored record, never raw runner output. It emits
neutral Markdown, an advisory disclaimer, bounded findings and evidence, version
metadata, and a hidden marker such as:

```html
<!-- syn-review:v1 repo=owner/repository item=123 -->
```

The publisher receives only the rendered body, record identity, expected marker,
target identity, and publication policy. It locates an existing comment only when
the marker and configured Syn App author identity both match. No match creates one
comment; one verified match updates it; multiple matches or ambiguous ownership
refuse publication. Pull requests use the Issues conversation-comment API, never
inline review comments.

Before writing, Syn rechecks the item state, newest accepted delivery, snapshot,
admitted-source set, policy/profile/gate versions, runner approval, and publication
switches. Refused, quarantined, stale, fake-runner, disabled, closed, or ambiguous
work produces no write. An uncertain create/update result is reconciled by marker
lookup before retry. Syn-authored comment webhook events are retained as no-ops so
publication cannot trigger a review loop.

## Credential and trust boundaries

| Capability | Secret available | Explicitly absent |
| --- | --- | --- |
| Webhook verifier | Webhook signing secret | GitHub API and model credentials |
| Snapshot reader | Read-only GitHub installation token | Comment-write and model credentials |
| Safety/policy | None | All external credentials |
| Review runner | Approved provider credential only | GitHub, webhook, and unrelated provider credentials |
| Record store/renderer | None | All external credentials |
| Publisher | Narrow GitHub issue-comment credential | Provider and webhook credentials |

These are runtime boundaries, not naming conventions. Construction APIs accept only
the capability they use; tests inspect child environments and injected clients.
Where the initial binary cannot provide operating-system process isolation, secrets
are loaded just in time by distinct adapters, never placed in shared configuration
objects, and integration tests prove that forbidden components cannot observe them.

## Effective policy

Effective behavior is the intersection of immutable service limits, organization
policy, repository profile, actual credential permissions, and rollout phase. Lower
layers may remove capabilities but cannot add them. Unknown fields are errors.

Issue-comment publication and pull-request-comment publication are independent,
default-off switches. Live publication additionally requires a runtime flag, an
approved real runner, an allowlisted repository/event/data class, and a healthy
publisher. Installation access alone never opts a repository in.

## Persistent state

The PoC uses a configured state root with separate directories for receipts, queued
work, dead letters, snapshots, immutable review records, and publication receipts.
State filenames use hashes or validated identifiers rather than untrusted text.
All transitions use atomic replacement and startup reconciliation. File permissions
are restrictive, and raw webhook bodies are discarded after extracting the minimum
verified metadata needed for audit and replay.

The interfaces for delivery store, queue, record store, and publication receipt
store remain backend-neutral so a later transactional database can replace the
filesystem without changing product behavior.

## Failure handling and rollback

Every stage returns a typed outcome and terminal error class. Retriable infrastructure
failures are bounded; policy, safety, schema, and ambiguity failures are terminal.
Health distinguishes HTTP availability, intake enablement, worker readiness,
publisher state, queue depth, and dead-letter count without exposing payloads.

The publisher has an immediate kill switch independent of intake. If a trust-boundary
or publication invariant fails, operators disable publication first, then intake and
review if necessary, preserve sanitized evidence, rotate possibly exposed secrets,
and resume only in fixture/dry-run mode after review. Existing inaccurate comments
are corrected or removed under maintainer control rather than through a hidden Syn
mutation path.

## Verification strategy

- Unit tests cover config intersection, canonicalization/hashing, safety outcomes,
  schema validation, record atomicity, rendering, marker ownership, and freshness.
- Signed webhook tests cover every allowed event plus invalid signatures, spoofed
  headers, duplicates, unsupported actions, self-events, and ordering races.
- End-to-end tests prove one create followed by edits, no unsafe/stale writes, no
  writes outside the Issues comment client, and reconciliation after uncertain writes.
- Credential-boundary tests inject sentinel secrets and prove they are unavailable
  to forbidden components and subprocess environments.
- Golden fixture suites cover VIA-style and simple-alert-proxy behavior through
  profiles only; an adversarial corpus covers all issue #3 detector classes.
- Fuzz tests target verified webhook decoding, normalization, parsers, and marker
  handling. Race tests cover workers, queue state, and atomic record operations.

## Decisions and trade-offs

### Filesystem persistence for the PoC

A filesystem backend keeps deployment small and records inspectable with standard
tools. It does not provide multi-node transactions, so the MVP is explicitly single-
instance and serializes state transitions. Backend interfaces preserve a migration
path. A memory-only queue was rejected because accepted events would be lost on
restart and could be acknowledged before durable acceptance.

### One top-level conversation comment

Editing a single marker-backed comment avoids bot noise and makes ownership and
idempotency tractable across issues and pull requests. Inline review comments were
rejected because they expand permissions, APIs, anchoring behavior, and duplication
risk without being necessary to prove useful advisory review.

### Separate read and publish capabilities

A single installation token would be simpler, but an accidental token leak into the
runner would then cross the write boundary. Separate components and permissions make
the intended ceiling enforceable and testable.

### No public comment for quarantine or refusal

Even a generic public response can reveal that a security-shaped report or secret
was detected. The MVP records an operator-visible outcome but renders no public body.
A private notification adapter remains out of the public publication path and must
be separately designed before use.

## Decisions required before live pilots

The following may remain placeholders through fixture work but must be recorded
before enabling automatic live publication: service and GitHub App owner; webhook
endpoint and secret custody; credential rotation; provider and permitted data
classes; private-repository inference constraints; retention periods; budget and
latency ceilings; private security escalation route; and incident owner.
