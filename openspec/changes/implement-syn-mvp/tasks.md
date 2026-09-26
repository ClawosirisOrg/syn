## 1. Threat boundary and schemas

- [ ] 1.1 Document the threat model, credential boundaries, immutable service
  action ceiling, stop conditions, and operator rollback procedure.
- [ ] 1.2 Define strict versioned schemas for service policy/config, organization policy,
  repository profile, source manifest, safety result, review decision, canonical
  record, delivery receipt, and publication receipt.
- [ ] 1.3 Implement unknown-field rejection and effective-policy intersection;
  test that lower layers and overprivileged credentials cannot expand the ceiling.
- [ ] 1.4 Add safe example configurations with intake and publication default-off
  and no representation for forbidden GitHub mutations.
- [ ] 1.5 Add `AGPL-3.0-or-later` SPDX identifiers to all new source files and
  verify that generated or bundled material has compatible licensing metadata.

## 2. Shared fixture pipeline

- [ ] 2.1 Implement `serve`, `review-fixture`, `review-github`, `replay-delivery`,
  `validate-config`, and `version` commands with cancellation, deadlines, dry-run
  defaults, and documented exit codes.
- [ ] 2.2 Implement source normalization, canonical ordering, provenance manifests,
  trust partitioning, deterministic hashes, incomplete-source refusal, and pinned
  default-branch `CODEOWNERS` resolution with explicit fallback behavior.
- [ ] 2.3 Implement deterministic safety orchestration, detector interfaces, all
  four outcomes, bounded redaction references, and fail-closed scanner behavior.
- [ ] 2.4 Implement `DecisionEngine` with the fully functional `disabled` default.
- [ ] 2.5 Implement `ReviewRunner`, strict output validation, and a deterministic
  fake that exposes invocation counts for negative safety tests.
- [ ] 2.6 Implement atomic filesystem review records and deterministic dry-run
  rendering from stored validated records only.
- [ ] 2.7 Add sanitized VIA-style, simple-alert-proxy, and adversarial fixtures;
  document fixture provenance and verify both pilots use the same core interfaces
  and schemas with no private-repository data unless synthetic or explicitly sanitized.
- [ ] 2.8 Cover the complete issue #3 adversarial matrix, including prompt and tool
  injection, Unicode/bidirectional and encoded instructions, nested markup,
  filenames/commits/code/docs/branch `AGENTS.md`, secrets/private URLs, security
  reports, oversized/binary/archive data, unsafe paths, incomplete sources, scanner
  failure, malformed runner output, webhook spoof/replay/order cases, marker/author
  ambiguity, uncertain writes, and benign lookalikes for detector classes.

## 3. Automatic GitHub intake

- [ ] 3.1 Implement bounded raw-body intake, SHA-256 webhook signature verification
  before parsing, required headers, and the exact event/action allowlist.
- [ ] 3.2 Add durable receipts and queue state, delivery/event deduplication, bounded
  depth, retries with jitter, dead letters, startup reconciliation, and replay.
- [ ] 3.3 Schedule reviews for issue/PR opens and new human comments/reviews; record
  unsupported, unallowlisted, and Syn-authored deliveries as no-ops.
- [ ] 3.4 Implement read-only authoritative GitHub fetching and explicit fallback
  behavior for maintainer and `CODEOWNERS` resolution without checking out PR code.
- [ ] 3.5 Serialize/coalesce per-item work without losing receipts, supersede stale
  runs, and bind trigger metadata to each immutable snapshot and record.
- [ ] 3.6 Add signed end-to-end and fuzz tests for every allowed event, invalid and
  oversized input, replay conflicts, concurrent comments, and restart recovery.
- [ ] 3.7 Prove by injected clients and sentinel credentials that intake, safety,
  review, and records cannot access the publisher credential.

## 4. Real reviewer integration

- [ ] 4.1 Implement one approved backend behind `ReviewRunner` with destination
  allowlisting, explicit provider/data-class policy, timeouts, and cancellation.
- [ ] 4.2 Strip ambient secrets and GitHub credentials, deny general-purpose tools,
  and validate all backend output against the strict decision schema.
- [ ] 4.3 Record provider/model/adapter identity, version, latency, token/cost fields,
  and terminal error class without leaking input or secrets.
- [ ] 4.4 Compare the backend with deterministic fixtures in dry-run mode and document
  privacy, cost, latency, and failure observations.
- [ ] 4.5 Block live publication for the fake runner, an unapproved provider/data
  class, missing version metadata, or unavailable policy.

## 5. Advisory publication

- [ ] 5.1 Implement deterministic Markdown rendering, stable hidden markers,
  advisory wording, size limits, and forbidden-data filtering.
- [ ] 5.2 Implement the separate `Publisher` and an Issues conversation-comment
  client whose API surface contains only list/get/create/update comment operations.
- [ ] 5.3 Implement marker plus App-author ownership checks, create-once/edit-in-place
  behavior, ambiguous/duplicate refusal, and self-event loop suppression.
- [ ] 5.4 Revalidate freshness, policy, item state, newest accepted delivery, gate,
  runner approval, and publication switches immediately before every write.
- [ ] 5.5 Persist publication intent and receipt, rate-limit writes, and reconcile
  uncertain outcomes by marker lookup before retry.
- [ ] 5.6 Implement exact dry-run create/update diffs, global/per-target kill switches,
  and default-off issue and pull-request publication controls.
- [ ] 5.7 Prove end to end that safe approved work creates then edits one comment and
  that refused, quarantined, stale, spoofed, ambiguous, closed, disabled, and fake-
  runner cases perform zero writes.
- [ ] 5.8 Prove no client or code path can label, close, push, repair, approve, merge,
  release, mutate workflows, or call any GitHub write outside comment create/update.

## 6. Operations and pilot evaluation

- [ ] 6.1 Add structured redacted logs and health/readiness output for intake,
  workers, publisher state, queue depth, and dead-letter count.
- [ ] 6.2 Document deployment, configuration, GitHub App permissions, credential
  ownership/rotation, replay, fixture provenance, retention, security assumptions,
  limitations, cleanup, stop conditions, and recovery.
- [ ] 6.3 Run formatting, unit, end-to-end, fuzz smoke, race, vet, and CodeQL checks;
  retain reviewed deterministic goldens with no secrets or private data.
- [ ] 6.4 Record service/App/publisher ownership, webhook endpoint and secret
  custody, delivery retention, and credential rotation before automatic intake;
  record provider, data-class, private-inference, full-retention, budget, escalation,
  and incident decisions before a real reviewer or private repository is enabled.
- [ ] 6.5 Run 3-5 approved items for each pilot profile with live marker-backed
  comments and classify feedback as useful, incorrect, unsafe, or insufficient.
- [ ] 6.6 Publish latency, cost, false-positive, quarantine, refusal, and safety
  observations plus a go/no-go recommendation for broader onboarding.
