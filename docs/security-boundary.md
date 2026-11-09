# MVP security boundary and recovery

This document defines the implementation boundary for [PRD #3](https://github.com/ClawOsirisOrg/syn/issues/3) and [Phase 0 #6](https://github.com/ClawOsirisOrg/syn/issues/6). It is a design contract, not evidence that later phases are implemented or a production deployment approval. The default operating mode is fixture-only, dry-run, with intake and publication off.

## Assets, adversaries, and trust

Protect webhook signing material, GitHub installation credentials, provider credentials, private item contents, quarantine findings, canonical records, and the integrity of a single Syn advisory comment. The adversary may control issue/PR text, comments, review text, branch names, commit messages, filenames, diffs, untrusted repository guidance, linked URLs, webhook payload fields before signature verification, and spoofed Syn markers. It may replay deliveries, race edits/new comments against review, induce API timeouts, and cause scanner/backend failures. Neither a valid GitHub signature nor an allowlisted repository makes its item contents trusted instructions.

Trust order is immutable service limits, organization policy, repository profile, immutable item snapshot. Each lower layer may only reduce capability. Provider output is a proposal, never a policy grant. A URL is data, not an authorization to fetch or exfiltrate. No PR code executes in the privileged service. Reviewer project context may contain only the admitted provenance-labelled review envelope, versioned policy/profile references, pinned approved guidance, maintainer-owned curated repository knowledge, and sanitized bounded projections of prior canonical records; raw private coding-agent memory, authoring transcripts, resumable reviewer sessions, and target-supplied second-reviewer requests are excluded. Each review attempt uses a fresh isolated reviewer context with a bounded completed-cycle history and explicit truncation markers.

## Capability domains

| Domain | May access | Must not access |
| --- | --- | --- |
| Webhook verifier | Webhook signing secret and bounded raw delivery | GitHub or provider credentials |
| Snapshot reader | Read-only GitHub installation credential and allowlisted item sources | Comment-write credential; provider credential |
| Policy, safety, records and renderer | Validated configuration, bounded sanitized metadata | All external credentials and raw quarantined content in durable output |
| Review runner | Approved provider credential for approved data class; provenance-labelled bounded envelope | GitHub credentials, general shell/tools, unrelated secrets or arbitrary network destinations |
| Publisher | Narrowly scoped conversation-comment credential and validated stored record projection | Provider and webhook credentials; raw model output or unsafe source text |

These are required runtime boundaries, not merely interface names. If a single process cannot prove separation, live publication stays disabled. Tests must inject sentinel credentials and count every client method call. Actual token permissions may be broader by accident; such a mismatch is operator-visible and **never** extends the software's action surface.

## Immutable service action ceiling

The sole permitted GitHub mutation in the MVP is create/update of one Syn-owned, marker-backed, **top-level Issues conversation comment** on an allowlisted issue or pull request. No labels, item-state changes, contents or branch writes, repair PRs, approvals, merges, releases, workflow changes, administration, or dormant API for those actions. Publishing requires all of: explicit runtime enablement; independent issue/PR publication switches in service/organization/repository policy; exact repository/event allowlists; healthy separate publisher; approved real runner and data class; stored validated record; fresh snapshot/item and newest accepted delivery; matching Syn App author and unique marker on update. Absence or ambiguity in any check means no write. Installation access alone never activates intake or publication.

## Required refusal and exposure limits

Verify HMAC-SHA256 over a bounded **raw** webhook body before JSON parsing or external calls. Preserve durable minimal delivery identity before acceptance; deduplicate retries and reject conflicts. Normalize and size-bound every admitted source before invoking a runner. Scanner error/timeout, ambiguous encoding, incomplete manifests, security-shaped or secret-bearing material, malformed output, policy absence, stale state and ambiguous marker ownership all fail closed. Quarantined payloads, tokens, receiver URLs, and raw findings never appear in records, logs, public comments or fixtures. The source acquirer must verify default-branch commit provenance before assigning pinned trust; a commit-shaped field is not proof. Before rendering, resolve every safety/review finding source ID against the admitted manifest and prove the manifest and context bundle hashes refer to the stored snapshot. Schema decoding alone cannot establish these cross-record facts. Records precede rendering; publication receipts link to immutable records. An uncertain GitHub write is reconciled by marker-and-author lookup before any retry. Rate limits and retry counts are bounded.

## Stop conditions and rollback

Immediately disable publication if any forbidden GitHub endpoint is called; a write credential reaches a runner/intake/safety process; unsafe or stale work publishes; a secret leaks into a record/log/comment; duplicate Syn comments appear; another actor's comment is edited; untrusted content changes tools/policy; the provider violates its approved data policy; or the receiver cannot authenticate/deduplicate. If the incident concerns intake or review integrity, activate the global intake/review kill switch as well. Preserve only sanitized receipts, records, publication outcomes, and failure metadata; do not retain unsafe payloads to diagnose the incident. Notify the designated operator privately; rotate webhook and App credentials if exposure is possible; have a maintainer correct inaccurate comments. Resume only fixture/dry-run processing after a documented root-cause review, fresh tests, and explicit operator approval. Never treat a restarted process or feature flag alone as remediation.

Before enabling automatic intake, record the service/App owner, webhook endpoint/secret custodian, credential rotation, delivery retention, and incident owner. Before enabling a real provider, private item, or live pilot, additionally decide provider/data-class routing and privacy constraints, private security-notification route, snapshot/prompt/output/audit retention, latency/cost budget, credential ownership, and recovery plan. Missing decisions keep the corresponding mode disabled.
