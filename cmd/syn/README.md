# Phase 1 local CLI

Only local operations are available. No command reads GitHub credentials, calls a provider, fetches a URL, or publishes a comment. Publication is disabled regardless of policy flags. An offline fixture preview is not authority to post it.

Commands:

- syn version (and legacy syn --version): print build version.
- syn validate-config --service SERVICE.yaml --organization ORG.yaml --profile PROFILE.yaml --repository owner/repo --event issues/opened [--approved-data-class public]: strict service/org/profile parsing (each regular file at most 1 MiB), cross-reference and effective fixture-policy evaluation. JSON output reports repository, event, fixture_review, live_intake=false, live_publication=false. If the data class is omitted fixture_review is false. A false eligibility result is a valid policy evaluation, not an error.
- syn review-fixture --service SERVICE.yaml --organization ORG.yaml --profile PROFILE.yaml --spec SPEC.json --record-root /absolute/private/records --approved-data-class public [--timeout 5s]: operator supplies an existing, private, operator-owned record root; never created by this command. Timeout must be positive and <=30s. Source selection and acquisition claims are local synthetic inputs, not authenticated. The CLI derives a deterministic no-findings fake response from the verified local snapshot and passes it through safety/review/recordstore/render. No custom runner or detector can be selected. On reviewed records output JSON contains record_id, record_path, outcome, dry_run.operation=CREATE and dry_run.body equal to the local render.CreatePreview body. A safety stop emits record_id, record_path and outcome only; no dry_run/body.
- syn serve, syn review-github, syn replay-delivery: explicitly unavailable; any arguments still fail closed. There is no publish flag or fallback to a live client.

Fixture spec is one JSON object (max 256 KiB) with exact case-sensitive keys and no duplicates, nulls, extra documents or unknown fields. Example:

    {"target":{"repository":"example-org/example-repo","kind":"issue","number":17},
     "trigger":{"delivery_id":"synthetic-17","event":"issues","action":"opened","installation_id":1,"actor_id":2},
     "sources":[{"id":"issue:17","type":"issue","body":"Small synthetic change.","acquired_at":"2026-10-16T00:00:00Z"}]}

Accepted source IDs are canonical item-bound locators, e.g. issue:17 or pull:17, validated by source.Build. All sources are untrusted conversation data; no default-branch guidance, path reads, trust flags, arbitrary fake responses, or network fetches. At most 16 sources, 32 KiB each and 128 KiB total body bytes; all input is preflight-scanned and never reflected into the public body. This CLI marks explicitly supplied local text as complete/stable for synthetic testing only. It cannot prove GitHub freshness or completeness.

Exit codes: 0 valid evaluation/reviewed preview; 2 malformed, denied policy or invalid input; 3 persisted safety refusal/quarantine with no preview; 4 unavailable live command; 5 local operational/output error; 124 fixture deadline/cancellation (record may already have been persisted; no preview emitted). For code 3, structured JSON on stdout identifies the stored record. Other failure codes emit no JSON body. Never treat a fixture record or preview as publishable.

The review-fixture deadline starts after argument validation, before policy/spec file reads and parsing or source snapshot construction. It is checked between bounded preprocessing stages and before runner, store, and output work; expiry returns 124 without a public JSON body. Context cancellation is cooperative: blocking filesystem I/O and custom detectors (if integrated in another entry point) require an outer killable process boundary for strict wall-clock enforcement. This local CLI does not expose custom detectors.
