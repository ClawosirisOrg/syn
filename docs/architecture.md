# Initial architecture

Syn separates review, records, policy, and publication so that no model output
directly causes a GitHub mutation.

```text
GitHub event or manual request
  -> organization allowlist and immutable snapshot
  -> mandatory input safety gate
       normalize and bound input
       partition trusted policy from untrusted content
       scan for secrets, prompt injection, unsafe content, and security shape
       pass sanitized envelope | quarantine | refuse
  -> optional bounded decision engine
  -> bounded project context bundle
  -> source-aware review runner
  -> schema validation and durable record
  -> deterministic freshness and publication gate
  -> one marker-backed advisory comment
```

## Trust hierarchy

Policy is resolved from most authoritative to least authoritative:

```text
service hard limits
  -> organization policy
    -> repository profile
      -> immutable item snapshot
```

A lower layer may be stricter, but it cannot grant a capability forbidden by a
higher layer.

## Planned components

- **Credential broker:** a narrowly scoped GitHub App or equivalent. The
  reviewer never receives its write token.
- **Event intake:** validates the repository and event allowlists and captures
  an immutable snapshot.
- **Safety preflight:** normalizes, bounds, partitions, scans, and classifies
  all admitted content before it can reach a model or agent.
- **Context builder:** combines trusted versioned policy and repository
  guidance with bounded, data-only projections of prior canonical records. It
  records source identities, versions, hashes, trust classes, and truncation.
- **Review runner:** one project-aware semantic reviewer produces structured
  evidence and maintainer-facing prose from read-only context in a fresh,
  disposable attempt.
- **Decision engine:** an optional bounded classifier. It starts disabled or in
  shadow mode and can only make routing more restrictive.
- **Record store:** persists canonical review records before publication.
- **Policy and publication gate:** rechecks freshness and permissions, then
  creates or edits exactly one marked comment.
- **Private notification adapter:** routes quarantined items without falling
  back to public disclosure.
- **Operator surface:** reports reviews, quarantines, stale records, provider
  failures, costs, and overrides without mutating product state.

## Reviewer and retained-context boundary

Syn does not run a generic model review and then decide whether a second
project reviewer may inspect the item. Deterministic admission, safety, schema,
and freshness checks gate one configured `ReviewRunner`; that runner owns the
product, architecture, functional, security, and proof judgment for the
admitted snapshot.

An adapter may use a project-specialist coding agent as that reviewer, but only
in a fresh read-only review mode. It receives the bounded context bundle, not
the authoring transcript, private agent memory, a branch-write credential, or
the publisher credential. Implementing an accepted finding is a separate
maintainer-authorized workflow outside the MVP.

Syn retains records, not a hidden reviewer mind:

- versioned policy, profiles, pinned guidance, and approved architecture
  decisions are authoritative context;
- prior findings, dispositions, reviewed hashes, and proof state are bounded
  item history linked to canonical records;
- curated repository knowledge requires a maintainer-owned source, version,
  content hash, and revalidation rule;
- runtime prompts, scratch files, tool state, and model/agent sessions are
  ephemeral and are destroyed after every terminal outcome. Policy-approved
  bounded prompt/output audit artifacts, if retained, are explicit records with
  their own retention class and are never resumable session memory.

Earlier model output is evidence, never policy or future instruction. A future
semantic index may locate candidate context, but deterministic admission must
re-establish repository scope, provenance, trust class, freshness, and size
limits before any result reaches the reviewer.

## Safety gate outcomes

The gate produces exactly one of:

- `pass`
- `pass_with_redactions`
- `quarantine`
- `refuse`

Scanner error, timeout, ambiguous decoding, stale state, or unsupported content
fails closed. A URL is data, not permission to fetch it. Validation commands
come only from a pinned repository profile and run without write credentials,
ambient secrets, or network access by default.

## MVP permission ceiling

The MVP may read repository contents and issue/PR context and may write a
single advisory conversation comment when policy permits. It has no contents
write, branch, label, close, approval, merge, release, workflow, or
administration capability.
