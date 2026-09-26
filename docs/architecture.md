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
- **Review runner:** produces structured evidence and maintainer-facing prose
  from read-only context.
- **Decision engine:** an optional bounded classifier. It starts disabled or in
  shadow mode and can only make routing more restrictive.
- **Record store:** persists canonical review records before publication.
- **Policy and publication gate:** rechecks freshness and permissions, then
  creates or edits exactly one marked comment.
- **Private notification adapter:** routes quarantined items without falling
  back to public disclosure.
- **Operator surface:** reports reviews, quarantines, stale records, provider
  failures, costs, and overrides without mutating product state.

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
