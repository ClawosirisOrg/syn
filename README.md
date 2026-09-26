# Syn

Syn is a conservative, auditable GitHub review service inspired by
[ClawSweeper](https://github.com/openclaw/clawsweeper). It is named for Syn,
the Norse goddess associated with refusal and guarding the door.

Syn's job is to review selected issues and pull requests while keeping models
away from write credentials and treating repository content as untrusted input.
The model proposes; deterministic policy decides whether anything may be
stored or published.

> [!IMPORTANT]
> Syn is in its initial design and scaffolding phase. It is not ready to
> install on a production repository.

## MVP boundaries

The first release is advisory-only. It may:

- read allowlisted issue, pull-request, and repository context;
- run a mandatory safety gate before any model or agent invocation;
- create a durable, schema-validated review record;
- publish one marker-backed advisory comment per reviewed item; and
- privately quarantine security-shaped or secret-bearing work.

It may not label, close, push, repair, approve, merge, release, or mutate
product state. No dormant mutation path belongs in the MVP.

## Core invariants

1. Every externally controlled input crosses a deterministic safety gate.
2. Models receive no GitHub write credential or unrelated secrets.
3. Durable records are canonical; comments are projections of those records.
4. Repository installation does not imply activation.
5. Snapshot drift, missing policy, malformed output, or scanner failure blocks
   publication.
6. Probabilistic stages may make a decision stricter, never less strict.

See [docs/architecture.md](docs/architecture.md) for the initial architecture
and trust boundaries.

## Development

Syn targets Go 1.27.

```bash
go test ./...
go vet ./...
go run ./cmd/syn --version
```

The initial CLI is intentionally minimal while the safety envelope, policy
schema, and durable record format are specified and tested.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes. Please report
security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Syn is licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE)
(`AGPL-3.0-or-later`).
