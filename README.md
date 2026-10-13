# Syn

Syn is a conservative, auditable GitHub review service inspired by
[ClawSweeper](https://github.com/openclaw/clawsweeper). Its name comes from
Sýn—usually anglicized as Syn—the Norse goddess associated with defensive
refusal and guarding the door.

Syn's job is to review selected issues and pull requests while keeping models
away from write credentials and treating repository content as untrusted input.
The model proposes; deterministic policy decides whether anything may be
stored or published.

## Namesake

The project's namesake—and patron in spirit—is
[Sýn](https://en.wikipedia.org/wiki/Syn_(goddess)), whose name means “denial”
or “refusal.” In chapter 35 of the *Prose Edda*, she is both gatekeeper and
defender:

> “The eleventh is Syn: she keeps the door in the hall, and locks it before
> those who should not go in; she is also set at trials as a defence against
> such suits as she wishes to refute: thence is the expression, that *syn* is
> set forward, when a man denies.”
>
> — Snorri Sturluson, *Gylfaginning* 35,
> [translated by Arthur Gilchrist Brodeur (1916)](https://en.wikisource.org/wiki/The_Prose_Edda_(1916_translation_by_Arthur_Gilchrist_Brodeur)/Gylfaginning#pageindex_78)

That is Syn's job in software form: guard the trust boundary, refuse what has
not earned admission, and make every denial explainable.

> [!IMPORTANT]
> Syn is in its initial design and scaffolding phase. It is not ready to
> install on a production repository.

## MVP boundaries

The first release is advisory-only. It may:

- read allowlisted issue, pull-request, and repository context;
- run a mandatory safety gate before any model or agent invocation;
- invoke one project-aware semantic reviewer in a fresh read-only attempt;
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
7. One `ReviewRunner` owns semantic review for an attempt; a generic model
   verdict never gates access to a second project reviewer.
8. Reviewer continuity comes from bounded, provenance-linked context and
   canonical records, not persistent agent sessions or self-authored memory.
9. Review and coding are separate capabilities even when the same underlying
   agent implementation can perform both roles.

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
