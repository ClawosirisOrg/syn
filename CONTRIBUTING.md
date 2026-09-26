# Contributing to Syn

Syn is security-sensitive infrastructure. Small, reviewable changes with clear
tests are preferred.

## Before opening a pull request

1. Open or reference an issue for behavior changes.
2. Keep the MVP permission ceiling and trust boundaries intact.
3. Add focused tests for changed behavior.
4. Run:

   ```bash
   gofmt -w .
   go vet ./...
   go test ./...
   ```

5. Document user-visible or policy-visible changes.

Pull requests require review from a code owner and must pass required checks.
Do not include credentials, real private issue content, vulnerability details,
or other sensitive fixtures.

## Design expectations

- Treat issue text, comments, diffs, filenames, branch content, and linked
  artifacts as untrusted data.
- Keep GitHub write credentials outside model and review-worker processes.
- Prefer deterministic, testable policy over prompt-only controls.
- Preserve fail-closed behavior.
- Do not add mutation capabilities to the MVP under feature flags or as unused
  code.

Use GitHub's private vulnerability reporting rather than a public issue for
security findings.
