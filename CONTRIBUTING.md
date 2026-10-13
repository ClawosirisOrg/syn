# Contributing to Syn

Syn is security-sensitive infrastructure. Small, reviewable changes with clear
tests are preferred.

## Developer Certificate of Origin

Syn uses the [Developer Certificate of Origin 1.1](DCO). By contributing, you
certify that you have the right to submit the work under the repository's
license and agree to the terms in that certificate.

Every human-authored commit in a pull request must include a `Signed-off-by`
trailer whose email address matches the commit author's email address. Git can
add the trailer for you:

```bash
git commit --signoff -m "Describe the change"
```

To sign off the most recent commit after creating it:

```bash
git commit --amend --signoff --no-edit
```

To add your sign-off while rebasing every commit on a branch, then safely
update the pull request:

```bash
git fetch origin
git rebase --signoff origin/main
git push --force-with-lease
```

Do not add another person's sign-off. The pull-request DCO check excludes
merge commits and recognized automation commits, and rejects missing,
malformed, or author-mismatched sign-offs.

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
