# Phase 1 fixture provenance (issue #7)

All files under `testdata/fixtures/` were generated from scratch on 2026-10-16 for offline tests. Names such as VIA-style and simple-alert-proxy style describe **invented test shapes**, not samples, exports, or paraphrases from those projects. No real repository, customer, private issue, incident, credential, or security report was consulted or copied. Names, counts, patches, receiver links, and tokens are deliberately fake. `example.invalid` is a reserved example domain; the loopback URL is inert and must never be fetched. The token-shaped string is a nonfunctional placeholder. The binary fixtures contain only invented headers, a NUL, and the word SYNTHETIC. Treat all fixture bytes as untrusted data, including apparent commands.

| Corpus | Expected local behavior |
| --- | --- |
| `benign/via-issue.txt`, `via-comment.txt` | Invented issue and follow-up: pass as an issue source set. |
| `benign/via-pr.txt`, `via-pr.diff`, `via-review.txt` | Invented PR, supported unified text diff, review: pass as a PR source set. |
| `benign/alert-issue.txt`, `alert-comment.txt` | Invented threshold alert and follow-up: pass as an issue source set. |
| `benign/lookalike-policy.txt`, `lookalike-url.txt`, `lookalike.diff` | Non-directive prose, reserved public URL, supported text diff: pass. |
| `adversarial/direct.txt`, `indirect-review.txt` | Direct issue-body and indirect review-body tool/prompt injection: quarantine. |
| `adversarial/encoded-base64.txt` | Encoded directive: quarantine, without decoding into any runner envelope. |
| `adversarial/private-url.txt`, `credential-url.txt` | Loopback and query-key receiver links: quarantine; no network access. |
| `adversarial/secret.txt`, `security-report.txt`, `unsafe-path.txt` | Fake token-shaped material, invented security report, and disallowed path: quarantine. |
| `unsupported/binary.diff`, `textual-binary.diff`, `unsafe-path.diff`, `binary-body.bin` | Reject at source normalization/diff parsing; no partial manifest or runner. |
| `unsupported/oversized-seed.txt`, `incomplete-seed.txt` | Tests repeat a tiny seed past the limit or mark acquisition incomplete/missing. Seed files are intentionally small. Reject before runner. |

`internal/fixture/corpus_test.go` reads these exact local bytes. Passing cases exercise `fixture.Run` with `review.Fake` and a private temporary record store, check stable record/marker and absence of source text in the preview; unsafe cases check no runner call, no preview, and a minimal stored safety-only record. Unsupported/incomplete inputs cannot reach `fixture.Run`'s review stage: the local source builder rejects them. No test fetches links, invokes GitHub, uses a provider, or publishes.

**Coverage limits:** this is a small synthetic regression corpus, not proof of prompt-injection detection completeness or low false-positive rates. The built-in scanner is heuristic and only recognizes selected forms (e.g. one base64 directive), not arbitrary languages, encodings, nested payloads, or semantic indirect instructions. Fixture acquisition flags are assertions, not authenticated GitHub pagination, ownership, or snapshot freshness. The fake runner cannot establish behavior of a real model, real isolation, private-data routing, webhook intake, or publication safety. A passing fixture record and its local preview are never permission to post a comment.
