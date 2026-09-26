# Safety and review

## ADDED Requirements

### Requirement: Create a bounded immutable source manifest

Syn SHALL normalize every admitted source into a typed entry containing a stable
identifier, type, locator, trust class, byte length, content hash, and acquisition
time. It SHALL compute a deterministic aggregate snapshot hash over the canonical
ordered manifest and source hashes.

#### Scenario: Complete supported source set

- **GIVEN** all policy-selected sources are available and within limits
- **WHEN** snapshot acquisition completes
- **THEN** every admitted byte is represented by a provenance entry bound to one snapshot hash

#### Scenario: Incomplete or changed source set

- **GIVEN** a selected comment, diff, or other required source is missing, truncated, ambiguous, or unexpectedly changes during acquisition
- **WHEN** Syn attempts to finalize the snapshot
- **THEN** it refuses the snapshot before runner invocation

### Requirement: Resolve ownership from trusted sources

Syn SHALL resolve maintainers and `CODEOWNERS` only from approved repository metadata
and pinned default-branch guidance. A repository profile SHALL define explicit
fallback behavior for missing, malformed, ambiguous, or unmatched ownership.

#### Scenario: Pull request changes CODEOWNERS

- **GIVEN** an untrusted pull-request branch modifies `CODEOWNERS`
- **WHEN** Syn resolves ownership for that pull request
- **THEN** it ignores the branch copy and uses the pinned approved default-branch source

#### Scenario: No owner and no safe fallback

- **GIVEN** no trusted owner matches and the profile has no approved fallback
- **WHEN** ownership resolution completes
- **THEN** Syn refuses the run instead of inventing or inferring an owner

### Requirement: Preserve trust partitions

Syn SHALL distinguish immutable service instructions, versioned organization policy,
pinned default-branch guidance, and attacker-controlled issue, comment, pull-request,
filename, commit, attachment, and external-reference data. Passing safety checks
SHALL NOT promote untrusted data into instructions or policy.

#### Scenario: Instructions appear in repository content

- **GIVEN** an untrusted source contains text that claims to override policy or request tools
- **WHEN** Syn constructs the review envelope
- **THEN** the text remains quoted provenance-labelled data and cannot alter instructions, tools, permissions, network, or policy

### Requirement: Do not expand untrusted sources during acquisition

Syn SHALL treat URLs as data and SHALL NOT follow arbitrary links. It SHALL NOT check
out or execute pull-request code with a privileged credential. Unsupported attachments,
binaries, archives, and external pages SHALL be excluded or fail closed according to
explicit policy rather than being fetched or interpreted implicitly.

#### Scenario: Issue links to external instructions

- **GIVEN** issue or comment text contains a URL
- **WHEN** Syn builds the admitted source set
- **THEN** it records the URL as untrusted text without fetching its target

#### Scenario: Pull request contains executable code

- **GIVEN** a pull request is selected for review
- **WHEN** Syn acquires metadata and diffs
- **THEN** it does not check out or execute the branch with any privileged credential

### Requirement: Run deterministic safety preflight first

Before every model or agent invocation, Syn SHALL normalize supported encodings,
enforce per-source and aggregate limits, and evaluate detectors for secrets,
security-shaped reports, prompt or tool manipulation, exfiltration requests, unsafe
paths, encoded or hidden instructions, nested markup, and unsupported binary/archive
content.

#### Scenario: Safe bounded input

- **GIVEN** a complete bounded snapshot with no blocking finding
- **WHEN** preflight completes
- **THEN** it returns `pass` or `pass_with_redactions` and MAY construct a bounded review envelope

#### Scenario: Secret or security-shaped report

- **GIVEN** a source contains credential-like material or a private vulnerability report
- **WHEN** preflight evaluates it
- **THEN** it returns `quarantine` or `refuse`, does not invoke the runner, and preserves only non-sensitive finding provenance

#### Scenario: Scanner uncertainty

- **GIVEN** a detector errors, times out, cannot normalize input unambiguously, or encounters unsupported content
- **WHEN** preflight cannot prove a permitted outcome
- **THEN** it fails closed without runner invocation

### Requirement: Limit safety outcomes

Safety preflight SHALL return exactly one of `pass`, `pass_with_redactions`,
`quarantine`, or `refuse`. Quarantined or refused work SHALL have no public comment
body and SHALL NOT expose sensitive values in logs or records.

#### Scenario: Redaction permits review

- **GIVEN** a finding is covered by deterministic approved redaction policy
- **WHEN** preflight returns `pass_with_redactions`
- **THEN** the runner receives only the bounded redacted representation with provenance references

### Requirement: Isolate and validate review execution

Syn SHALL invoke review through a small `ReviewRunner` interface. The runner SHALL
receive no GitHub credential, webhook secret, unrelated provider secret, arbitrary
tool capability, or unrestricted network access, and its output SHALL pass a strict
schema that rejects unknown fields and capabilities.

#### Scenario: Runner environment inspection

- **GIVEN** sentinel GitHub and unrelated secrets exist in the service environment
- **WHEN** a runner adapter or subprocess starts
- **THEN** those secrets are absent from its inputs and environment

#### Scenario: Malformed runner output

- **GIVEN** a runner returns invalid, extra, or capability-bearing fields
- **WHEN** output validation runs
- **THEN** Syn records a runner/schema failure and does not render or publish it

### Requirement: Support deterministic and approved real runners

Syn SHALL provide a deterministic fake runner for fixtures and tests and at least one
policy-approved real backend before live publication. It SHALL record runner,
provider, model, adapter, and version identity plus available latency and token/cost
metadata.

#### Scenario: Deterministic fixture replay

- **GIVEN** identical fixture, policy, profile, gate, runner, and schema versions
- **WHEN** the fake runner processes the fixture repeatedly
- **THEN** snapshot hashes, record identities, markers, and deterministic fields match

#### Scenario: Remote provider is not approved for the data class

- **GIVEN** a safe envelope whose repository data class is not approved for the configured remote provider
- **WHEN** Syn evaluates runner policy
- **THEN** it refuses the remote invocation before sending any content

### Requirement: Keep decision assessment optional and restrictive

Syn SHALL define a separate `DecisionEngine` and SHALL support `disabled` as the
default complete MVP mode. Any future decision assessment SHALL only restrict
routing and SHALL NOT clear safety findings or authorize publication.

#### Scenario: Decision engine disabled

- **GIVEN** a valid configuration with `DecisionEngine=disabled`
- **WHEN** a safe review runs
- **THEN** the pipeline completes without calling a probabilistic decision model

### Requirement: Constrain optional validation execution

If profile-declared validation is implemented or invoked, commands SHALL come only
from pinned trusted profile data and SHALL execute in an ephemeral, read-only,
no-secret sandbox with network disabled by default. Untrusted sources SHALL NOT
supply or modify validation commands.

#### Scenario: Comment requests a validation command

- **GIVEN** an issue or comment instructs Syn to execute a command
- **WHEN** the review pipeline processes the text
- **THEN** Syn treats it as untrusted data and does not execute it

#### Scenario: Trusted profile validation runs

- **GIVEN** an approved pinned profile declares an optional validation command
- **WHEN** policy permits Syn to run it
- **THEN** the command runs without write access, secrets, or network access by default
