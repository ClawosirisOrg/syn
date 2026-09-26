# Configuration and policy

## ADDED Requirements

### Requirement: Compute a non-expanding effective policy

Syn SHALL compute effective behavior as the intersection of immutable service hard
limits, versioned organization policy, repository profile, actual credential
permissions, and rollout phase. A lower layer SHALL be able to restrict but never
expand a higher-layer capability.

#### Scenario: Repository requests a forbidden mutation

- **GIVEN** a repository profile requests labels, state changes, pushes, approvals, merges, or another forbidden mutation
- **WHEN** Syn validates configuration
- **THEN** configuration fails because the request exceeds the immutable service ceiling

#### Scenario: Repository is stricter than organization

- **GIVEN** organization policy permits issue comments and a repository profile disables them
- **WHEN** effective policy is resolved
- **THEN** issue-comment publication is disabled for that repository

### Requirement: Reject ambiguous configuration

Versioned service policy/configuration, organization policy, and repository profiles
SHALL reject unknown fields, missing explicit repository and event allowlists,
unsupported schema versions, and ambiguous ownership or policy references.
They SHALL load from YAML or JSON with equivalent validation semantics.

#### Scenario: Installed but not allowlisted

- **GIVEN** the GitHub App can access a repository that is absent from the explicit repository allowlist
- **WHEN** an event arrives for that repository
- **THEN** installation access does not opt it in and Syn records a no-op

#### Scenario: Unknown field

- **GIVEN** a profile contains an unrecognized property
- **WHEN** configuration is loaded
- **THEN** Syn rejects the profile instead of silently ignoring the property

#### Scenario: Equivalent YAML and JSON policies

- **GIVEN** YAML and JSON documents representing the same supported policy values
- **WHEN** Syn validates and resolves each document
- **THEN** they produce the same effective policy and validation result

### Requirement: Require layered publication approval

Issue and pull-request conversation-comment publication SHALL be separate switches
that default to false. A live write SHALL additionally require an explicit runtime
enablement, approval at every policy layer, an approved real runner for the data
class, and a healthy publisher.

#### Scenario: One layer disables publication

- **GIVEN** a safe validated record but any required switch or approval is absent
- **WHEN** Syn computes publication intent
- **THEN** it records a dry-run or disabled outcome and makes no GitHub write

#### Scenario: Fake runner targets a live repository

- **GIVEN** a record produced by the deterministic fake runner for a non-synthetic repository
- **WHEN** publication is evaluated
- **THEN** Syn refuses publication regardless of other switches

### Requirement: Exclude forbidden mutation capabilities

The MVP SHALL expose no implementation path for labels, issue or pull-request state
changes, branch or contents writes, repair pull requests, approvals, merges, releases,
workflow changes, or administration. Its only permitted GitHub write SHALL be create
or update of Syn's top-level advisory conversation comment.

#### Scenario: Credential has excess permission

- **GIVEN** a mistakenly overprivileged installation credential
- **WHEN** Syn constructs its GitHub clients and effective policy
- **THEN** the software action surface remains limited to approved comment create/update operations
- **AND** the permission mismatch is operator-visible

### Requirement: Resolve target differences through profiles

Target-specific evidence, ownership, applicability, status, routing, authentication,
redaction, and template rules SHALL be expressed through validated profiles rather
than organization or repository branches in core packages.

#### Scenario: Two pilot repositories

- **GIVEN** VIA-style and simple-alert-proxy fixtures with different profiles
- **WHEN** Syn reviews both
- **THEN** the same binary, interfaces, gate, record schema, and renderer process them
