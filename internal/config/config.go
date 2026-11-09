// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config parses strict versioned policy and computes a conservative,
// credential-free effective policy for a single repository and event.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const Version = 1
const maxConfigBytes = 1 << 20

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var maintainerPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)

const maxApprovedMaintainers = 8

// Publication contains only advisory conversation-comment switches. There are
// deliberately no fields representing other GitHub mutations.
type Publication struct {
	IssueComments       bool `json:"issue_comments" yaml:"issue_comments"`
	PullRequestComments bool `json:"pull_request_comments" yaml:"pull_request_comments"`
}

// ServiceConfig is the operator-owned gate above organization and repository
// policy. All boolean capabilities are false unless explicitly enabled.
type ServiceConfig struct {
	Version             int         `json:"version" yaml:"version"`
	IntakeEnabled       bool        `json:"intake_enabled" yaml:"intake_enabled"`
	PublicationEnabled  bool        `json:"publication_enabled" yaml:"publication_enabled"`
	RepositoryAllowlist []string    `json:"repository_allowlist" yaml:"repository_allowlist"`
	EventAllowlist      []string    `json:"event_allowlist" yaml:"event_allowlist"`
	DataClasses         []string    `json:"data_classes" yaml:"data_classes"`
	Publication         Publication `json:"publication" yaml:"publication"`
}

type OrganizationPolicy struct {
	Version             int         `json:"version" yaml:"version"`
	Organization        string      `json:"organization" yaml:"organization"`
	RepositoryAllowlist []string    `json:"repository_allowlist" yaml:"repository_allowlist"`
	EventAllowlist      []string    `json:"event_allowlist" yaml:"event_allowlist"`
	DataClasses         []string    `json:"data_classes" yaml:"data_classes"`
	Publication         Publication `json:"publication" yaml:"publication"`
}

// OwnershipFallbackMode is deliberately limited to refusal or an explicitly
// listed trusted-profile maintainer set. It never grants GitHub permissions.
type OwnershipFallbackMode string

const (
	OwnershipRefuse              OwnershipFallbackMode = "refuse"
	OwnershipApprovedMaintainers OwnershipFallbackMode = "approved_maintainers"
)

// OwnershipGap distinguishes failures to identify an owner from pinned
// default-branch CODEOWNERS and approved repository metadata.
type OwnershipGap string

const (
	OwnershipMissing   OwnershipGap = "missing"
	OwnershipMalformed OwnershipGap = "malformed"
	OwnershipAmbiguous OwnershipGap = "ambiguous"
	OwnershipUnmatched OwnershipGap = "unmatched"
)

// OwnershipFallback specifies a bounded, case-specific fallback. An omitted
// mode means refuse. Listed users are candidate identities only: Phase 1 must
// verify them using approved metadata; this package never resolves an owner.
type OwnershipFallback struct {
	Missing             OwnershipFallbackMode `json:"missing" yaml:"missing"`
	Malformed           OwnershipFallbackMode `json:"malformed" yaml:"malformed"`
	Ambiguous           OwnershipFallbackMode `json:"ambiguous" yaml:"ambiguous"`
	Unmatched           OwnershipFallbackMode `json:"unmatched" yaml:"unmatched"`
	ApprovedMaintainers []string              `json:"approved_maintainers" yaml:"approved_maintainers"`
}

// ModeFor is a fail-closed policy lookup, not ownership resolution. Unknown
// reasons, including the zero value, always refuse.
func (f OwnershipFallback) ModeFor(gap OwnershipGap) OwnershipFallbackMode {
	if err := f.Validate(); err != nil {
		return OwnershipRefuse
	}
	var mode OwnershipFallbackMode
	switch gap {
	case OwnershipMissing:
		mode = f.Missing
	case OwnershipMalformed:
		mode = f.Malformed
	case OwnershipAmbiguous:
		mode = f.Ambiguous
	case OwnershipUnmatched:
		mode = f.Unmatched
	default:
		return OwnershipRefuse
	}
	if mode == OwnershipApprovedMaintainers && len(f.ApprovedMaintainers) > 0 {
		return mode
	}
	return OwnershipRefuse
}

// Validate rejects unknown modes and unbounded or unused identity allowlists.
// Phase 1 must still verify listed candidates against approved trusted metadata.
func (f OwnershipFallback) Validate() error {
	usesList := false
	for _, mode := range []OwnershipFallbackMode{f.Missing, f.Malformed, f.Ambiguous, f.Unmatched} {
		switch mode {
		case "", OwnershipRefuse:
		case OwnershipApprovedMaintainers:
			usesList = true
		default:
			return fmt.Errorf("invalid ownership fallback mode %q", mode)
		}
	}
	if usesList && len(f.ApprovedMaintainers) == 0 {
		return errors.New("approved_maintainers fallback requires explicit identities")
	}
	if !usesList && len(f.ApprovedMaintainers) > 0 {
		return errors.New("approved_maintainers are unused")
	}
	if len(f.ApprovedMaintainers) > maxApprovedMaintainers {
		return errors.New("too many approved maintainers")
	}
	seen := map[string]bool{}
	for _, login := range f.ApprovedMaintainers {
		key := identity(login)
		if len(login) > 39 || !maintainerPattern.MatchString(login) || strings.Contains(login, "--") || seen[key] {
			return fmt.Errorf("invalid or duplicate approved maintainer %q", login)
		}
		seen[key] = true
	}
	return nil
}

func (f *OwnershipFallback) defaultRefusal() {
	if f.ApprovedMaintainers == nil {
		f.ApprovedMaintainers = []string{}
	}
	if f.Missing == "" {
		f.Missing = OwnershipRefuse
	}
	if f.Malformed == "" {
		f.Malformed = OwnershipRefuse
	}
	if f.Ambiguous == "" {
		f.Ambiguous = OwnershipRefuse
	}
	if f.Unmatched == "" {
		f.Unmatched = OwnershipRefuse
	}
}

type RepositoryProfile struct {
	Version           int               `json:"version" yaml:"version"`
	Organization      string            `json:"organization" yaml:"organization"`
	Repository        string            `json:"repository" yaml:"repository"`
	EventAllowlist    []string          `json:"event_allowlist" yaml:"event_allowlist"`
	DataClass         string            `json:"data_class" yaml:"data_class"`
	Publication       Publication       `json:"publication" yaml:"publication"`
	OwnershipFallback OwnershipFallback `json:"ownership_fallback" yaml:"ownership_fallback"`
}

// ParseService, ParseOrganization and ParseRepository accept json or yaml
// and reject unknown, duplicate, ambiguous, or unsupported fields/documents.
func ParseService(data []byte, format string) (ServiceConfig, error) {
	var p ServiceConfig
	if err := decode(data, format, &p); err != nil {
		return ServiceConfig{}, err
	}
	if err := p.Validate(); err != nil {
		return ServiceConfig{}, err
	}
	return p, nil
}

// ParseOrganization and ParseRepository reject unknown,
// duplicate, non-string, ambiguous, or unsupported fields/documents.
func ParseOrganization(data []byte, format string) (OrganizationPolicy, error) {
	var p OrganizationPolicy
	if err := decode(data, format, &p); err != nil {
		return OrganizationPolicy{}, err
	}
	if err := p.Validate(); err != nil {
		return OrganizationPolicy{}, err
	}
	return p, nil
}

func ParseRepository(data []byte, format string) (RepositoryProfile, error) {
	var p RepositoryProfile
	if err := decode(data, format, &p); err != nil {
		return RepositoryProfile{}, err
	}
	p.OwnershipFallback.defaultRefusal()
	if err := p.Validate(); err != nil {
		return RepositoryProfile{}, err
	}
	return p, nil
}

func decode(data []byte, format string, out any) error {
	if len(data) == 0 || len(data) > maxConfigBytes {
		return errors.New("config: empty or oversized input")
	}
	switch strings.ToLower(strings.TrimPrefix(format, ".")) {
	case "json":
		if err := rejectDuplicateJSON(data); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if err := strictJSONKeys(data, reflect.TypeOf(out).Elem()); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		d := json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		if err := d.Decode(out); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		var extra any
		if err := d.Decode(&extra); err != io.EOF {
			return errors.New("config: trailing JSON value")
		}
	case "yaml", "yml":
		var node yaml.Node
		d := yaml.NewDecoder(bytes.NewReader(data))
		if err := d.Decode(&node); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if err := checkYAML(&node, 0); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		var extra yaml.Node
		if err := d.Decode(&extra); err != io.EOF {
			return errors.New("config: trailing YAML document")
		}
		// KnownFields is enforced by the decoder, not by Node.Decode.
		d = yaml.NewDecoder(bytes.NewReader(data))
		d.KnownFields(true)
		if err := d.Decode(out); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	default:
		return fmt.Errorf("config: unsupported format %q", format)
	}
	return nil
}

// encoding/json matches struct fields case-insensitively even with
// DisallowUnknownFields. Check spelling exactly before decoding into structs.
func strictJSONKeys(data []byte, typ reflect.Type) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return errors.New("expected JSON object")
	}
	for name, raw := range fields {
		found := false
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if name != field.Tag.Get("json") {
				continue
			}
			found = true
			if field.Type.Kind() == reflect.Struct {
				if err := strictJSONKeys(raw, field.Type); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
			}
			break
		}
		if !found {
			return fmt.Errorf("unknown JSON field %q", name)
		}
	}
	return nil
}

func checkYAML(n *yaml.Node, depth int) error {
	if depth > 64 {
		return errors.New("YAML nesting limit exceeded")
	}
	if n.Anchor != "" || n.Kind == yaml.AliasNode {
		return errors.New("YAML anchors and aliases are not allowed")
	}
	if n.Tag == "!!null" {
		return errors.New("YAML null is not allowed")
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return errors.New("invalid YAML document")
		}
	case yaml.MappingNode:
		if n.Tag != "!!map" {
			return errors.New("unsupported YAML map tag")
		}
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Tag != "!!str" || key.Kind != yaml.ScalarNode || key.Value == "<<" {
				return errors.New("invalid YAML key or merge")
			}
			if seen[key.Value] {
				return fmt.Errorf("duplicate YAML key %q", key.Value)
			}
			seen[key.Value] = true
		}
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return errors.New("unsupported YAML sequence tag")
		}
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str", "!!bool", "!!int":
		default:
			return errors.New("unsupported YAML scalar tag")
		}
	default:
		return errors.New("unsupported YAML node")
	}
	for _, child := range n.Content {
		if err := checkYAML(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func rejectDuplicateJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSON(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func scanJSON(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit exceeded")
	}
	tok, err := d.Token()
	if err != nil {
		return err
	}
	start, ok := tok.(json.Delim)
	if !ok {
		if tok == nil {
			return errors.New("JSON null is not allowed")
		}
		return nil
	}
	switch start {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			tok, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := tok.(string)
			if !ok {
				return errors.New("non-string JSON key")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = true
			if err := scanJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := scanJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}

// GitHub owner/repository names are ASCII and case-insensitive. Compare only
// validated names; never trim, Unicode-fold, or infer permission from access.
func validName(s string) bool  { return len(s) <= 100 && namePattern.MatchString(s) }
func identity(s string) string { return strings.ToLower(s) }
func validRepo(s, org string) bool {
	parts := strings.Split(s, "/")
	return len(parts) == 2 && validName(parts[0]) && validName(parts[1]) &&
		(org == "" || identity(parts[0]) == identity(org))
}
func validRepositories(repositories []string, org string) error {
	if len(repositories) == 0 {
		return errors.New("explicit nonempty repository_allowlist required")
	}
	seen := map[string]bool{}
	for _, r := range repositories {
		key := identity(r)
		if !validRepo(r, org) || seen[key] {
			return fmt.Errorf("invalid or ambiguous repository %q", r)
		}
		seen[key] = true
	}
	return nil
}
func validClasses(classes []string) error {
	seen := map[string]bool{}
	for _, c := range classes {
		if !validClass(c) || seen[c] {
			return fmt.Errorf("invalid or duplicate data class %q", c)
		}
		seen[c] = true
	}
	return nil
}
func validEvents(events []string) error {
	if len(events) == 0 {
		return errors.New("explicit nonempty event_allowlist required")
	}
	seen := map[string]bool{}
	for _, e := range events {
		// This switch is the immutable service event/action ceiling.
		switch e {
		case "issues/opened", "pull_request/opened", "issue_comment/created",
			"pull_request_review/submitted", "pull_request_review_comment/created":
		default:
			return fmt.Errorf("unsupported event %q", e)
		}
		if seen[e] {
			return fmt.Errorf("duplicate event %q", e)
		}
		seen[e] = true
	}
	return nil
}
func validClass(s string) bool {
	switch s {
	case "public", "internal", "private":
		return true
	}
	return false
}
func (p ServiceConfig) Validate() error {
	if p.Version != Version {
		return fmt.Errorf("unsupported service version %d", p.Version)
	}
	if err := validRepositories(p.RepositoryAllowlist, ""); err != nil {
		return err
	}
	if err := validEvents(p.EventAllowlist); err != nil {
		return err
	}
	return validClasses(p.DataClasses)
}
func (p OrganizationPolicy) Validate() error {
	if p.Version != Version {
		return fmt.Errorf("unsupported organization version %d", p.Version)
	}
	if !validName(p.Organization) {
		return errors.New("invalid organization")
	}
	if err := validRepositories(p.RepositoryAllowlist, p.Organization); err != nil {
		return err
	}
	if err := validEvents(p.EventAllowlist); err != nil {
		return err
	}
	return validClasses(p.DataClasses)
}
func (p RepositoryProfile) Validate() error {
	if p.Version != Version {
		return fmt.Errorf("unsupported repository version %d", p.Version)
	}
	if !validName(p.Organization) || !validRepo(p.Repository, p.Organization) {
		return errors.New("invalid profile organization or repository")
	}
	if err := validEvents(p.EventAllowlist); err != nil {
		return err
	}
	if !validClass(p.DataClass) {
		return errors.New("invalid data_class")
	}
	return p.OwnershipFallback.Validate()
}

// Credentials reports effective permissions, never token values. ExcessPermissions
// is set by the credential inspector for any permission outside read/comment.
type Credentials struct {
	ReadRepository      bool
	IssueComments       bool
	PullRequestComments bool
	ExcessPermissions   bool
}

type RolloutPhase string

const (
	RolloutDisabled RolloutPhase = "disabled"
	RolloutFixture  RolloutPhase = "fixture"
	RolloutDryRun   RolloutPhase = "dry_run"
	RolloutLive     RolloutPhase = "live"
)

// Runtime switches are opt-in and default to deny. The runner and publisher
// attestations must be supplied by their respective trusted runtime components.
type Runtime struct {
	Phase                  RolloutPhase
	IntakeEnabled          bool
	LivePublicationEnabled bool
	ApprovedRealRunner     bool
	ApprovedDataClasses    []string
	PublisherHealthy       bool
}

type EffectivePolicy struct {
	// AdmitReview is authenticated GitHub event intake; FixtureReview is only
	// eligibility for local sanitized, non-publishing fixture review.
	AdmitReview         bool
	FixtureReview       bool
	IssueComments       bool
	PullRequestComments bool
	PermissionMismatch  bool
}

// Resolve is the only exported effective-policy resolver. The versioned service
// gate is mandatory; no installed-repository or credential permission opts a
// target into a missing service, organization or profile allowlist.
func Resolve(service ServiceConfig, org OrganizationPolicy, profile RepositoryProfile, repository, event string, creds Credentials, runtime Runtime) (EffectivePolicy, error) {
	if err := service.Validate(); err != nil {
		return EffectivePolicy{}, err
	}
	if err := org.Validate(); err != nil {
		return EffectivePolicy{}, err
	}
	if err := profile.Validate(); err != nil {
		return EffectivePolicy{}, err
	}
	if !validRepo(repository, org.Organization) ||
		identity(profile.Organization) != identity(org.Organization) ||
		identity(profile.Repository) != identity(repository) {
		return EffectivePolicy{}, errors.New("ambiguous or mismatched profile ownership")
	}
	switch runtime.Phase {
	case "", RolloutDisabled, RolloutFixture, RolloutDryRun, RolloutLive:
	default:
		return EffectivePolicy{}, errors.New("unsupported rollout phase")
	}
	for _, c := range runtime.ApprovedDataClasses {
		if !validClass(c) {
			return EffectivePolicy{}, errors.New("invalid runtime data class")
		}
	}
	eff := EffectivePolicy{PermissionMismatch: creds.ExcessPermissions}
	allowed := containsRepository(service.RepositoryAllowlist, repository) && containsRepository(org.RepositoryAllowlist, repository) &&
		contains(service.EventAllowlist, event) && contains(org.EventAllowlist, event) && contains(profile.EventAllowlist, event) &&
		contains(service.DataClasses, profile.DataClass) && contains(org.DataClasses, profile.DataClass) &&
		contains(runtime.ApprovedDataClasses, profile.DataClass)
	// Local fixture work is separate from signed event intake. A fixture
	// requires explicit non-live rollout and no GitHub credential permissions;
	// service/runtime intake and publication switches cannot opt it in or out.
	eff.FixtureReview = allowed && (runtime.Phase == RolloutFixture || runtime.Phase == RolloutDryRun) &&
		!creds.ReadRepository && !creds.IssueComments && !creds.PullRequestComments && !creds.ExcessPermissions
	// Disabled and fixture rollout never admit live GitHub events. Dry-run
	// intake still requires every ordinary live-intake gate.
	eff.AdmitReview = allowed && service.IntakeEnabled && runtime.IntakeEnabled && creds.ReadRepository &&
		(runtime.Phase == RolloutLive || runtime.Phase == RolloutDryRun)
	live := eff.AdmitReview && service.PublicationEnabled && runtime.Phase == RolloutLive && runtime.LivePublicationEnabled &&
		runtime.ApprovedRealRunner && runtime.PublisherHealthy && !creds.ExcessPermissions
	eff.IssueComments = live && service.Publication.IssueComments && org.Publication.IssueComments && profile.Publication.IssueComments && creds.IssueComments
	eff.PullRequestComments = live && service.Publication.PullRequestComments && org.Publication.PullRequestComments && profile.Publication.PullRequestComments && creds.PullRequestComments
	return eff, nil
}
func containsRepository(ss []string, repository string) bool {
	for _, r := range ss {
		if identity(r) == identity(repository) {
			return true
		}
	}
	return false
}
func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
