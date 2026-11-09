// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ownership provisionally resolves a single review owner from
// acquired default-branch CODEOWNERS and operator-approved maintainer metadata.
// It neither checks GitHub permissions nor grants any GitHub authority.
package ownership

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/ClawOsirisOrg/syn/internal/acquire"
	"github.com/ClawOsirisOrg/syn/internal/config"
)

const maxRules = 256
const maxLines = 1024
const maxLineBytes = 1024
const maxPaths = 128
const maxGuidanceBytes = 1 << 20

var loginRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)
var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Pin is an independently selected approved default branch/commit/location,
// not values learned from the Guidance witness or a pull request.
type Pin struct{ Repository, DefaultBranch, Commit, Path string }

// TrustedMaintainers is supplied ONLY by explicitly approved operator-owned
// repository metadata, never a webhook, PR, CODEOWNERS, or model output.
// Approved is an assertion by the caller, not an authenticated attestation:
// the integration must establish and protect the metadata provenance.
type TrustedMaintainers struct {
	Repository string
	Approved   bool
	Logins     []string
}

type Request struct {
	Profile     config.RepositoryProfile
	Pin         Pin
	Guidance    *acquire.Guidance // nil means confirmed missing; a bad witness is NOT missing
	Maintainers TrustedMaintainers
	Kind        string   // issue or pull_request
	Paths       []string // complete, verified changed paths for PR; issue paths if explicitly known
}

// Result never represents a publisher, GitHub permission or approval. Gap is
// set for a fallback or refusal; zero gap denotes a direct CODEOWNERS match.
type Result struct {
	OwnerID      string
	Gap          config.OwnershipGap
	FromFallback bool
}

// Resolve fails closed: invalid trust inputs are hard errors with no fallback.
// A configured fallback is attempted only for the four classified ownership
// gaps, and every candidate must be present in approved maintainer metadata.
// More than one distinct owner (including fallback candidates) is ambiguous.
func Resolve(req Request) (Result, error) {
	var empty Result
	if err := req.Profile.Validate(); err != nil {
		return empty, fmt.Errorf("invalid repository profile: %w", err)
	}
	if !strings.EqualFold(req.Pin.Repository, req.Profile.Repository) || req.Pin.DefaultBranch == "" || !commitRE.MatchString(req.Pin.Commit) || !codeownersPath(req.Pin.Path) {
		return empty, errors.New("invalid approved CODEOWNERS pin")
	}
	trusted, err := validateMaintainers(req.Maintainers, req.Profile.Repository)
	if err != nil {
		return empty, err
	}
	if req.Kind != "issue" && req.Kind != "pull_request" {
		return empty, errors.New("invalid target kind")
	}
	if len(req.Paths) > maxPaths {
		return empty, errors.New("too many target paths")
	}
	if req.Kind == "pull_request" && len(req.Paths) == 0 {
		return empty, errors.New("PR paths must be complete and nonempty")
	}
	for _, p := range req.Paths {
		if !validTargetPath(p) {
			return empty, errors.New("invalid target path")
		}
	}
	if req.Guidance == nil {
		return fallback(req.Profile.OwnershipFallback, config.OwnershipMissing, trusted)
	}
	if err := req.Guidance.Verify(req.Pin.Repository, req.Pin.DefaultBranch, req.Pin.Commit, req.Pin.Path); err != nil {
		return empty, fmt.Errorf("unverified CODEOWNERS guidance: %w", err)
	}
	rules, err := parse(req.Guidance.Body)
	if err != nil {
		return fallback(req.Profile.OwnershipFallback, config.OwnershipMalformed, trusted)
	}
	if len(req.Paths) == 0 {
		return fallback(req.Profile.OwnershipFallback, config.OwnershipUnmatched, trusted)
	}
	var chosen string
	var gap config.OwnershipGap
	ambiguous := false
	for _, p := range req.Paths {
		owner := ""
		for _, rule := range rules {
			if rule.matches(p) {
				owner = rule.owner
			} // CODEOWNERS last matching rule wins
		}
		if owner == "" {
			if gap == "" {
				gap = config.OwnershipUnmatched
			}
			continue
		}
		id, ok := trusted[strings.ToLower(owner)]
		if !ok {
			gap = config.OwnershipMalformed
			continue
		}
		if chosen != "" && !strings.EqualFold(chosen, id) {
			ambiguous = true
		}
		chosen = id
	}
	if ambiguous {
		return Result{Gap: config.OwnershipAmbiguous}, errors.New("ownership ambiguous: conflicting pinned CODEOWNERS owners")
	}
	if gap != "" {
		resolved, err := fallback(req.Profile.OwnershipFallback, gap, trusted)
		if err != nil {
			return resolved, err
		}
		if chosen != "" && !strings.EqualFold(chosen, resolved.OwnerID) {
			return Result{Gap: config.OwnershipAmbiguous}, errors.New("ownership ambiguous: fallback conflicts with pinned CODEOWNERS owner")
		}
		return resolved, nil
	}
	return Result{OwnerID: chosen}, nil
}

func fallback(policy config.OwnershipFallback, gap config.OwnershipGap, trusted map[string]string) (Result, error) {
	result := Result{Gap: gap}
	if policy.ModeFor(gap) != config.OwnershipApprovedMaintainers {
		return result, fmt.Errorf("ownership %s: fallback refused", gap)
	}
	// Do not arbitrarily select one of multiple approved candidates.
	if len(policy.ApprovedMaintainers) != 1 {
		return result, fmt.Errorf("ownership %s: fallback candidates ambiguous", gap)
	}
	login, ok := trusted[strings.ToLower(policy.ApprovedMaintainers[0])]
	if !ok {
		return result, fmt.Errorf("ownership %s: fallback candidate not verified", gap)
	}
	result.OwnerID, result.FromFallback = login, true
	return result, nil
}

func validateMaintainers(m TrustedMaintainers, repo string) (map[string]string, error) {
	if !m.Approved || !strings.EqualFold(m.Repository, repo) || len(m.Logins) > 256 {
		return nil, errors.New("maintainer metadata is not approved for repository")
	}
	verified := make(map[string]string, len(m.Logins))
	for _, login := range m.Logins {
		key := strings.ToLower(login)
		if !validLogin(login) || verified[key] != "" {
			return nil, errors.New("invalid or duplicate trusted maintainer")
		}
		verified[key] = login
	}
	return verified, nil
}
func validLogin(login string) bool {
	return len(login) <= 39 && loginRE.MatchString(login) && !strings.Contains(login, "--")
}
func codeownersPath(p string) bool {
	return p == "CODEOWNERS" || p == ".github/CODEOWNERS" || p == "docs/CODEOWNERS"
}
func validTargetPath(p string) bool {
	if p == "" || len(p) > 512 || path.Clean(p) != p || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "*?[]") || strings.IndexByte(p, 92) >= 0 {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	for _, c := range p {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

type rule struct{ kind, prefix, suffix, owner string }

// Conservative subset: *, /literal/path, /literal/directory/, *.extension,
// /literal/directory/*.extension. Only one @login per rule; standalone #
// may introduce a trailing comment. No escaping, negation,
// character classes, **, teams, wildcards elsewhere, or unanchored directory
// patterns. Unsupported lines invalidate the entire file, never silently skip.
func parse(body []byte) ([]rule, error) {
	if len(body) > maxGuidanceBytes {
		return nil, errors.New("CODEOWNERS too large")
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) > maxLines && !(len(lines) == maxLines+1 && lines[len(lines)-1] == "") {
		return nil, errors.New("too many CODEOWNERS lines")
	}
	rules := make([]rule, 0)
	for _, raw := range lines {
		if len(raw) > maxLineBytes {
			return nil, errors.New("CODEOWNERS line too long")
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || len(fields) > 2 && fields[2] != "#" {
			return nil, errors.New("unsupported CODEOWNERS line")
		}
		if !strings.HasPrefix(fields[1], "@") || !validLogin(strings.TrimPrefix(fields[1], "@")) {
			return nil, errors.New("invalid CODEOWNERS identity")
		}
		r, err := parsePattern(fields[0])
		if err != nil {
			return nil, err
		}
		r.owner = fields[1][1:]
		rules = append(rules, r)
		if len(rules) > maxRules {
			return nil, errors.New("too many CODEOWNERS rules")
		}
	}
	return rules, nil
}
func parsePattern(p string) (rule, error) {
	if p == "*" {
		return rule{kind: "all"}, nil
	}
	if strings.HasPrefix(p, "*.") && validSuffix(p[2:]) {
		return rule{kind: "suffix", suffix: p[1:]}, nil
	}
	if !strings.HasPrefix(p, "/") {
		return rule{}, errors.New("unsupported unanchored pattern")
	}
	name := strings.TrimPrefix(p, "/")
	if i := strings.LastIndex(name, "/*."); i >= 0 && i+3 < len(name) && validLiteralPattern(name[:i]) && validSuffix(name[i+3:]) {
		return rule{kind: "childSuffix", prefix: name[:i] + "/", suffix: name[i+2:]}, nil
	}
	if strings.HasSuffix(name, "/") && validLiteralPattern(strings.TrimSuffix(name, "/")) {
		return rule{kind: "dir", prefix: name}, nil
	}
	if validLiteralPattern(name) {
		return rule{kind: "exact", prefix: name}, nil
	}
	return rule{}, errors.New("unsupported CODEOWNERS pattern")
}

// Reject characters whose CODEOWNERS semantics may differ from a literal.
func validLiteralPattern(p string) bool {
	if !validTargetPath(p) {
		return false
	}
	for _, c := range p {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '/' || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}
func validSuffix(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for _, c := range s {
		if c < 'A' || c > 'Z' {
			if c < 'a' || c > 'z' {
				if c < '0' || c > '9' {
					if c != '-' && c != '_' {
						return false
					}
				}
			}
		}
	}
	return true
}
func (r rule) matches(p string) bool {
	switch r.kind {
	case "all":
		return true
	case "exact":
		// A slash-anchored literal can name a directory in CODEOWNERS;
		// it owns descendants as well as the path itself.
		return p == r.prefix || strings.HasPrefix(p, r.prefix+"/")
	case "dir":
		return strings.HasPrefix(p, r.prefix)
	case "suffix":
		return strings.HasSuffix(path.Base(p), r.suffix)
	case "childSuffix":
		return strings.HasPrefix(p, r.prefix) && !strings.Contains(strings.TrimPrefix(p, r.prefix), "/") && strings.HasSuffix(p, r.suffix)
	}
	return false
}
