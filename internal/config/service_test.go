// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const serviceYAML = "version: 1\nintake_enabled: true\npublication_enabled: true\n" +
	"repository_allowlist: [example-org/a]\nevent_allowlist: [issues/opened, pull_request/opened]\n" +
	"data_classes: [public]\npublication:\n  issue_comments: true\n  pull_request_comments: true\n"

func TestServiceStrictFormats(t *testing.T) {
	s, err := ParseService([]byte(serviceYAML), "yaml")
	if err != nil {
		t.Fatal(err)
	}
	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := ParseService(j, "json")
	if err != nil || !reflect.DeepEqual(s, fromJSON) {
		t.Fatalf("service YAML/JSON mismatch: %v, %+v", err, fromJSON)
	}
	cases := map[string]string{
		"unknown":             serviceYAML + "other: true\n",
		"unsupported version": strings.Replace(serviceYAML, "version: 1", "version: 2", 1),
		"missing version":     strings.Replace(serviceYAML, "version: 1\n", "", 1),
		"missing repos":       strings.Replace(serviceYAML, "[example-org/a]", "[]", 1),
		"unsupported event":   strings.Replace(serviceYAML, "issues/opened", "issues/closed", 1),
		"missing events":      strings.Replace(serviceYAML, "[issues/opened, pull_request/opened]", "[]", 1),
		"duplicate repo case": strings.Replace(serviceYAML, "[example-org/a]", "[example-org/a, Example-Org/A]", 1),
		"forbidden mutation":  strings.Replace(serviceYAML, "  issue_comments: true", "  push: true\n  issue_comments: true", 1),
		"duplicate switch":    serviceYAML + "intake_enabled: false\n",
		"YAML alias":          strings.Replace(serviceYAML, "data_classes: [public]", "data_classes: &classes [public]", 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseService([]byte(raw), "yaml"); err == nil {
				t.Fatal("accepted invalid service")
			}
		})
	}
	for name, raw := range map[string]string{
		"unknown switch":    strings.Replace(string(j), "\"intake_enabled\":true", "\"intake_enabledd\":true", 1),
		"case-alias switch": strings.Replace(string(j), "\"intake_enabled\":true", "\"Intake_Enabled\":true", 1),
		"duplicate switch":  strings.Replace(string(j), "\"intake_enabled\":true", "\"intake_enabled\":true,\"intake_enabled\":false", 1),
		"mutation":          strings.Replace(string(j), "\"issue_comments\":true", "\"merge\":true,\"issue_comments\":true", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if raw == string(j) {
				t.Fatal("test substitution did not apply")
			}
			if _, err := ParseService([]byte(raw), "json"); err == nil {
				t.Fatal("accepted invalid JSON service")
			}
		})
	}
}

func TestServiceCannotBeBypassed(t *testing.T) {
	o, p := validConfig(t)
	c, r := enabled()
	baseline := resolve(t, enabledService(), o, p, p.Repository, "issues/opened", c, r)
	if !baseline.AdmitReview || !baseline.IssueComments || !baseline.PullRequestComments {
		t.Fatalf("baseline: %+v", baseline)
	}
	s := enabledService()
	if _, err := Resolve(ServiceConfig{}, o, p, p.Repository, "issues/opened", c, r); err == nil {
		t.Fatal("zero service config accepted")
	}
	for name, change := range map[string]func(*ServiceConfig){
		"intake off":            func(s *ServiceConfig) { s.IntakeEnabled = false },
		"repo not allowlisted":  func(s *ServiceConfig) { s.RepositoryAllowlist = []string{"example-org/b"} },
		"event not allowlisted": func(s *ServiceConfig) { s.EventAllowlist = []string{"pull_request/opened"} },
		"class not allowlisted": func(s *ServiceConfig) { s.DataClasses = nil },
	} {
		t.Run(name, func(t *testing.T) {
			v := s
			change(&v)
			eff := resolve(t, v, o, p, p.Repository, "issues/opened", c, r)
			if eff.AdmitReview || eff.IssueComments || eff.PullRequestComments {
				t.Fatalf("service ceiling bypass: %+v", eff)
			}
		})
	}
	for name, change := range map[string]func(*ServiceConfig){
		"global publication off": func(s *ServiceConfig) { s.PublicationEnabled = false },
		"issue switch off":       func(s *ServiceConfig) { s.Publication.IssueComments = false },
		"pull switch off":        func(s *ServiceConfig) { s.Publication.PullRequestComments = false },
	} {
		t.Run(name, func(t *testing.T) {
			v := s
			change(&v)
			eff := resolve(t, v, o, p, p.Repository, "issues/opened", c, r)
			if !eff.AdmitReview {
				t.Fatal("service publication incorrectly disabled intake")
			}
			if name == "global publication off" && (eff.IssueComments || eff.PullRequestComments) {
				t.Fatalf("global publication bypass: %+v", eff)
			}
			if name == "issue switch off" && (eff.IssueComments || !eff.PullRequestComments) {
				t.Fatalf("independent issue switch: %+v", eff)
			}
			if name == "pull switch off" && (!eff.IssueComments || eff.PullRequestComments) {
				t.Fatalf("independent pull switch: %+v", eff)
			}
		})
	}
}

func TestMixedCaseGitHubIdentity(t *testing.T) {
	s := enabledService()
	s.RepositoryAllowlist = []string{"ClawOsirisOrg/Syn"}
	o, p := validConfig(t)
	o.Organization = "ClawOsirisOrg"
	o.RepositoryAllowlist = []string{"clawosirisorg/sYn"}
	p.Organization = "CLAWOSIRISORG"
	p.Repository = "ClawOsirisOrg/syn"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	c, r := enabled()
	for _, repo := range []string{"ClawOsirisOrg/syn", "clawosirisorg/SYN", "CLAWOSIRISORG/Syn"} {
		eff := resolve(t, s, o, p, repo, "issues/opened", c, r)
		if !eff.IssueComments {
			t.Fatalf("mixed-case identity rejected %q: %+v", repo, eff)
		}
	}
	for _, repo := range []string{"ClawOsirisOrg/other", "OtherOrg/Syn", "ClawOsirisOrg/Syn/extra", "ClawOsirisOrg/syn ", "ClawOsirisOrg/Sýn"} {
		eff, err := Resolve(s, o, p, repo, "issues/opened", c, r)
		if err == nil && (eff.AdmitReview || eff.IssueComments || eff.PullRequestComments) {
			t.Fatalf("other or ambiguous identity admitted %q: %+v", repo, eff)
		}
	}
	s.RepositoryAllowlist = []string{"ClawOsirisOrg/Syn", "clawosirisorg/syn"}
	if err := s.Validate(); err == nil {
		t.Fatal("duplicate mixed-case service entries accepted")
	}
	o.RepositoryAllowlist = []string{"ClawOsirisOrg/Syn", "clawosirisorg/syn"}
	if err := o.Validate(); err == nil {
		t.Fatal("duplicate mixed-case org entries accepted")
	}
}

func TestServiceExamplesDefaultOff(t *testing.T) {
	base := filepath.Join("..", "..", "configs")
	y, err := os.ReadFile(filepath.Join(base, "service.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	j, err := os.ReadFile(filepath.Join(base, "service.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseService(y, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseService(j, "json")
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("service examples not equivalent: %v", err)
	}
	if a.IntakeEnabled || a.PublicationEnabled || a.Publication != (Publication{}) || len(a.DataClasses) != 0 {
		t.Fatalf("unsafe service defaults: %+v", a)
	}
	orgBytes, err := os.ReadFile(filepath.Join(base, "organization.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	org, err := ParseOrganization(orgBytes, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	profileBytes, err := os.ReadFile(filepath.Join(base, "repository.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ParseRepository(profileBytes, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, r := enabled()
	eff := resolve(t, a, org, profile, profile.Repository, "issues/opened", c, r)
	if eff.AdmitReview || eff.IssueComments || eff.PullRequestComments {
		t.Fatalf("example enabled behavior: %+v", eff)
	}
}

// A fixture phase is local-only: it must not depend on service webhook intake
// or a GitHub read token, and it never enables GitHub comment publication.
func TestFixtureEligibilityDefaultOffIntake(t *testing.T) {
	o, p := validConfig(t)
	s := enabledService()
	s.IntakeEnabled = false
	s.PublicationEnabled = false
	s.Publication = Publication{}
	// The fixture runner has a data-class approval, but no GitHub credentials.
	c := Credentials{}
	r := Runtime{Phase: RolloutFixture, ApprovedDataClasses: []string{"public"}}
	e := resolve(t, s, o, p, p.Repository, "issues/opened", c, r)
	if !e.FixtureReview || e.AdmitReview || e.IssueComments || e.PullRequestComments {
		t.Fatalf("fixture must remain local-only: %+v", e)
	}
	r.Phase = RolloutDryRun
	e = resolve(t, s, o, p, p.Repository, "issues/opened", c, r)
	if !e.FixtureReview || e.AdmitReview || e.IssueComments || e.PullRequestComments {
		t.Fatalf("dry-run fixture must remain local-only: %+v", e)
	}
	// Turning on every service/runtime intake and publication switch cannot
	// convert credential-free fixture eligibility into live intake or writing.
	s.IntakeEnabled, s.PublicationEnabled = true, true
	s.Publication = Publication{IssueComments: true, PullRequestComments: true}
	r.IntakeEnabled, r.LivePublicationEnabled = true, true
	r.ApprovedRealRunner, r.PublisherHealthy = true, true
	e = resolve(t, s, o, p, p.Repository, "issues/opened", c, r)
	if !e.FixtureReview || e.AdmitReview || e.IssueComments || e.PullRequestComments {
		t.Fatalf("credential-free fixture escalated with all switches enabled: %+v", e)
	}
	// The same path works with an example service whose intake is default-off
	// once its repository and data class have been explicitly allowlisted.
	path := filepath.Join("..", "..", "configs", "service.example.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fromExample, err := ParseService(data, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	fromExample.RepositoryAllowlist = []string{p.Repository}
	e = resolve(t, fromExample, o, p, p.Repository, "issues/opened", c, r)
	if e.FixtureReview || e.AdmitReview || e.IssueComments || e.PullRequestComments {
		t.Fatalf("fixture review bypassed absent service data class: %+v", e)
	}
	fromExample.DataClasses = []string{p.DataClass}
	e = resolve(t, fromExample, o, p, p.Repository, "issues/opened", c, r)
	if !e.FixtureReview || e.AdmitReview || e.IssueComments || e.PullRequestComments {
		t.Fatalf("default-off service blocked local fixture or enabled a write: %+v", e)
	}
}

func TestFixtureNoEscalationAndAllowlistIntersection(t *testing.T) {
	o, p := validConfig(t)
	s := enabledService()
	r := Runtime{
		Phase: RolloutFixture, ApprovedDataClasses: []string{"public"},
		IntakeEnabled: true, LivePublicationEnabled: true,
		ApprovedRealRunner: true, PublisherHealthy: true,
	}
	c := Credentials{}
	for name, alter := range map[string]func(*ServiceConfig, *OrganizationPolicy, *RepositoryProfile, *Runtime, *Credentials){
		"service repo excluded": func(s *ServiceConfig, _ *OrganizationPolicy, _ *RepositoryProfile, _ *Runtime, _ *Credentials) {
			s.RepositoryAllowlist = []string{"example-org/b"}
		},
		"org repo excluded": func(_ *ServiceConfig, o *OrganizationPolicy, _ *RepositoryProfile, _ *Runtime, _ *Credentials) {
			o.RepositoryAllowlist = []string{"example-org/b"}
		},
		"service event excluded": func(s *ServiceConfig, _ *OrganizationPolicy, _ *RepositoryProfile, _ *Runtime, _ *Credentials) {
			s.EventAllowlist = []string{"pull_request/opened"}
		},
		"org event excluded": func(_ *ServiceConfig, o *OrganizationPolicy, _ *RepositoryProfile, _ *Runtime, _ *Credentials) {
			o.EventAllowlist = []string{"pull_request/opened"}
		},
		"profile event excluded": func(_ *ServiceConfig, _ *OrganizationPolicy, p *RepositoryProfile, _ *Runtime, _ *Credentials) {
			p.EventAllowlist = []string{"pull_request/opened"}
		},
		"service class excluded": func(s *ServiceConfig, _ *OrganizationPolicy, _ *RepositoryProfile, _ *Runtime, _ *Credentials) {
			s.DataClasses = nil
		},
		"org class excluded": func(_ *ServiceConfig, o *OrganizationPolicy, _ *RepositoryProfile, _ *Runtime, _ *Credentials) {
			o.DataClasses = nil
		},
		"runtime class excluded": func(_ *ServiceConfig, _ *OrganizationPolicy, _ *RepositoryProfile, r *Runtime, _ *Credentials) {
			r.ApprovedDataClasses = nil
		},
		"different profile class": func(_ *ServiceConfig, _ *OrganizationPolicy, p *RepositoryProfile, _ *Runtime, _ *Credentials) {
			p.DataClass = "private"
		},
		"read credential present": func(_ *ServiceConfig, _ *OrganizationPolicy, _ *RepositoryProfile, _ *Runtime, c *Credentials) {
			c.ReadRepository = true
		},
		"comment credential present": func(_ *ServiceConfig, _ *OrganizationPolicy, _ *RepositoryProfile, _ *Runtime, c *Credentials) {
			c.IssueComments = true
		},
		"excess permission": func(_ *ServiceConfig, _ *OrganizationPolicy, _ *RepositoryProfile, _ *Runtime, c *Credentials) {
			c.ExcessPermissions = true
		},
		"rollout disabled": func(_ *ServiceConfig, _ *OrganizationPolicy, _ *RepositoryProfile, r *Runtime, _ *Credentials) {
			r.Phase = RolloutDisabled
		},
		"rollout unspecified": func(_ *ServiceConfig, _ *OrganizationPolicy, _ *RepositoryProfile, r *Runtime, _ *Credentials) {
			r.Phase = ""
		},
		"rollout live": func(_ *ServiceConfig, _ *OrganizationPolicy, _ *RepositoryProfile, r *Runtime, _ *Credentials) {
			r.Phase = RolloutLive
		},
	} {
		t.Run(name, func(t *testing.T) {
			ss, oo, pp, rr, cc := s, o, p, r, c
			alter(&ss, &oo, &pp, &rr, &cc)
			e := resolve(t, ss, oo, pp, p.Repository, "issues/opened", cc, rr)
			if e.FixtureReview || e.AdmitReview || e.IssueComments || e.PullRequestComments {
				t.Fatalf("fixture or live escalation: %+v", e)
			}
		})
	}
	// Even when every publication gate is switched on, fixture rollout never
	// grants a live comment capability.
	e := resolve(t, s, o, p, p.Repository, "issues/opened", c, r)
	if !e.FixtureReview || e.AdmitReview || e.IssueComments || e.PullRequestComments {
		t.Fatalf("fixture rollout enabled live capability: %+v", e)
	}
	p.Repository = "example-org/b"
	if _, err := Resolve(s, o, p, "example-org/a", "issues/opened", c, r); err == nil {
		t.Fatal("profile ownership mismatch admitted")
	}
}

func TestLiveIntakeRemainsFailClosed(t *testing.T) {
	o, p := validConfig(t)
	s := enabledService()
	c, r := enabled()
	r.Phase = RolloutDisabled
	e := resolve(t, s, o, p, p.Repository, "issues/opened", c, r)
	if e.AdmitReview || e.FixtureReview || e.IssueComments || e.PullRequestComments {
		t.Fatalf("disabled rollout admitted event: %+v", e)
	}
	r.Phase = RolloutFixture
	e = resolve(t, s, o, p, p.Repository, "issues/opened", c, r)
	if e.AdmitReview || e.FixtureReview || e.IssueComments || e.PullRequestComments {
		t.Fatalf("fixture rollout admitted event with credentials: %+v", e)
	}
	r.Phase = RolloutDryRun
	e = resolve(t, s, o, p, p.Repository, "issues/opened", c, r)
	if !e.AdmitReview || e.FixtureReview || e.IssueComments || e.PullRequestComments {
		t.Fatalf("dry-run intake published or blocked explicit intake: %+v", e)
	}
	s.IntakeEnabled = false
	e = resolve(t, s, o, p, p.Repository, "issues/opened", c, r)
	if e.AdmitReview || e.FixtureReview || e.IssueComments || e.PullRequestComments {
		t.Fatalf("default-off service admitted event: %+v", e)
	}
}
