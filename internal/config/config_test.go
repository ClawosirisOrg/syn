// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const orgYAML = `version: 1
organization: example-org
repository_allowlist: [example-org/a]
event_allowlist: [issues/opened, pull_request/opened]
data_classes: [public]
publication:
  issue_comments: true
  pull_request_comments: true
`
const profileYAML = `version: 1
organization: example-org
repository: example-org/a
event_allowlist: [issues/opened, pull_request/opened]
data_class: public
publication:
  issue_comments: true
  pull_request_comments: true
`

func validConfig(t *testing.T) (OrganizationPolicy, RepositoryProfile) {
	t.Helper()
	o, err := ParseOrganization([]byte(orgYAML), "yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseRepository([]byte(profileYAML), "yaml")
	if err != nil {
		t.Fatal(err)
	}
	return o, p
}

func TestJSONAndYAMLEquivalence(t *testing.T) {
	o, p := validConfig(t)
	jsonOrg := `{"version":1,"organization":"example-org","repository_allowlist":["example-org/a"],"event_allowlist":["issues/opened","pull_request/opened"],"data_classes":["public"],"publication":{"issue_comments":true,"pull_request_comments":true}}`
	jsonProfile := `{"version":1,"organization":"example-org","repository":"example-org/a","event_allowlist":["issues/opened","pull_request/opened"],"data_class":"public","publication":{"issue_comments":true,"pull_request_comments":true}}`
	jO, err := ParseOrganization([]byte(jsonOrg), ".json")
	if err != nil || !reflect.DeepEqual(o, jO) {
		t.Fatalf("organization equivalence: %v, %+v", err, jO)
	}
	jP, err := ParseRepository([]byte(jsonProfile), ".yaml") // YAML must also accept JSON syntax.
	if err != nil || !reflect.DeepEqual(p, jP) {
		t.Fatalf("profile equivalence: %v, %+v", err, jP)
	}
	jP, err = ParseRepository([]byte(jsonProfile), "json")
	if err != nil || !reflect.DeepEqual(p, jP) {
		t.Fatalf("JSON profile equivalence: %v, %+v", err, jP)
	}
}

func TestRejectInvalidOrganization(t *testing.T) {
	cases := map[string]string{
		"missing version":      strings.Replace(orgYAML, "version: 1\n", "", 1),
		"future version":       strings.Replace(orgYAML, "version: 1", "version: 2", 1),
		"unknown":              orgYAML + "extra: true\n",
		"mutation":             orgYAML + "labels: true\n",
		"nested mutation":      strings.Replace(orgYAML, "  issue_comments: true", "  merge: true\n  issue_comments: true", 1),
		"missing repositories": strings.Replace(orgYAML, "repository_allowlist: [example-org/a]", "repository_allowlist: []", 1),
		"missing events":       strings.Replace(orgYAML, "event_allowlist: [issues/opened, pull_request/opened]", "event_allowlist: []", 1),
		"unsupported event":    strings.Replace(orgYAML, "issues/opened", "issues/closed", 1),
		"duplicate event":      strings.Replace(orgYAML, "issues/opened, pull_request/opened", "issues/opened, issues/opened", 1),
		"duplicate repository": strings.Replace(orgYAML, "[example-org/a]", "[example-org/a, example-org/a]", 1),
		"other owner":          strings.Replace(orgYAML, "example-org/a", "other-org/a", 1),
		"case ambiguity":       strings.Replace(orgYAML, "[example-org/a]", "[example-org/a, Example-Org/A]", 1),
		"duplicate key":        orgYAML + "version: 1\n",
		"alias":                strings.Replace(orgYAML, "organization: example-org", "organization: &owner example-org", 1),
		"merge":                orgYAML + "<<: {version: 1}\n",
		"multiple documents":   orgYAML + "---\nversion: 1\n",
		"null":                 strings.Replace(orgYAML, "organization: example-org", "organization: null", 1),
		"unknown data class":   strings.Replace(orgYAML, "[public]", "[secret]", 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseOrganization([]byte(input), "yaml"); err == nil {
				t.Fatal("accepted invalid organization")
			}
		})
	}
	jsonCases := []string{
		`{"version":1,"version":1}`,
		`{"version":1,"organization":"example-org","repository_allowlist":["example-org/a"],"event_allowlist":["issues/opened"],"publication":{"issue_comments":true,"issue_comments":true}}`,
		`{"version":1,"organization":"example-org","repository_allowlist":["example-org/a"],"event_allowlist":["issues/opened"],"publication":{"merge":true}}`,
		`{"version":1,"organization":"example-org","repository_allowlist":["example-org/a"],"event_allowlist":["issues/opened"],"publication":{"issue_comments":null}}`,
		`{"version":1,"organization":"example-org","repository_allowlist":["example-org/a"],"event_allowlist":["issues/opened"]}{}`,
	}
	for _, input := range jsonCases {
		if _, err := ParseOrganization([]byte(input), "json"); err == nil {
			t.Errorf("accepted invalid JSON %q", input)
		}
	}
}

func TestRejectInvalidProfile(t *testing.T) {
	cases := []string{
		strings.Replace(profileYAML, "version: 1", "version: 9", 1),
		strings.Replace(profileYAML, "repository: example-org/a", "repository: other-org/a", 1),
		strings.Replace(profileYAML, "event_allowlist: [issues/opened, pull_request/opened]", "event_allowlist: []", 1),
		strings.Replace(profileYAML, "data_class: public", "data_class: unknown", 1),
		profileYAML + "push: true\n",
		strings.Replace(profileYAML, "  issue_comments: true", "  approve: true\n  issue_comments: true", 1),
	}
	for _, input := range cases {
		if _, err := ParseRepository([]byte(input), "yaml"); err == nil {
			t.Errorf("accepted invalid profile %q", input)
		}
	}
}

func enabledService() ServiceConfig {
	return ServiceConfig{Version: Version, IntakeEnabled: true, PublicationEnabled: true,
		RepositoryAllowlist: []string{"example-org/a"}, EventAllowlist: []string{"issues/opened", "pull_request/opened"},
		DataClasses: []string{"public"}, Publication: Publication{IssueComments: true, PullRequestComments: true}}
}
func enabled() (Credentials, Runtime) {
	return Credentials{ReadRepository: true, IssueComments: true, PullRequestComments: true}, Runtime{
		Phase: RolloutLive, IntakeEnabled: true, LivePublicationEnabled: true,
		ApprovedRealRunner: true, ApprovedDataClasses: []string{"public"}, PublisherHealthy: true,
	}
}
func resolve(t *testing.T, service ServiceConfig, o OrganizationPolicy, p RepositoryProfile, repo, event string, c Credentials, r Runtime) EffectivePolicy {
	t.Helper()
	e, err := Resolve(service, o, p, repo, event, c, r)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func TestIntersection(t *testing.T) {
	o, p := validConfig(t)
	c, r := enabled()
	base := resolve(t, enabledService(), o, p, "example-org/a", "issues/opened", c, r)
	if !base.AdmitReview || !base.IssueComments || !base.PullRequestComments || base.PermissionMismatch {
		t.Fatalf("baseline: %+v", base)
	}
	for name, change := range map[string]func(*OrganizationPolicy, *RepositoryProfile, *Credentials, *Runtime){
		"no org repo": func(o *OrganizationPolicy, _ *RepositoryProfile, _ *Credentials, _ *Runtime) {
			o.RepositoryAllowlist = []string{"example-org/b"}
		},
		"no org event": func(o *OrganizationPolicy, _ *RepositoryProfile, _ *Credentials, _ *Runtime) {
			o.EventAllowlist = []string{"pull_request/opened"}
		},
		"no profile event": func(_ *OrganizationPolicy, p *RepositoryProfile, _ *Credentials, _ *Runtime) {
			p.EventAllowlist = []string{"pull_request/opened"}
		},
		"no org data class": func(o *OrganizationPolicy, _ *RepositoryProfile, _ *Credentials, _ *Runtime) { o.DataClasses = nil },
		"no runtime data class": func(_ *OrganizationPolicy, _ *RepositoryProfile, _ *Credentials, r *Runtime) {
			r.ApprovedDataClasses = nil
		},
		"no read credential": func(_ *OrganizationPolicy, _ *RepositoryProfile, c *Credentials, _ *Runtime) {
			c.ReadRepository = false
		},
		"no intake": func(_ *OrganizationPolicy, _ *RepositoryProfile, _ *Credentials, r *Runtime) { r.IntakeEnabled = false },
	} {
		t.Run(name, func(t *testing.T) {
			oo, pp, cc, rr := o, p, c, r
			change(&oo, &pp, &cc, &rr)
			e := resolve(t, enabledService(), oo, pp, "example-org/a", "issues/opened", cc, rr)
			if e.AdmitReview || e.IssueComments || e.PullRequestComments {
				t.Fatalf("escalation: %+v", e)
			}
		})
	}
	for name, change := range map[string]func(*OrganizationPolicy, *RepositoryProfile, *Credentials, *Runtime){
		"default rollout": func(_ *OrganizationPolicy, _ *RepositoryProfile, _ *Credentials, r *Runtime) { r.Phase = "" },
		"dry run":         func(_ *OrganizationPolicy, _ *RepositoryProfile, _ *Credentials, r *Runtime) { r.Phase = RolloutDryRun },
		"runtime publication off": func(_ *OrganizationPolicy, _ *RepositoryProfile, _ *Credentials, r *Runtime) {
			r.LivePublicationEnabled = false
		},
		"fake runner": func(_ *OrganizationPolicy, _ *RepositoryProfile, _ *Credentials, r *Runtime) {
			r.ApprovedRealRunner = false
		},
		"publisher unhealthy": func(_ *OrganizationPolicy, _ *RepositoryProfile, _ *Credentials, r *Runtime) {
			r.PublisherHealthy = false
		},
		"excess permission": func(_ *OrganizationPolicy, _ *RepositoryProfile, c *Credentials, _ *Runtime) {
			c.ExcessPermissions = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			oo, pp, cc, rr := o, p, c, r
			change(&oo, &pp, &cc, &rr)
			e := resolve(t, enabledService(), oo, pp, "example-org/a", "issues/opened", cc, rr)
			wantIntake := name != "default rollout"
			if e.AdmitReview != wantIntake || e.FixtureReview || e.IssueComments || e.PullRequestComments {
				t.Fatalf("publication or intake escalation: %+v", e)
			}
			if name == "excess permission" && !e.PermissionMismatch {
				t.Fatal("permission mismatch not visible")
			}
		})
	}
	for name, change := range map[string]func(*OrganizationPolicy, *RepositoryProfile, *Credentials){
		"org issue":        func(o *OrganizationPolicy, _ *RepositoryProfile, _ *Credentials) { o.Publication.IssueComments = false },
		"profile issue":    func(_ *OrganizationPolicy, p *RepositoryProfile, _ *Credentials) { p.Publication.IssueComments = false },
		"credential issue": func(_ *OrganizationPolicy, _ *RepositoryProfile, c *Credentials) { c.IssueComments = false },
	} {
		t.Run(name, func(t *testing.T) {
			oo, pp, cc := o, p, c
			change(&oo, &pp, &cc)
			e := resolve(t, enabledService(), oo, pp, "example-org/a", "issues/opened", cc, r)
			if e.IssueComments || !e.PullRequestComments {
				t.Fatalf("switches not independent: %+v", e)
			}
		})
	}
	for name, change := range map[string]func(*OrganizationPolicy, *RepositoryProfile, *Credentials){
		"org pull": func(o *OrganizationPolicy, _ *RepositoryProfile, _ *Credentials) {
			o.Publication.PullRequestComments = false
		},
		"profile pull": func(_ *OrganizationPolicy, p *RepositoryProfile, _ *Credentials) {
			p.Publication.PullRequestComments = false
		},
		"credential pull": func(_ *OrganizationPolicy, _ *RepositoryProfile, c *Credentials) { c.PullRequestComments = false },
	} {
		t.Run(name, func(t *testing.T) {
			oo, pp, cc := o, p, c
			change(&oo, &pp, &cc)
			e := resolve(t, enabledService(), oo, pp, "example-org/a", "issues/opened", cc, r)
			if !e.IssueComments || e.PullRequestComments {
				t.Fatalf("switches not independent: %+v", e)
			}
		})
	}
	if e := resolve(t, enabledService(), o, p, "example-org/a", "issues/closed", c, r); e.AdmitReview || e.IssueComments || e.PullRequestComments {
		t.Fatalf("unsupported event admitted: %+v", e)
	}
	p.Repository = "example-org/b"
	if _, err := Resolve(enabledService(), o, p, "example-org/a", "issues/opened", c, r); err == nil {
		t.Fatal("profile ownership mismatch accepted")
	}
}

func TestSafeDefaultsAndExamples(t *testing.T) {
	o, p := validConfig(t)
	c, r := Credentials{}, Runtime{}
	e := resolve(t, enabledService(), o, p, "example-org/a", "issues/opened", c, r)
	if e != (EffectivePolicy{}) {
		t.Fatalf("zero-value runtime/credential escalated: %+v", e)
	}
	base := filepath.Join("..", "..", "configs")
	yamlOrg, err := os.ReadFile(filepath.Join(base, "organization.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	jsonOrg, err := os.ReadFile(filepath.Join(base, "organization.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	o1, err := ParseOrganization(yamlOrg, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	o2, err := ParseOrganization(jsonOrg, "json")
	if err != nil || !reflect.DeepEqual(o1, o2) {
		t.Fatalf("examples differ: %v", err)
	}
	profile, err := os.ReadFile(filepath.Join(base, "repository.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p1, err := ParseRepository(profile, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, r = enabled()
	service := enabledService()
	service.RepositoryAllowlist = []string{p1.Repository}
	e = resolve(t, service, o1, p1, p1.Repository, "issues/opened", c, r)
	if e.AdmitReview || e.IssueComments || e.PullRequestComments {
		t.Fatalf("example enabled actions: %+v", e)
	}
}

func TestCaseSensitiveJSONAndForbiddenMutations(t *testing.T) {
	for _, name := range []string{"label", "labels", "close", "state", "push", "approve", "merge", "release", "workflow", "admin", "repair_pr"} {
		bad := strings.Replace(orgYAML, "publication:\n", "publication:\n  "+name+": true\n", 1)
		if _, err := ParseOrganization([]byte(bad), "yaml"); err == nil {
			t.Errorf("accepted %s mutation", name)
		}
		bad = strings.Replace(profileYAML, "publication:\n", "publication:\n  "+name+": true\n", 1)
		if _, err := ParseRepository([]byte(bad), "yaml"); err == nil {
			t.Errorf("accepted profile %s mutation", name)
		}
	}
	for _, input := range []string{
		"{\"version\":1,\"Organization\":\"example-org\",\"repository_allowlist\":[\"example-org/a\"],\"event_allowlist\":[\"issues/opened\"]}",
		"{\"version\":1,\"organization\":\"example-org\",\"repository_allowlist\":[\"example-org/a\"],\"event_allowlist\":[\"issues/opened\"],\"publication\":{\"Issue_Comments\":true}}",
	} {
		if _, err := ParseOrganization([]byte(input), "json"); err == nil {
			t.Errorf("accepted noncanonical JSON field: %s", input)
		}
	}
}

func TestNoUnknownPhaseOrFormat(t *testing.T) {
	o, p := validConfig(t)
	c, r := enabled()
	r.Phase = "experimental"
	if _, err := Resolve(enabledService(), o, p, p.Repository, "issues/opened", c, r); err == nil {
		t.Fatal("accepted unknown rollout")
	}
	if _, err := ParseOrganization([]byte(orgYAML), "toml"); err == nil {
		t.Fatal("accepted unknown format")
	}
	if _, err := ParseOrganization(make([]byte, maxConfigBytes+1), "yaml"); err == nil {
		t.Fatal("accepted oversized input")
	}
}
