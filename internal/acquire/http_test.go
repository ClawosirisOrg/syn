// SPDX-License-Identifier: AGPL-3.0-or-later
package acquire

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestHTTPGuardrails(t *testing.T) {
	status := http.StatusOK
	content := "{}"
	seen := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer test-only" {
			t.Error("missing authenticated GET")
		}
		if status == http.StatusFound {
			w.Header().Set("Location", "https://evil.example/steal")
		}
		w.WriteHeader(status)
		io.WriteString(w, content)
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	client, e := NewHTTPClient("test-only", transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "api.github.com" {
			t.Error("unsafe outbound origin/method")
		}
		cloned := r.Clone(r.Context())
		u := *r.URL
		u.Scheme = target.Scheme
		u.Host = target.Host
		cloned.URL = &u
		cloned.Host = target.Host
		return http.DefaultTransport.RoundTrip(cloned)
	}))
	if e != nil {
		t.Fatal(e)
	}
	p := "/repos/ClawOsirisOrg/syn"
	if _, e = client.GET(context.Background(), p, 5); e != nil {
		t.Fatal(e)
	}
	status = http.StatusFound
	if _, e = client.GET(context.Background(), p, 5); e == nil {
		t.Fatal("redirect accepted")
	}
	status = http.StatusNotFound
	if _, e = client.GET(context.Background(), p, 5); e == nil {
		t.Fatal("missing object accepted")
	}
	status = http.StatusOK
	content = strings.Repeat("x", 64)
	if _, e = client.GET(context.Background(), p, 5); e == nil {
		t.Fatal("oversized response accepted")
	}
	for _, bad := range []string{"https://api.github.com/repos/ClawOsirisOrg/syn", "//evil.example/a", "/repos/ClawOsirisOrg/syn?x=1", "/repos/ClawOsirisOrg/syn/contents/AGENTS.md?ref=pr-branch", "/repos/ClawOsirisOrg/syn/pulls/7", "/repos/ClawOsirisOrg/syn%2fother"} {
		prior := seen
		if _, e = client.GET(context.Background(), bad, 5); e == nil || seen != prior {
			t.Errorf("unsafe API path sent: %q", bad)
		}
	}
	if _, e = NewHTTPClient("", nil); e == nil {
		t.Fatal("unauthenticated client")
	}
}
