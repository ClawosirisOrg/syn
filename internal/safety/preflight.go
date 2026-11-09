// SPDX-License-Identifier: AGPL-3.0-or-later

// Package safety implements a provisional, local-only deterministic preflight.
// A passing result is not an authorization to invoke a runner: acquisition,
// policy, context construction and trust isolation are separate boundaries.
package safety

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"html"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ClawOsirisOrg/syn/internal/contracts"
)

const GateVersion = "preflight-v1"
const MaxSourceBytes = 256 * 1024
const MaxTotalBytes = 1024 * 1024
const MaxSources = 32
const MaxDetectors = 16
const MaxHits = 64
const MaxScanTime = 2 * time.Second

// Source is a complete, already acquired source. Complete must be asserted by
// the acquirer, not inferred from the bytes. This cannot prove the selected
// source set is complete or independently authenticate a snapshot hash.
type Source struct {
	ID       string
	Body     []byte
	Complete bool
}

// View is read-only by convention. Detectors must not retain or mutate Text,
// make external calls, or return raw text in diagnostics. The gate passes a copy.
type View struct {
	ID   string
	Text string
}

// Hit uses byte offsets into View.Text; references emitted by the gate are
// hashes of class/source/offsets, never snippets or hashes of secret values.
// Only the built-in email detector can request redaction.
type Hit struct {
	Class      string
	Start, End int
	Redact     bool
}
type Detector interface {
	Detect(context.Context, View) ([]Hit, error)
}
type DetectorFunc func(context.Context, View) ([]Hit, error)

func (f DetectorFunc) Detect(ctx context.Context, v View) ([]Hit, error) { return f(ctx, v) }

type Options struct {
	// AllowEmailRedaction explicitly permits only complete ASCII email matches
	// to be replaced by the fixed literal [REDACTED EMAIL]. Default is false.
	AllowEmailRedaction bool
	// Additional cooperative detectors. They may restrict, never override,
	// built-in findings. Nil detector or invalid output fails closed. Live use
	// needs an outer process isolation/deadline: in-process context cancellation
	// cannot terminate a detector that ignores its context.
	Detectors []Detector
	Timeout   time.Duration
}

// SanitizedSource is data only. Caller must preserve its untrusted provenance,
// escape/quote it when constructing an envelope, and never elevate it to policy.
type SanitizedSource struct {
	ID   string
	Text string
}
type Result struct {
	Safety contracts.SafetyResult
	// Sources is nil on quarantine/refuse, and is a complete ordered set on pass.
	Sources []SanitizedSource
}

func digest(b []byte) contracts.Hash {
	h := sha256.Sum256(b)
	return contracts.Hash(hex.EncodeToString(h[:]))
}
func finding(class, id string, start, end int) contracts.Finding {
	// Domain separation prevents confusing this location reference with content.
	h := digest([]byte("safety-v1:" + class + ":" + id + ":" + itoa(start) + ":" + itoa(end)))
	return contracts.Finding{Class: class, SourceID: id, ReferenceHash: h}
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
func stop(s contracts.SafetyResult, class, id string) Result {
	s.Outcome = "refuse"
	s.Findings = []contracts.Finding{finding(class, id, 0, 0)}
	return Result{Safety: s}
}

// Check validates metadata and every byte before producing a data-only copy.
// Input uncertainty with a valid manifest returns a refusal. Invalid or
// unbounded manifest identity returns an error: no valid contract result can
// be constructed without a trustworthy versioned manifest.
func Check(ctx context.Context, manifest contracts.SourceManifest, sources []Source, opt Options) (Result, error) {
	if len(manifest.Sources) == 0 || len(manifest.Sources) > MaxSources {
		return Result{}, errors.New("source manifest count outside bound")
	}
	if err := manifest.Validate(); err != nil {
		return Result{}, errors.New("invalid source manifest")
	}
	s := contracts.SafetyResult{SchemaVersion: contracts.SchemaVersion, SnapshotHash: manifest.SnapshotHash, GateVersion: GateVersion, Outcome: "pass", Findings: []contracts.Finding{}}
	first := manifest.Sources[0].ID
	if ctx == nil || len(sources) != len(manifest.Sources) || len(sources) > MaxSources || len(opt.Detectors) > MaxDetectors || opt.Timeout < 0 || opt.Timeout > MaxScanTime {
		return stop(s, "unsupported_content", first), nil
	}
	timeout := opt.Timeout
	if timeout == 0 {
		timeout = MaxScanTime
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	total := 0
	// Verify all sources before scanning or emitting even a partial safe envelope.
	for i, entry := range manifest.Sources {
		src := sources[i]
		if src.ID != entry.ID || !src.Complete || len(src.Body) != int(entry.Bytes) || len(src.Body) > MaxSourceBytes || total > MaxTotalBytes-len(src.Body) || digest(src.Body) != entry.ContentHash {
			return stop(s, "unsupported_content", entry.ID), nil
		}
		total += len(src.Body)
		if !utf8.Valid(src.Body) || strings.ContainsRune(string(src.Body), '\x00') {
			return stop(s, "unsupported_content", entry.ID), nil
		}
		for _, r := range string(src.Body) {
			if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
				return stop(s, "unsupported_content", entry.ID), nil
			}
		}
		if strings.HasPrefix(string(src.Body), "PK\x03\x04") || strings.HasPrefix(string(src.Body), "\x1f\x8b") || strings.HasPrefix(string(src.Body), "%!PS") {
			return stop(s, "unsupported_content", entry.ID), nil
		}
	}
	safe := make([]SanitizedSource, 0, len(sources))
	hasRedaction := false
	hasQuarantine := false
	hasRefusal := false
	for _, src := range sources {
		if ctx.Err() != nil {
			return stop(s, "scanner_error", src.ID), nil
		}
		body := strings.ReplaceAll(string(src.Body), "\r\n", "\n")
		body = strings.ReplaceAll(body, "\r", "\n")
		hits := builtin(body, opt.AllowEmailRedaction)
		for _, det := range opt.Detectors {
			if det == nil {
				return stop(s, "scanner_error", src.ID), nil
			}
			// Cooperative detectors are required. A detector that ignores context
			// cannot be force-killed in-process; the caller must isolate it.
			got, err := invoke(ctx, det, View{ID: src.ID, Text: body})
			if err != nil || ctx.Err() != nil || len(got) > MaxHits {
				return stop(s, "scanner_error", src.ID), nil
			}
			hits = append(hits, got...)
		}
		if len(hits) > MaxHits {
			return stop(s, "scanner_error", src.ID), nil
		}
		sort.Slice(hits, func(i, j int) bool {
			if hits[i].Start != hits[j].Start {
				return hits[i].Start < hits[j].Start
			}
			if hits[i].End != hits[j].End {
				return hits[i].End < hits[j].End
			}
			return hits[i].Class < hits[j].Class
		})
		var out strings.Builder
		last := 0
		for _, h := range hits {
			if h.Start < 0 || h.End <= h.Start || h.End > len(body) || !utf8.RuneStart(body[h.Start]) || h.End < len(body) && !utf8.RuneStart(body[h.End]) || !allowed(h.Class) || h.Redact && (h.Class != "redaction" || !opt.AllowEmailRedaction || !emailFull.MatchString(body[h.Start:h.End])) || h.Class == "redaction" && !h.Redact {
				return stop(s, "scanner_error", src.ID), nil
			}
			if h.Redact {
				if h.Start < last {
					return stop(s, "scanner_error", src.ID), nil
				}
				out.WriteString(body[last:h.Start])
				out.WriteString("[REDACTED EMAIL]")
				last = h.End
				hasRedaction = true
			} else if h.Class == "unsupported_content" || h.Class == "scanner_error" {
				hasRefusal = true
			} else {
				hasQuarantine = true
			}
			// Bounded, location-only provenance. Redaction findings are emitted only
			// if the entire snapshot is safe and all replacements were performed.
			s.Findings = append(s.Findings, finding(h.Class, src.ID, h.Start, h.End))
		}
		out.WriteString(body[last:])
		safe = append(safe, SanitizedSource{ID: src.ID, Text: out.String()})
	}
	if ctx.Err() != nil {
		return stop(s, "scanner_error", first), nil
	}
	if hasRefusal {
		s.Outcome = "refuse"
		safe = nil
	} else if hasQuarantine {
		s.Outcome = "quarantine"
		safe = nil
	} else if hasRedaction {
		s.Outcome = "pass_with_redactions"
	} else {
		s.Outcome = "pass"
	}
	result := Result{Safety: s, Sources: safe}
	if err := s.Validate(); err != nil {
		return stop(contracts.SafetyResult{SchemaVersion: contracts.SchemaVersion, SnapshotHash: manifest.SnapshotHash, GateVersion: GateVersion}, "scanner_error", first), nil
	}
	return result, nil
}
func allowed(c string) bool {
	switch c {
	case "secret", "security_report", "prompt_injection", "exfiltration", "unsafe_path", "encoded_instruction", "unsupported_content", "scanner_error", "redaction":
		return true
	}
	return false
}
func invoke(ctx context.Context, d Detector, v View) (hits []Hit, err error) {
	defer func() {
		if recover() != nil {
			hits = nil
			err = errors.New("scanner panic")
		}
	}()
	return d.Detect(ctx, v)
}

var secret = regexp.MustCompile(`(?i)(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|(?:bearer|password|api[_-]?key|token)\s*[:= ]\s*[A-Za-z0-9_./+\-=]{24,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)`)
var security = regexp.MustCompile(`(?i)\b(?:CVE-[0-9]{4}-[0-9]{4,}|responsible disclosure|privately report (?:a )?vulnerability|security vulnerability|zero.day exploit|exploit steps)\b`)
var injection = regexp.MustCompile(`(?i)(?:ignore (?:all )?(?:previous|prior|above) instructions|override (?:your |the )?(?:system|developer|policy) (?:prompt|instructions)|(?:system|developer) prompt|\[INST\]|<\|(?:im_start|system)\|>|(?:call|invoke|run|execute) (?:the )?(?:shell|terminal|tool|command))`)
var exfil = regexp.MustCompile(`(?i)(?:send|upload|post|transmit|exfiltrate)\b.{0,90}\b(?:token|secret|credential|private key|env(?:ironment)? variables?)\b|\b(?:token|secret|credential|private key)\b.{0,90}\b(?:send|upload|post|transmit|exfiltrate)\b`)
var unsafePath = regexp.MustCompile(`(?i)(?:\.\.[/\\]|~[/\\]\.(?:ssh|aws|config)\b|(?:/etc/passwd|/etc/shadow|/proc/self/environ)\b|[A-Za-z]:\\(?:Users|Windows)\\|\.(?:env|ssh)(?:[/\\]|\b)|\\\\[A-Za-z0-9_.-]+\\)`)
var email = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
var emailFull = regexp.MustCompile(`(?i)^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$`)

// Twelve encoded characters cover short tool directives such as "run shell".
var b64 = regexp.MustCompile(`[A-Za-z0-9+/]{12,}={0,2}`)
var urlCandidate = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
var queryCredential = regexp.MustCompile(`(?i)(?:^|[_-])(?:auth|authorization|token|secret|password|passwd|session(?:[_-]?id)?|sid|jwt|api[_-]?key|access[_-]?key|key|client[_-]?secret)$`)
var exfilVariant = regexp.MustCompile(`(?i)(?:copy|dump|export|share|paste|forward|send|upload|post|transmit)\b.{0,100}\b(?:environment variables?|env vars?|secrets?|tokens?|credentials?|api keys?|private keys?)\b|(?:environment variables?|env vars?|secrets?|tokens?|credentials?|api keys?|private keys?)\b.{0,100}\b(?:copy|dump|export|share|paste|forward|send|upload|post|transmit)\b`)
var toolVariant = regexp.MustCompile(`(?i)(?:use|call|invoke|run|execute|open)\s+(?:the\s+)?(?:shell|terminal|browser|web[._]run|functions\.exec|bash|powershell|curl)\b`)
var nested = regexp.MustCompile(`(?i)<(?:script|iframe|object|embed)\b|<!--.{0,200}(?:ignore|instruction|system|tool)`)

// urlHits parses URL text only; it never resolves hosts, follows links, or
// retains a URL in a finding. Invalid/ambiguous URL syntax refuses rather than
// allowing a concealed destination through the gate.
func urlHits(body string) []Hit {
	var hits []Hit
	spans := urlCandidate.FindAllStringIndex(body, MaxHits+1)
	if len(spans) > MaxHits {
		return []Hit{{Class: "unsupported_content", Start: 0, End: len(body)}}
	}
	for _, span := range spans {
		end := span[1]
		for end > span[0] && strings.ContainsRune(".,;!?)", rune(body[end-1])) {
			end--
		}
		if end == span[0] {
			continue
		}
		u, err := url.Parse(body[span[0]:end])
		if err != nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
			hits = append(hits, Hit{Class: "unsupported_content", Start: span[0], End: end})
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		private := host == "localhost" || !strings.Contains(host, ".")
		if host == "" || strings.Contains(host, "..") {
			hits = append(hits, Hit{Class: "unsupported_content", Start: span[0], End: end})
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			private = ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast()
		} else {
			// Numeric-but-unparseable hosts may hide octal/abbreviated private IPs.
			if strings.IndexFunc(host, func(r rune) bool { return r != '.' && (r < '0' || r > '9') }) == -1 {
				hits = append(hits, Hit{Class: "unsupported_content", Start: span[0], End: end})
				continue
			}
			for _, label := range strings.Split(host, ".") {
				switch label {
				case "internal", "intranet", "private", "localhost", "local", "lan", "corp", "home", "homelab", "svc", "cluster":
					private = true
				}
				if strings.HasPrefix(label, "internal-") || strings.HasPrefix(label, "intranet-") || strings.HasPrefix(label, "private-") {
					private = true
				}
			}
		}
		if private {
			hits = append(hits, Hit{Class: "unsafe_path", Start: span[0], End: end})
		}
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			hits = append(hits, Hit{Class: "unsupported_content", Start: span[0], End: end})
			continue
		}
		for key := range values {
			if queryCredential.MatchString(key) {
				hits = append(hits, Hit{Class: "exfiltration", Start: span[0], End: end})
				break
			}
		}
	}
	return hits
}

// dangerous is used only on decoded text; its caller emits an opaque reference
// to the original encoded bytes, not offsets or content from the decoded copy.
func dangerous(body string) bool {
	return secret.MatchString(body) || security.MatchString(body) || injection.MatchString(body) || toolVariant.MatchString(body) || exfil.MatchString(body) || exfilVariant.MatchString(body) || unsafePath.MatchString(body) || nested.MatchString(body) || len(urlHits(body)) > 0
}

func builtin(body string, redact bool) []Hit {
	var hits []Hit
	add := func(class string, re *regexp.Regexp) {
		spans := re.FindAllStringIndex(body, MaxHits+1)
		if len(spans) > MaxHits {
			hits = append(hits, Hit{Class: "unsupported_content", Start: 0, End: len(body)})
			return
		}
		for _, p := range spans {
			hits = append(hits, Hit{Class: class, Start: p[0], End: p[1]})
		}
	}
	add("secret", secret)
	add("security_report", security)
	add("prompt_injection", injection)
	add("exfiltration", exfil)
	add("exfiltration", exfilVariant)
	add("prompt_injection", toolVariant)
	add("unsafe_path", unsafePath)
	hits = append(hits, urlHits(body)...)
	add("encoded_instruction", nested)
	decoded := html.UnescapeString(body)
	if decoded != body && dangerous(decoded) {
		hits = append(hits, Hit{Class: "encoded_instruction", Start: 0, End: len(body)})
	}
	if percent, err := url.PathUnescape(body); err == nil && percent != body && dangerous(percent) {
		hits = append(hits, Hit{Class: "encoded_instruction", Start: 0, End: len(body)})
	}
	encoded := b64.FindAllStringIndex(body, MaxHits+1)
	if len(encoded) > MaxHits {
		hits = append(hits, Hit{Class: "unsupported_content", Start: 0, End: len(body)})
		return hits
	}
	for _, p := range encoded {
		candidate := body[p[0]:p[1]]
		raw, err := base64.StdEncoding.DecodeString(candidate)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(candidate, "="))
		}
		if err == nil && utf8.Valid(raw) && dangerous(string(raw)) {
			hits = append(hits, Hit{Class: "encoded_instruction", Start: p[0], End: p[1]})
		}
	}
	if redact {
		spans := email.FindAllStringIndex(body, MaxHits+1)
		if len(spans) > MaxHits {
			hits = append(hits, Hit{Class: "unsupported_content", Start: 0, End: len(body)})
			return hits
		}
		for _, p := range spans {
			hits = append(hits, Hit{Class: "redaction", Start: p[0], End: p[1], Redact: true})
		}
	}
	return hits
}
