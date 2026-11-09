// SPDX-License-Identifier: AGPL-3.0-or-later

// Package source builds bounded snapshots from explicitly selected, already
// acquired text. It does not fetch links, read paths, or execute content.
package source

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ClawOsirisOrg/syn/internal/acquire"
	"github.com/ClawOsirisOrg/syn/internal/contracts"
)

// Limits are ceilings; zero selects the hard ceiling, never unlimited.
type Limits struct{ MaxSources, MaxSourceBytes, MaxTotalBytes int }

const (
	hardSources     = 128
	hardSourceBytes = 1 << 20
	hardTotalBytes  = 4 << 20
)

// Selection lists every required source independently of acquired data.
// Locators: issue:N, pull:N, diff:pull:N, comment:{issue|pull}:N:ID,
// review:pull:N:ID, review_comment:pull:N:ID, default:PATH (pinned),
// or pr:N:PATH (untrusted branch). N must equal the target number.
// The caller must authenticate the selection and any default-branch pin.
type Selection struct{ ID, Type, Locator, Trust, PinnedCommit, DefaultBranch string }

// Acquired comes from an authoritative reader, not from URL/path expansion.
// That reader must verify pagination and freshness. Pinned guidance also
// requires a verified acquire.Acquire witness: an assertion flag is not proof.
type Acquired struct {
	ID               string
	Body             []byte
	AcquiredAt       time.Time
	Complete, Stable bool
	Guidance         *acquire.Guidance
}

// Snapshot retains normalized bodies privately; Manifest returns a copy.
type Snapshot struct {
	manifest contracts.SourceManifest
	bodies   map[string]string
	branches map[string]string
}

func (s Snapshot) Manifest() contracts.SourceManifest {
	m := s.manifest
	m.Sources = append([]contracts.SourceEntry(nil), m.Sources...)
	return m
}
func (s Snapshot) Text(id string) (string, bool) { v, ok := s.bodies[id]; return v, ok }

func bounded(l Limits) (Limits, error) {
	if l.MaxSources < 0 || l.MaxSources > hardSources || l.MaxSourceBytes < 0 || l.MaxSourceBytes > hardSourceBytes || l.MaxTotalBytes < 0 || l.MaxTotalBytes > hardTotalBytes {
		return l, errors.New("invalid source limits")
	}
	if l.MaxSources == 0 {
		l.MaxSources = hardSources
	}
	if l.MaxSourceBytes == 0 {
		l.MaxSourceBytes = hardSourceBytes
	}
	if l.MaxTotalBytes == 0 {
		l.MaxTotalBytes = hardTotalBytes
	}
	return l, nil
}

// Build refuses missing, extra, duplicate, incomplete, changed, unsupported or
// oversized inputs; it never returns a partial manifest on failure.
func Build(target contracts.Target, selected []Selection, acquired []Acquired, limits Limits) (Snapshot, error) {
	var empty Snapshot
	l, err := bounded(limits)
	if err != nil {
		return empty, err
	}
	if len(selected) == 0 || len(selected) > l.MaxSources || len(acquired) != len(selected) {
		return empty, errors.New("incomplete or oversized source set")
	}
	ordered := append([]Selection(nil), selected...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	items := make(map[string]Acquired, len(acquired))
	for _, item := range acquired {
		if item.ID == "" {
			return empty, errors.New("missing acquired identity")
		}
		if _, ok := items[item.ID]; ok {
			return empty, errors.New("duplicate acquired identity")
		}
		items[item.ID] = item
	}
	m := contracts.SourceManifest{SchemaVersion: contracts.SchemaVersion, Target: target, Sources: make([]contracts.SourceEntry, 0, len(ordered))}
	bodies := make(map[string]string, len(ordered))
	locators := make(map[string]bool, len(ordered))
	branches := make(map[string]string)
	total := 0
	for i, choice := range ordered {
		if i > 0 && ordered[i-1].ID == choice.ID {
			return empty, errors.New("duplicate selected identity")
		}
		if err := validateSelection(target, choice); err != nil {
			return empty, err
		}
		if locators[choice.Locator] {
			return empty, errors.New("duplicate source locator")
		}
		locators[choice.Locator] = true
		item, ok := items[choice.ID]
		if !ok || !item.Complete || !item.Stable || item.AcquiredAt.IsZero() {
			return empty, errors.New("missing, incomplete or unstable source")
		}
		if choice.Trust == "pinned_guidance" {
			file := strings.TrimPrefix(choice.Locator, "default:")
			branches[choice.ID] = choice.DefaultBranch
			if choice.DefaultBranch == "" || item.Guidance == nil || item.Guidance.Verify(target.Repository, choice.DefaultBranch, choice.PinnedCommit, file) != nil || !bytes.Equal(item.Body, item.Guidance.Body) {
				return empty, errors.New("guidance provenance mismatch")
			}
		} else if item.Guidance != nil {
			return empty, errors.New("untrusted source supplied guidance witness")
		}
		if len(item.Body) > l.MaxSourceBytes || len(item.Body) > l.MaxTotalBytes-total {
			return empty, errors.New("source size limit exceeded")
		}
		normal, err := Normalize(item.Body)
		if err != nil {
			return empty, err
		}
		if choice.Type == "diff" {
			if err := validateDiffPaths(normal); err != nil {
				return empty, err
			}
		}
		total += len(item.Body)
		entry := contracts.SourceEntry{ID: choice.ID, Type: choice.Type, Locator: choice.Locator, Trust: choice.Trust, PinnedCommit: choice.PinnedCommit, Bytes: int64(len(normal)), ContentHash: digest([]byte(normal)), AcquiredAt: item.AcquiredAt.UTC().Format(time.RFC3339Nano)}
		m.Sources = append(m.Sources, entry)
		bodies[choice.ID] = normal
	}
	if len(items) != len(ordered) {
		return empty, errors.New("unexpected acquired source")
	}
	h, err := snapshotHash(m, branches)
	if err != nil {
		return empty, err
	}
	m.SnapshotHash = h
	if err := m.Validate(); err != nil {
		return empty, err
	}
	return Snapshot{manifest: m, bodies: bodies, branches: branches}, nil
}

func validateSelection(target contracts.Target, s Selection) error {
	if s.ID == "" || s.Locator == "" || strings.ContainsAny(s.Locator, "?#%\\") || strings.Contains(s.Locator, "..") {
		return errors.New("unsafe source locator")
	}
	if s.Type == "guidance" {
		switch s.Trust {
		case "pinned_guidance":
			if s.DefaultBranch == "" || !strings.HasPrefix(s.Locator, "default:") || safePath(strings.TrimPrefix(s.Locator, "default:")) != nil {
				return errors.New("invalid pinned guidance locator")
			}
		case "untrusted":
			// PR branch files are always data, even when named AGENTS.md or CODEOWNERS.
			if target.Kind != "pull_request" || !strings.HasPrefix(s.Locator, "pr:") {
				return errors.New("invalid PR guidance target")
			}
			rest := strings.TrimPrefix(s.Locator, "pr:")
			number, file, ok := strings.Cut(rest, ":")
			n, validNumber := canonicalDecimal(number)
			if !ok || !validNumber || n != target.Number || safePath(file) != nil {
				return errors.New("invalid PR guidance locator")
			}
		default:
			return errors.New("invalid guidance trust")
		}
	} else {
		// An explicit, canonical grammar binds every conversation source to
		// the selected item. A comment/review ID alone cannot prove parentage.
		parts := strings.Split(s.Locator, ":")
		itemKind := "issue"
		if target.Kind == "pull_request" {
			itemKind = "pull"
		}
		var objectID int64
		var valid bool
		switch s.Type {
		case "issue":
			valid = len(parts) == 2 && parts[0] == "issue" && target.Kind == "issue"
		case "pull_request":
			valid = len(parts) == 2 && parts[0] == "pull" && target.Kind == "pull_request"
		case "diff":
			valid = len(parts) == 3 && parts[0] == "diff" && parts[1] == "pull" && target.Kind == "pull_request"
		case "comment":
			valid = len(parts) == 4 && parts[0] == "comment" && parts[1] == itemKind
		case "review", "review_comment":
			valid = len(parts) == 4 && parts[0] == s.Type && parts[1] == "pull" && target.Kind == "pull_request"
		}
		if !valid {
			return errors.New("invalid source locator type or target")
		}
		index := len(parts) - 1
		if len(parts) == 4 {
			index = 2
		}
		number, ok := canonicalDecimal(parts[index])
		if !ok || number != target.Number {
			return errors.New("source locator target mismatch")
		}
		if len(parts) == 4 {
			objectID, ok = canonicalDecimal(parts[3])
			if !ok {
				return errors.New("invalid source object identity")
			}
		}
		// IDs are opaque by default, but typed IDs cannot disagree with the
		// locator's own object/target identity.
		typedID := map[string]string{"issue": "issue", "pull_request": "pull", "diff": "diff", "comment": "comment", "review": "review", "review_comment": "review_comment"}[s.Type]
		if strings.HasPrefix(s.ID, typedID+":") {
			expected := number
			if len(parts) == 4 {
				expected = objectID
			}
			if s.ID != s.Locator && s.ID != typedID+":"+strconv.FormatInt(expected, 10) {
				return errors.New("source id/locator mismatch")
			}
		}
	}
	if s.Trust != "untrusted" && s.Trust != "pinned_guidance" || s.Trust == "pinned_guidance" && s.Type != "guidance" || s.Trust == "untrusted" && (s.PinnedCommit != "" || s.DefaultBranch != "") {
		return errors.New("invalid source trust partition")
	}
	return nil
}

// canonicalDecimal disallows signs, leading zeroes, overflow and non-digits.
func canonicalDecimal(raw string) (int64, bool) {
	n, err := strconv.ParseInt(raw, 10, 64)
	return n, err == nil && n > 0 && strconv.FormatInt(n, 10) == raw
}

func safePath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || path.Clean(p) != p || p == "." || strings.ContainsAny(p, "\\:%") || strings.ContainsRune(p, 0) {
		return errors.New("unsafe source path")
	}
	for _, r := range p {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return errors.New("unsafe source path")
		}
	}
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." || part == "" {
			return errors.New("unsafe source path")
		}
	}
	return nil
}

// Only a conservative subset of unified Git text patches is admitted. Unknown
// headers or lines (including binary and combined patches) fail closed.
var unifiedHunk = regexp.MustCompile("^@@ -[0-9]+(,[0-9]+)? \\+[0-9]+(,[0-9]+)? @@(?: .*)?$")
var diffIndex = regexp.MustCompile("^[0-9a-f]{4,64}\\.\\.[0-9a-f]{4,64}(?: [0-7]{6})?$")
var diffMode = regexp.MustCompile("^[0-7]{6}$")

func validateDiffPaths(body string) error {
	var header, oldPath, newPath, changed, inHunk bool
	var oldMode, newMode, newFile, deletedFile, renameFrom, renameTo, copyFrom, copyTo bool
	var fromName, toName string
	validSection := func() bool {
		return header && oldPath == newPath && oldMode == newMode && renameFrom == renameTo && copyFrom == copyTo && (changed || oldMode && newMode || renameFrom && renameTo || copyFrom && copyTo || (newFile || deletedFile) && oldPath && newPath)
	}
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if i == len(lines)-1 && line == "" {
			break
		} // terminal LF
		var names []string
		switch {
		case strings.HasPrefix(line, "diff --git "):
			if header && !validSection() {
				return errors.New("incomplete diff section")
			}
			header, oldPath, newPath, changed, inHunk = true, false, false, false, false
			oldMode, newMode, newFile, deletedFile, renameFrom, renameTo, copyFrom, copyTo = false, false, false, false, false, false, false, false
			fields := strings.Fields(strings.TrimPrefix(line, "diff --git "))
			if len(fields) != 2 || !strings.HasPrefix(fields[0], "a/") || !strings.HasPrefix(fields[1], "b/") {
				return errors.New("ambiguous diff path")
			}
			fromName, toName = fields[0][2:], fields[1][2:]
			names = []string{fromName, toName}
		case !header:
			return errors.New("diff missing supported header")
		case line == "GIT binary patch" || strings.HasPrefix(line, "Binary files ") || strings.HasPrefix(line, "diff --cc ") || strings.HasPrefix(line, "diff --combined ") || strings.HasPrefix(line, "@@@ "):
			return errors.New("unsupported binary or combined diff")
		case strings.HasPrefix(line, "@@ "):
			if !oldPath || !newPath || !unifiedHunk.MatchString(line) {
				return errors.New("ambiguous diff hunk")
			}
			changed, inHunk = true, true
		case inHunk:
			if line != "\\ No newline at end of file" && (line == "" || !strings.ContainsAny(line[:1], " +-")) {
				return errors.New("unsupported diff hunk content")
			}
		case strings.HasPrefix(line, "index "):
			if !diffIndex.MatchString(strings.TrimPrefix(line, "index ")) || strings.HasSuffix(line, " 160000") {
				return errors.New("ambiguous diff index")
			}
		case strings.HasPrefix(line, "old mode ") || strings.HasPrefix(line, "new mode ") || strings.HasPrefix(line, "new file mode ") || strings.HasPrefix(line, "deleted file mode "):
			_, mode, _ := strings.Cut(line, "mode ")
			if !diffMode.MatchString(mode) || mode == "160000" {
				return errors.New("ambiguous diff mode")
			}
			switch {
			case strings.HasPrefix(line, "old mode "):
				oldMode = true
			case strings.HasPrefix(line, "new mode "):
				newMode = true
			case strings.HasPrefix(line, "new file mode "):
				newFile = true
			case strings.HasPrefix(line, "deleted file mode "):
				deletedFile = true
			}
		case strings.HasPrefix(line, "similarity index ") || strings.HasPrefix(line, "dissimilarity index "):
			_, percentage, _ := strings.Cut(line, "index ")
			n, err := strconv.Atoi(strings.TrimSuffix(percentage, "%"))
			if err != nil || n < 0 || n > 100 || !strings.HasSuffix(percentage, "%") {
				return errors.New("ambiguous diff similarity")
			}
		case strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "+++ "):
			v := line[4:]
			if strings.HasPrefix(line, "--- ") {
				if oldPath || newPath {
					return errors.New("ambiguous old diff marker")
				}
				oldPath = true
			} else {
				if !oldPath || newPath {
					return errors.New("ambiguous new diff marker")
				}
				newPath = true
			}
			if v == "/dev/null" {
				continue
			}
			if strings.HasPrefix(line, "--- ") && v != "a/"+fromName || strings.HasPrefix(line, "+++ ") && v != "b/"+toName {
				return errors.New("diff header/path mismatch")
			}
			names = []string{v[2:]}
		case strings.HasPrefix(line, "rename from "):
			renameFrom = true
			names = []string{strings.TrimPrefix(line, "rename from ")}
		case strings.HasPrefix(line, "rename to "):
			renameTo = true
			names = []string{strings.TrimPrefix(line, "rename to ")}
		case strings.HasPrefix(line, "copy from "):
			copyFrom = true
			names = []string{strings.TrimPrefix(line, "copy from ")}
		case strings.HasPrefix(line, "copy to "):
			copyTo = true
			names = []string{strings.TrimPrefix(line, "copy to ")}
		default:
			return errors.New("unsupported diff content")
		}
		for _, name := range names {
			if err := safePath(name); err != nil {
				return err
			}
		}
	}
	if !validSection() {
		return errors.New("incomplete or unsupported diff")
	}
	return nil
}

func digest(data []byte) contracts.Hash {
	h := sha256.Sum256(data)
	return contracts.Hash(hex.EncodeToString(h[:]))
}

// Version two binds the approved guidance branch as well as each manifest
// entry; acquisition timestamps and witness internals are excluded.
func snapshotHash(m contracts.SourceManifest, branches map[string]string) (contracts.Hash, error) {
	type entry struct {
		ID            string
		Type          string
		Locator       string
		Trust         string
		PinnedCommit  string
		DefaultBranch string
		Bytes         int64
		ContentHash   contracts.Hash
	}
	v := struct {
		Version int
		Target  contracts.Target
		Sources []entry
	}{Version: m.SchemaVersion, Target: m.Target}
	for _, s := range m.Sources {
		v.Sources = append(v.Sources, entry{s.ID, s.Type, s.Locator, s.Trust, s.PinnedCommit, branches[s.ID], s.Bytes, s.ContentHash})
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return digest(append([]byte("syn-source-snapshot-v2:"), b...)), nil
}

// Verify checks the retained text and metadata before downstream use.
func (s Snapshot) Verify() error {
	if err := s.manifest.Validate(); err != nil {
		return err
	}
	if len(s.bodies) != len(s.manifest.Sources) {
		return errors.New("snapshot body count mismatch")
	}
	for _, e := range s.manifest.Sources {
		if e.Trust == "pinned_guidance" && s.branches[e.ID] == "" || e.Trust != "pinned_guidance" && s.branches[e.ID] != "" {
			return errors.New("snapshot guidance branch mismatch")
		}
		b, ok := s.bodies[e.ID]
		if !ok || int64(len(b)) != e.Bytes || digest([]byte(b)) != e.ContentHash {
			return errors.New("snapshot body mismatch")
		}
	}
	h, err := snapshotHash(s.manifest, s.branches)
	if err != nil {
		return err
	}
	if h != s.manifest.SnapshotHash {
		return errors.New("snapshot hash mismatch")
	}
	return nil
}

// Normalize admits strict UTF-8 with optional BOM and CRLF; ambiguous controls,
// combining marks, invisible formatting and binary/archive signatures are refused.
// This conservative subset does not claim full Unicode NFC normalization.
func Normalize(raw []byte) (string, error) {
	if len(raw) > hardSourceBytes {
		return "", errors.New("source size limit exceeded")
	}
	if bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		raw = raw[3:]
	}
	if looksBinaryOrArchive(raw) || !utf8.Valid(raw) {
		return "", errors.New("unsupported binary or encoding")
	}
	for _, r := range string(raw) {
		if r == '\n' || r == '\t' || r == '\r' {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.M, r) || r == utf8.RuneError || r&0xfffe == 0xfffe || r >= 0xfdd0 && r <= 0xfdef {
			return "", errors.New("ambiguous or unsupported unicode")
		}
	}
	for i, b := range raw {
		if b == '\r' && (i+1 == len(raw) || raw[i+1] != '\n') {
			return "", errors.New("ambiguous line ending")
		}
	}
	return strings.ReplaceAll(string(raw), "\r\n", "\n"), nil
}
func looksBinaryOrArchive(b []byte) bool {
	for _, magic := range [][]byte{{0x7f, 'E', 'L', 'F'}, {'P', 'K', 3, 4}, {'P', 'K', 5, 6}, {0x1f, 0x8b}, {0x89, 'P', 'N', 'G'}, {'%', 'P', 'D', 'F'}, {'R', 'a', 'r', '!'}, {'7', 'z', 0xbc, 0xaf}} {
		if bytes.HasPrefix(b, magic) {
			return true
		}
	}
	return len(b) >= 262 && bytes.Equal(b[257:262], []byte("ustar"))
}
