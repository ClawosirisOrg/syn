// SPDX-License-Identifier: AGPL-3.0-or-later

// Package recordstore persists validated metadata-only canonical records in an
// existing, operator-owned directory. It never stores source or runner bodies.
package recordstore

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ClawOsirisOrg/syn/internal/contracts"
)

const maxRecordBytes = 1 << 20

var (
	ErrConflict = errors.New("record identity already contains different bytes")
	ErrCorrupt  = errors.New("invalid stored canonical record")
)

// Store owns a directory handle, not its lifecycle. Close after use.
type Store struct{ root *os.Root }

// New requires an existing, privately operator-owned root; it never creates it.
func New(path string) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("record root must be a clean absolute path")
	}
	current := string(os.PathSeparator)
	for _, component := range strings.Split(strings.TrimPrefix(path, current), current) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("inspect record root: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("record root path contains a non-directory or symlink")
		}
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open record root: %w", err)
	}
	info, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("inspect opened root: %w", err)
	}
	expected, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, expected) {
		root.Close()
		return nil, errors.New("record root changed during open")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		root.Close()
		return nil, errors.New("record root must be privately operator-owned")
	}
	return &Store{root: root}, nil
}

func (s *Store) Close() error { return s.root.Close() }

func recordName(id contracts.Hash) (string, error) {
	v := string(id)
	if len(v) != 64 {
		return "", errors.New("invalid record ID")
	}
	for _, c := range v {
		if c < '0' || c > '9' && (c < 'a' || c > 'f') {
			return "", errors.New("invalid record ID")
		}
	}
	return v + ".json", nil
}

// Put never replaces a record. A retry succeeds only for valid, byte-identical
// data. Errors after Link can leave the record installed; retry to confirm.
func (s *Store) Put(record contracts.CanonicalRecord) error {
	if err := record.Validate(); err != nil {
		return fmt.Errorf("invalid canonical record: %w", err)
	}
	name, err := recordName(record.RecordID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode canonical record: %w", err)
	}
	if len(data) == 0 || len(data) > maxRecordBytes {
		return errors.New("canonical record exceeds size limit")
	}
	if _, err := contracts.Decode[contracts.CanonicalRecord](data); err != nil {
		return fmt.Errorf("invalid canonical encoding: %w", err)
	}
	temp, err := randomName()
	if err != nil {
		return err
	}
	f, err := s.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create temporary record: %w", err)
	}
	defer s.root.Remove(temp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write temporary record: %w", err)
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync temporary record: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close temporary record: %w", err)
	}
	if err = s.root.Link(temp, name); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("install canonical record: %w", err)
		}
		existing, readErr := s.read(name, record.RecordID)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, data) {
			return ErrConflict
		}
	}
	// Sync both the installed link and removal of the temporary name. A retry
	// may race the first writer before its directory Sync.
	if err := s.root.Remove(temp); err != nil {
		return fmt.Errorf("remove temporary record: %w", err)
	}
	return s.syncDirectory()
}

// Get rejects malformed, noncanonical, oversized and mismatched stored records.
func (s *Store) Get(id contracts.Hash) (contracts.CanonicalRecord, error) {
	var zero contracts.CanonicalRecord
	name, err := recordName(id)
	if err != nil {
		return zero, err
	}
	data, err := s.read(name, id)
	if err != nil {
		return zero, err
	}
	return contracts.Decode[contracts.CanonicalRecord](data)
}

func (s *Store) read(name string, id contracts.Hash) ([]byte, error) {
	info, err := s.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxRecordBytes || info.Mode().Perm()&0077 != 0 {
		return nil, ErrCorrupt
	}
	f, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return nil, ErrCorrupt
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxRecordBytes || int64(len(data)) != info.Size() {
		return nil, ErrCorrupt
	}
	record, err := contracts.Decode[contracts.CanonicalRecord](data)
	if err != nil || record.RecordID != id {
		return nil, ErrCorrupt
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, ErrCorrupt
	}
	return data, nil
}

func randomName() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate temporary record name: %w", err)
	}
	return ".record-" + hex.EncodeToString(nonce[:]) + ".tmp", nil
}

func (s *Store) syncDirectory() error {
	dir, err := s.root.Open(".")
	if err != nil {
		return fmt.Errorf("open record directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync record directory: %w", err)
	}
	return nil
}
