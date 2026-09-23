package store

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const blobComplete = ".complete"

func (s *Store) PutLayer(rd io.Reader) (Digest, error) {
	d, err := s.PutBlob(rd)
	if err != nil {
		return Digest{}, err
	}
	return d, nil
}

func (s *Store) PutBlob(rd io.Reader) (Digest, error) {
	h := sha256DigestWriter()
	dir := s.BlobsDir()

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return Digest{}, fmt.Errorf("store: create temp blob: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpName) }

	if _, err := io.Copy(io.MultiWriter(tmp, h), rd); err != nil {
		cleanup()
		return Digest{}, fmt.Errorf("store: write blob: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return Digest{}, fmt.Errorf("store: sync blob: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		cleanup()
		return Digest{}, fmt.Errorf("store: chmod blob: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return Digest{}, fmt.Errorf("store: close blob: %w", err)
	}

	d := NewDigest(DigestAlgoSHA256, h.Hex())
	final := s.BlobPath(d)
	if _, err := os.Stat(final); err == nil {
		os.Remove(tmpName)
		return d, nil
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		os.Remove(tmpName)
		return Digest{}, fmt.Errorf("store: mkdir blob dir: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		return Digest{}, fmt.Errorf("store: commit blob %s: %w", d, err)
	}
	_ = syncDir(filepath.Dir(final))
	return d, nil
}

func (s *Store) PutBlobBytes(data []byte) (Digest, error) {
	return s.PutBlob(bytes.NewReader(data))
}

func (s *Store) OpenBlob(d Digest) (io.ReadCloser, error) {
	if !d.Valid() {
		return nil, fmt.Errorf("store: invalid blob digest %q", d)
	}
	f, err := os.Open(s.BlobPath(d))
	if err != nil {
		return nil, fmt.Errorf("store: open blob %s: %w", d, err)
	}
	return f, nil
}

func (s *Store) EnsureLayer(d Digest) (string, error) {
	if err := s.VerifyBlob(d); err != nil {
		return "", err
	}
	dir := s.LayerDir(d)
	if _, err := os.Stat(filepath.Join(dir, blobComplete)); err == nil {
		return dir, nil
	}
	if err := s.extractTo(d, dir); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, blobComplete), []byte("ok\n"), 0o644); err != nil {
		return "", fmt.Errorf("store: mark layer complete: %w", err)
	}
	return dir, nil
}

func (s *Store) RemoveBlob(d Digest) error {
	if !d.Valid() {
		return nil
	}
	_ = os.Remove(s.BlobPath(d))
	_ = os.RemoveAll(s.LayerDir(d))
	return nil
}

func (s *Store) LayerDigests() ([]Digest, error) {
	var out []Digest
	root := s.LayersDir()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || info.Name() != blobComplete {
			return nil
		}
		dir := filepath.Dir(path)
		hexV := filepath.Base(dir)
		d := NewDigest(DigestAlgoSHA256, hexV)
		if d.Valid() {
			out = append(out, d)
		}
		return nil
	})
	return out, err
}
