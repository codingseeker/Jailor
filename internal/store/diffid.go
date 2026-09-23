package store

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

func (s *Store) DiffID(d Digest) (Digest, error) {
	if !d.Valid() {
		return Digest{}, fmt.Errorf("store: invalid layer digest %q", d)
	}
	f, err := os.Open(s.BlobPath(d))
	if err != nil {
		return Digest{}, fmt.Errorf("store: open layer blob %s: %w", d, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return Digest{}, fmt.Errorf("store: layer %s is not a valid gzip stream: %w", d, err)
	}
	defer gz.Close()

	return DigestOf(gz)
}

func (s *Store) BlobSize(d Digest) (int64, error) {
	if !d.Valid() {
		return 0, fmt.Errorf("store: invalid blob digest %q", d)
	}
	info, err := os.Stat(s.BlobPath(d))
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func (s *Store) CopyBlobTo(d Digest, w io.Writer) error {
	if err := s.VerifyBlob(d); err != nil {
		return err
	}
	f, err := os.Open(s.BlobPath(d))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}
