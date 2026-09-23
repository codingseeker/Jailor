package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
)

const DigestAlgoSHA256 = "sha256"

type Digest struct {
	Algo string
	Hex  string
}

func NewDigest(algo, hexValue string) Digest {
	return Digest{Algo: algo, Hex: hexValue}
}

func ParseDigest(s string) (Digest, error) {
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return Digest{}, fmt.Errorf("store: invalid digest %q (want algo:hex)", s)
	}
	d := Digest{Algo: s[:i], Hex: s[i+1:]}
	if !d.Valid() {
		return Digest{}, fmt.Errorf("store: invalid digest %q", s)
	}
	return d, nil
}

func MustDigest(s string) Digest {
	d, err := ParseDigest(s)
	if err != nil {
		panic(err)
	}
	return d
}

func (d Digest) String() string { return d.Algo + ":" + d.Hex }

func (d Digest) Valid() bool {
	if d.Algo != DigestAlgoSHA256 {
		return false
	}
	if len(d.Hex) != sha256.Size*2 {
		return false
	}
	for _, c := range d.Hex {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

type sha256Sum struct {
	h hash.Hash
}

func sha256DigestWriter() *sha256Sum { return &sha256Sum{h: sha256.New()} }

func (s *sha256Sum) Write(p []byte) (int, error) { return s.h.Write(p) }

func (s *sha256Sum) Hex() string { return hex.EncodeToString(s.h.Sum(nil)) }

func DigestOf(r io.Reader) (Digest, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return Digest{}, err
	}
	return NewDigest(DigestAlgoSHA256, hex.EncodeToString(h.Sum(nil))), nil
}

func DigestOfFile(path string) (Digest, error) {
	f, err := os.Open(path)
	if err != nil {
		return Digest{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return Digest{}, err
	}
	return NewDigest(DigestAlgoSHA256, hex.EncodeToString(h.Sum(nil))), nil
}

func (s *Store) VerifyBlob(d Digest) error {
	if !d.Valid() {
		return fmt.Errorf("store: refusal to verify invalid digest %q", d)
	}
	path := s.BlobPath(d)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("store: open blob %s: %w", d, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("store: hash blob %s: %w", d, err)
	}
	got := NewDigest(DigestAlgoSHA256, hex.EncodeToString(h.Sum(nil)))
	if got.String() != d.String() {
		return fmt.Errorf("store: blob %s is corrupted (recomputed %s)", d, got)
	}
	return nil
}
