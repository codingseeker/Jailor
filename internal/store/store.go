package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const SubDir = "store"

type Store struct {
	Root string
}

func Open(root string) (*Store, error) {
	if root == "" {
		return nil, fmt.Errorf("store: no root specified")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", root, err)
	}
	s := &Store{Root: root}
	for _, dir := range []string{
		s.BlobsDir(),
		s.LayersDir(),
		s.ContainersDir(),
		s.MetaDir(),
		s.VolumesDir(),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: create %s: %w", dir, err)
		}
	}
	s.cleanTemps()
	return s, nil
}

func (s *Store) BlobsDir() string { return filepath.Join(s.Root, "blobs") }

func (s *Store) LayersDir() string { return filepath.Join(s.Root, "layers") }

func (s *Store) ContainersDir() string { return filepath.Join(s.Root, "containers") }

func (s *Store) MetaDir() string { return filepath.Join(s.Root, "meta") }

func (s *Store) BlobPath(d Digest) string {
	return filepath.Join(s.BlobsDir(), d.Algo, d.Hex[:2], d.Hex)
}

func (s *Store) LayerDir(d Digest) string {
	return filepath.Join(s.LayersDir(), d.Algo, d.Hex[:2], d.Hex)
}

func (s *Store) ContainerDir(id string) string {
	return filepath.Join(s.ContainersDir(), id)
}

func (s *Store) ContainerRootfs(id string) string {
	return filepath.Join(s.ContainerDir(id), "rootfs")
}

func (s *Store) HasBlob(d Digest) bool {
	if !d.Valid() {
		return false
	}
	info, err := os.Stat(s.BlobPath(d))
	return err == nil && info.Mode().IsRegular()
}

func AtomicWrite(dst string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("store: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("store: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("store: sync temp: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("store: chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close temp: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("store: rename temp into place: %w", err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Store) cleanTemps() {
	_ = filepath.Walk(s.Root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		name := info.Name()
		if strings.HasPrefix(name, ".tmp-") {
			_ = os.Remove(path)
		}
		return nil
	})
}
