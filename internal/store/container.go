package store

import (
	"fmt"
	"os"
	"path/filepath"
)

type Mount struct {
	Rootfs string

	Driver string

	ReadOnly bool
}

const fstypeMarker = "fstype"

func (s *Store) MountContainerFS(id string, layers []Digest, readOnly bool) (*Mount, error) {
	if id == "" {
		return nil, fmt.Errorf("store: no container id given")
	}
	dir := s.ContainerDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create container dir: %w", err)
	}
	rootfs := filepath.Join(dir, "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return nil, fmt.Errorf("store: create container rootfs: %w", err)
	}

	if err := s.unmount(rootfs); err != nil {
		return nil, fmt.Errorf("store: clear stale container mount: %w", err)
	}

	lower, err := s.resolveLowerLayers(layers)
	if err != nil {
		return nil, err
	}

	var m *Mount
	if len(lower) > 0 && supportsOverlay() {
		if om, err := s.tryMountOverlay(readOnly, lower, rootfs); err == nil {
			m = om
		}
	}

	if m == nil {
		if err := copyLayerStack(lower, rootfs); err != nil {
			return nil, fmt.Errorf("store: assemble container rootfs: %w", err)
		}
		m = &Mount{Rootfs: rootfs, Driver: "copy", ReadOnly: readOnly}
	}
	if err := recordFS(s.ContainerDir(id), m); err != nil {
		return nil, err
	}
	return m, nil
}

func (s *Store) tryMountOverlay(readOnly bool, lower []string, rootfsPath string) (*Mount, error) {
	if readOnly {
		if err := mountOverlayRO(lower, rootfsPath); err != nil {
			return nil, err
		}
		return &Mount{Rootfs: rootfsPath, Driver: "overlay", ReadOnly: true}, nil
	}
	dir := filepath.Dir(rootfsPath)
	upper := filepath.Join(dir, "upper")
	work := filepath.Join(dir, "work")
	for _, d := range []string{upper, work} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	if err := mountOverlay(lower, upper, work, rootfsPath); err != nil {
		return nil, err
	}
	return &Mount{Rootfs: rootfsPath, Driver: "overlay", ReadOnly: false}, nil
}

func recordFS(dir string, m *Mount) error {
	if m == nil || dir == "" {
		return nil
	}
	return os.WriteFile(filepath.Join(dir, fstypeMarker), []byte(m.Driver+"\n"), 0o600)
}

func (s *Store) resolveLowerLayers(layers []Digest) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, d := range layers {
		if !d.Valid() {
			return nil, fmt.Errorf("store: invalid layer digest %q", d)
		}
		dir, err := s.EnsureLayer(d)
		if err != nil {
			return nil, err
		}
		if seen[dir] {
			continue
		}
		seen[dir] = true
		out = append(out, dir)
	}
	return out, nil
}

func (s *Store) UnmountContainerFS(id string) error {
	if id == "" {
		return nil
	}
	return s.unmount(filepath.Join(s.ContainerDir(id), "rootfs"))
}

func (s *Store) DeleteContainerFS(id string) error {
	if id == "" {
		return nil
	}
	dir := s.ContainerDir(id)
	_ = s.unmount(filepath.Join(dir, "rootfs"))
	return os.RemoveAll(dir)
}

func (s *Store) VolumesDir() string { return filepath.Join(s.Root, "volumes") }
