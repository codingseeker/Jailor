package image

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"jailor/internal/store"
)

type containerMeta struct {
	Image    string         `json:"image,omitempty"`
	Manifest store.Digest   `json:"manifest"`
	Layers   []store.Digest `json:"layers"`
}

const containerMetaFile = "layers.json"

func validContainerID(id string) bool {
	if id == "" || id == "." || id == ".." {
		return false
	}
	return !strings.ContainsAny(id, "/\\") &&
		!strings.Contains(id, "..")
}
func (is *ImageStore) Assemble(containerID, ref string, readOnly bool) (*store.Mount, *Image, error) {
	if !validContainerID(containerID) {
		return nil, nil, fmt.Errorf("image: invalid container id %q", containerID)
	}
	img, err := is.Get(ref)
	if err != nil {
		return nil, nil, err
	}
	layers := make([]store.Digest, len(img.Layers))
	copy(layers, img.Layers)

	m, err := is.st.MountContainerFS(containerID, layers, readOnly)
	if err != nil {
		return nil, nil, fmt.Errorf("image: assemble container %s: %w", containerID, err)
	}

	meta := containerMeta{Image: img.Name, Manifest: img.Digest, Layers: layers}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		_ = is.st.UnmountContainerFS(containerID)
		return nil, nil, err
	}
	dir := is.st.ContainerDir(containerID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		_ = is.st.UnmountContainerFS(containerID)
		return nil, nil, err
	}
	if err := store.AtomicWrite(filepath.Join(dir, containerMetaFile), data, 0o600); err != nil {
		_ = is.st.UnmountContainerFS(containerID)
		return nil, nil, err
	}
	return m, img, nil
}
func (is *ImageStore) Disassemble(containerID string) error {
	if !validContainerID(containerID) {
		return fmt.Errorf("image: invalid container id %q", containerID)
	}
	return is.st.UnmountContainerFS(containerID)
}

func (is *ImageStore) Delete(containerID string) error {
	if !validContainerID(containerID) {
		return fmt.Errorf("image: invalid container id %q", containerID)
	}
	return is.st.DeleteContainerFS(containerID)
}

func (is *ImageStore) readContainerMeta(id string) (*containerMeta, error) {
	data, err := os.ReadFile(filepath.Join(is.st.ContainerDir(id), containerMetaFile))
	if err != nil {
		return nil, err
	}
	var meta containerMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func (is *ImageStore) walkContainers(fn func(id string, meta containerMeta) error) error {
	entries, err := os.ReadDir(is.st.ContainersDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		meta, err := is.readContainerMeta(e.Name())
		if err != nil {
			continue
		}
		if err := fn(e.Name(), *meta); err != nil {
			return err
		}
	}
	return nil
}
func (is *ImageStore) containerUsesManifest(d store.Digest) bool {
	used := false
	_ = is.walkContainers(func(_ string, meta containerMeta) error {
		if meta.Manifest.String() == d.String() {
			used = true
		}
		return nil
	})
	return used
}

func (is *ImageStore) containerUsesLayer(d store.Digest) bool {
	used := false
	_ = is.walkContainers(func(_ string, meta containerMeta) error {
		for _, l := range meta.Layers {
			if l.String() == d.String() {
				used = true
				return nil
			}
		}
		return nil
	})
	return used
}
func (is *ImageStore) ContainerRootfs(id string) string {
	return is.st.ContainerRootfs(id)
}
