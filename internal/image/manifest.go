package image

import (
	"encoding/json"
	"fmt"
	"strings"

	"jailor/internal/store"
)

const (
	MediaTypeOCIManifest        = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex           = "application/vnd.oci.image.index.v1+json"
	MediaTypeOCIConfig          = "application/vnd.oci.image.config.v1+json"
	MediaTypeOCILayer           = "application/vnd.oci.image.layer.v1.tar"
	MediaTypeOCILayerGzip       = "application/vnd.oci.image.layer.v1.tar+gzip"
	MediaTypeOCILayerZstd       = "application/vnd.oci.image.layer.v1.tar+zstd"
	MediaTypeDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeDockerConfig       = "application/vnd.docker.container.image.v1+json"
	MediaTypeDockerLayerGzip    = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

func IsLayerMediaType(mt string) bool {
	switch mt {
	case MediaTypeOCILayerGzip, MediaTypeDockerLayerGzip:
		return true
	}
	return false
}
func IsManifestMediaType(mt string) bool {
	switch mt {
	case MediaTypeOCIManifest, MediaTypeDockerManifest:
		return true
	}
	return false
}
func IsConfigMediaType(mt string) bool {
	switch mt {
	case MediaTypeOCIConfig, MediaTypeDockerConfig:
		return true
	}
	return false
}

type Descriptor struct {
	MediaType   string            `json:"mediaType,omitempty"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    *Platform         `json:"platform,omitempty"`
}

type Platform struct {
	Architecture string `json:"architecture,omitempty"`
	OS           string `json:"os,omitempty"`
	Variant      string `json:"variant,omitempty"`
}

type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}
type Index struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Manifests     []Descriptor      `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type RuntimeConfig struct {
	Env        []string `json:"Env,omitempty"`
	Entrypoint []string `json:"Entrypoint,omitempty"`
	Cmd        []string `json:"Cmd,omitempty"`
	WorkingDir string   `json:"WorkingDir,omitempty"`
	User       string   `json:"User,omitempty"`
	StopSignal string   `json:"StopSignal,omitempty"`
}
type ImageConfig struct {
	Created      string              `json:"created,omitempty"`
	Author       string              `json:"author,omitempty"`
	Architecture string              `json:"architecture"`
	OS           string              `json:"os"`
	Variant      string              `json:"variant,omitempty"`
	Config       RuntimeConfig       `json:"config,omitempty"`
	RootFS       ImageRootFS         `json:"rootfs"`
	History      []ImageHistoryEntry `json:"history,omitempty"`
}

type ImageRootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

type ImageHistoryEntry struct {
	Created    string `json:"created,omitempty"`
	CreatedBy  string `json:"created_by,omitempty"`
	Comment    string `json:"comment,omitempty"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
}

func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("image: parse manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func ParseIndex(data []byte) (*Index, error) {
	var ix Index
	if err := json.Unmarshal(data, &ix); err != nil {
		return nil, fmt.Errorf("image: parse index: %w", err)
	}
	if ix.SchemaVersion != 2 {
		return nil, fmt.Errorf("image: index has unsupported schemaVersion %d", ix.SchemaVersion)
	}
	if ix.MediaType != "" && !IsIndexMediaType(ix.MediaType) {
		return nil, fmt.Errorf("image: unsupported index media type %q", ix.MediaType)
	}
	for _, d := range ix.Manifests {
		if err := validateDescriptor(d, false); err != nil {
			return nil, fmt.Errorf("image: index: %w", err)
		}
	}
	return &ix, nil
}

func ParseImageConfig(data []byte) (*ImageConfig, error) {
	var c ImageConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("image: parse config: %w", err)
	}
	if c.RootFS.Type != "layers" {
		return nil, fmt.Errorf("image: unsupported rootfs.type %q (want layers)", c.RootFS.Type)
	}
	for _, d := range c.RootFS.DiffIDs {
		if _, err := store.ParseDigest(d); err != nil {
			return nil, fmt.Errorf("image: config rootfs.diff_ids: %w", err)
		}
	}
	return &c, nil
}
func (m *Manifest) Validate() error {
	if m.SchemaVersion != 2 {
		return fmt.Errorf("image: manifest has unsupported schemaVersion %d", m.SchemaVersion)
	}
	if m.MediaType != "" && !IsManifestMediaType(m.MediaType) {
		return fmt.Errorf("image: unsupported manifest media type %q", m.MediaType)
	}
	if m.MediaType == "" {

		m.MediaType = MediaTypeDockerManifest
	}
	if err := validateDescriptor(m.Config, true); err != nil {
		return fmt.Errorf("image: manifest config: %w", err)
	}
	if !IsConfigMediaType(m.Config.MediaType) {
		return fmt.Errorf("image: manifest config has unsupported media type %q", m.Config.MediaType)
	}
	if len(m.Layers) == 0 {
		return fmt.Errorf("image: manifest has no layers")
	}
	for i, d := range m.Layers {
		if err := validateDescriptor(d, true); err != nil {
			return fmt.Errorf("image: manifest layer %d: %w", i, err)
		}
		if !IsLayerMediaType(d.MediaType) {
			return fmt.Errorf("image: manifest layer %d has unsupported media type %q", i, d.MediaType)
		}
	}
	return nil
}
func validateDescriptor(d Descriptor, requireMedia bool) error {
	if _, err := store.ParseDigest(d.Digest); err != nil {
		return fmt.Errorf("descriptor digest: %w", err)
	}
	if d.Size < 0 {
		return fmt.Errorf("descriptor %s has negative size", d.Digest)
	}
	if requireMedia && d.MediaType == "" {
		return fmt.Errorf("descriptor %s has no media type", d.Digest)
	}
	return nil
}

func digestOf(d Descriptor) store.Digest {
	dig, _ := store.ParseDigest(d.Digest)
	return dig
}
func IsIndexMediaType(mt string) bool {
	return mt == MediaTypeOCIIndex || mt == MediaTypeDockerManifestList
}
func NormalizeMediaType(mt string) string {
	if i := strings.IndexByte(mt, ','); i >= 0 {
		return mt[:i]
	}
	return mt
}
