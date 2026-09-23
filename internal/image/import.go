package image

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"jailor/internal/store"
)

const annotationRefName = "org.opencontainers.image.ref.name"

const ociLayoutVersion = "1.0.0"

type OciLayout struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

type ImportOptions struct {
	Tag string
}

func (is *ImageStore) ImportLayout(dir string, opts ImportOptions) (*Image, error) {
	if dir == "" {
		return nil, fmt.Errorf("image: no layout directory given")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	lay, err := os.ReadFile(filepath.Join(abs, "oci-layout"))
	if err != nil {
		return nil, fmt.Errorf("image: layout %s: %w", abs, err)
	}
	var l OciLayout
	if err := json.Unmarshal(lay, &l); err != nil {
		return nil, fmt.Errorf("image: parse oci-layout: %w", err)
	}
	if l.ImageLayoutVersion != ociLayoutVersion {
		return nil, fmt.Errorf("image: unsupported oci-layout version %q", l.ImageLayoutVersion)
	}

	idxData, err := os.ReadFile(filepath.Join(abs, "index.json"))
	if err != nil {
		return nil, fmt.Errorf("image: layout %s has no index.json: %w", abs, err)
	}
	idx, err := ParseIndex(idxData)
	if err != nil {
		return nil, err
	}
	if len(idx.Manifests) == 0 {
		return nil, fmt.Errorf("image: layout index has no manifests")
	}
	if opts.Tag == "" {
		opts.Tag = "latest"
	}
	desc := idx.Manifests[0]
	for i := range idx.Manifests {
		if refName(opts.Tag) != "" && idx.Manifests[i].Annotations[annotationRefName] == refName(opts.Tag) {
			desc = idx.Manifests[i]
			break
		}
	}

	man, manDigest, err := is.importManifestBlob(abs, desc)
	if err != nil {
		return nil, err
	}
	cfg, err := is.importConfigBlob(abs, man.Config)
	if err != nil {
		return nil, err
	}

	if len(cfg.RootFS.DiffIDs) != len(man.Layers) {
		return nil, fmt.Errorf("image: config references %d diff_ids but manifest has %d layers",
			len(cfg.RootFS.DiffIDs), len(man.Layers))
	}

	for i := range man.Layers {
		d := man.Layers[i]
		if err := is.importLayerBlob(abs, d); err != nil {
			return nil, fmt.Errorf("image: import layer %d: %w", i, err)
		}
		got, err := is.st.DiffID(digestOf(d))
		if err != nil {
			return nil, fmt.Errorf("image: diff layer %d: %w", i, err)
		}
		want, err := store.ParseDigest(cfg.RootFS.DiffIDs[i])
		if err != nil {
			return nil, err
		}
		if got.String() != want.String() {
			return nil, fmt.Errorf("image: layer %d digest mismatch: store has diff %s, config expects %s",
				i, got, want)
		}
		if _, err := is.st.EnsureLayer(digestOf(d)); err != nil {
			return nil, fmt.Errorf("image: extract layer %d: %w", i, err)
		}
	}

	name, err := localTagName(opts.Tag)
	if err != nil {
		return nil, err
	}

	is.mu.Lock()
	doc, err := is.readDoc()
	if err != nil {
		is.mu.Unlock()
		return nil, err
	}
	doc.Images[name] = refRow{Manifest: manDigest, Created: time.Now()}
	if err := is.saveRefs(doc); err != nil {
		is.mu.Unlock()
		return nil, err
	}
	is.mu.Unlock()

	img, err := is.Get(name)
	if err != nil {
		return nil, err
	}
	return img, nil
}
func (is *ImageStore) importManifestBlob(layout string, d Descriptor) (*Manifest, store.Digest, error) {
	data, err := is.copyLayoutBlob(layout, d)
	if err != nil {
		return nil, store.Digest{}, err
	}
	man, err := ParseManifest(data)
	if err != nil {
		return nil, store.Digest{}, err
	}
	return man, digestOf(d), nil
}
func (is *ImageStore) importConfigBlob(layout string, d Descriptor) (*ImageConfig, error) {
	data, err := is.copyLayoutBlob(layout, d)
	if err != nil {
		return nil, err
	}
	return ParseImageConfig(data)
}
func (is *ImageStore) importLayerBlob(layout string, d Descriptor) error {
	src := layoutBlobPath(layout, digestOf(d))
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("image: open layout blob %s: %w", src, err)
	}
	defer in.Close()
	got, err := is.st.PutBlob(in)
	if err != nil {
		return err
	}
	if got.String() != digestOf(d).String() {
		return fmt.Errorf("image: layout blob %s is corrupt (recomputed %s)", d.Digest, got)
	}
	return nil
}
func (is *ImageStore) copyLayoutBlob(layout string, d Descriptor) ([]byte, error) {
	in, err := os.Open(layoutBlobPath(layout, digestOf(d)))
	if err != nil {
		return nil, fmt.Errorf("image: open layout blob %s: %w", digestOf(d), err)
	}
	defer in.Close()
	got, err := is.st.PutBlob(in)
	if err != nil {
		return nil, err
	}
	if got.String() != digestOf(d).String() {
		return nil, fmt.Errorf("image: layout blob %s is corrupt (recomputed %s)", digestOf(d), got)
	}
	rc, err := is.st.OpenBlob(got)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func layoutBlobPath(layout string, d store.Digest) string {
	return filepath.Join(layout, "blobs", d.Algo, d.Hex)
}
func refName(tag string) string {
	return tag
}
func localTagName(tag string) (string, error) {
	r, err := ParseRef(tag)
	if err != nil {
		return "", err
	}
	if r.Registry != "" {
		return "", fmt.Errorf("image: import tag %q must be a local name (no registry)", tag)
	}
	return r.LocalName(), nil
}
