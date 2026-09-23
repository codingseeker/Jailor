package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"jailor/internal/image"
	"jailor/internal/store"
)

const acceptManifest = "application/vnd.docker.distribution.manifest.v2+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.oci.image.index.v1+json"

type PullOptions struct {
	Tag string

	MaxConcurrent int
}

type PullResult struct {
	Image *image.Image

	LayersDownloaded int

	LayersReused int
}

func (c *Client) Pull(is *image.ImageStore, refStr string, opts PullOptions) (*PullResult, error) {
	ref, err := Resolve(refStr)
	if err != nil {
		return nil, err
	}
	if is == nil {
		return nil, errors.New("registry: no image store for pull")
	}
	scope := "repository:" + ref.Name + ":pull"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	manBytes, manDigest, err := c.fetchManifest(ctx, ref, scope)
	if err != nil {
		return nil, fmt.Errorf("registry: fetch manifest: %w", err)
	}
	man, err := image.ParseManifest(manBytes)
	if err != nil {
		return nil, err
	}

	localTag := opts.Tag
	if localTag == "" {
		localTag, err = localPullTag(refStr)
		if err != nil {
			return nil, err
		}
	}

	layout, err := os.MkdirTemp("", "jailor-pull-*")
	if err != nil {
		return nil, fmt.Errorf("registry: stage pull: %w", err)
	}
	defer os.RemoveAll(layout)

	if err := writeLayoutBootstrap(layout); err != nil {
		return nil, err
	}
	if err := writeLayoutFile(layout, manDigest, manBytes); err != nil {
		return nil, err
	}

	cfgData, err := c.downloadBlob(ctx, is, layout, ref, scope, man.Config)
	if err != nil {
		return nil, err
	}
	if _, err := image.ParseImageConfig(cfgData); err != nil {
		return nil, err
	}

	res, err := c.downloadLayers(ctx, is, layout, ref, scope, man.Layers, opts.maxConcurrent(c))
	if err != nil {
		return nil, err
	}

	idx := image.Index{
		SchemaVersion: 2,
		MediaType:     image.MediaTypeOCIIndex,
		Manifests: []image.Descriptor{{
			MediaType:   man.MediaType,
			Digest:      manDigest.String(),
			Size:        int64(len(manBytes)),
			Annotations: map[string]string{refNameAnnotation: localTag},
		}},
	}
	idxData, err := json.Marshal(idx)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(layout, "index.json"), idxData, 0o644); err != nil {
		return nil, err
	}

	img, err := is.ImportLayout(layout, image.ImportOptions{Tag: localTag})
	if err != nil {
		return nil, fmt.Errorf("registry: import pulled image: %w", err)
	}
	return &PullResult{
		Image:            img,
		LayersDownloaded: res.downloaded,
		LayersReused:     res.reused,
	}, nil
}

const refNameAnnotation = "org.opencontainers.image.ref.name"

func (o PullOptions) maxConcurrent(c *Client) int {
	if o.MaxConcurrent > 0 {
		return o.MaxConcurrent
	}
	return c.maxConcurrent()
}

func localPullTag(refStr string) (string, error) {
	orig, err := image.ParseRef(refStr)
	if err != nil {
		return "", err
	}
	if orig.Name == "" {
		return "", errors.New("registry: cannot derive a local tag")
	}
	tag := orig.Tag
	if tag == "" {
		tag = "latest"
	}
	return orig.Name + ":" + tag, nil
}

func (c *Client) fetchManifest(ctx context.Context, ref image.Ref, scope string) ([]byte, store.Digest, error) {
	reqPath := "/v2/" + ref.Name + "/manifests/" + ref.Tag
	if ref.Digest.Valid() {
		reqPath = "/v2/" + ref.Name + "/manifests/" + ref.Digest.String()
	}
	header := http.Header{"Accept": []string{acceptManifest}}
	resp, err := c.do(http.MethodGet, ref.Registry, reqPath, header, nil, scope)
	if err != nil {
		return nil, store.Digest{}, err
	}
	defer resp.Body.Close()
	if err := httpOK(resp, http.StatusOK); err != nil {
		return nil, store.Digest{}, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, store.Digest{}, fmt.Errorf("registry: read manifest: %w", err)
	}
	mediaType := image.NormalizeMediaType(resp.Header.Get("Content-Type"))

	computed := sha256Hex(body)
	if ref.Digest.Valid() && computed != ref.Digest.String() {
		return nil, store.Digest{}, fmt.Errorf("registry: manifest digest mismatch: got %s, expected %s", computed, ref.Digest)
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != "" {
		if d, perr := store.ParseDigest(got); perr == nil && computed != d.String() {
			return nil, store.Digest{}, fmt.Errorf("registry: manifest digest mismatch: got %s, registry says %s", computed, d)
		}
	}

	if image.IsIndexMediaType(mediaType) {
		child, cdig, err := c.selectIndexChild(ctx, ref, scope, body)
		if err != nil {
			return nil, store.Digest{}, err
		}
		return child, cdig, nil
	}
	if !image.IsManifestMediaType(mediaType) {
		return nil, store.Digest{}, fmt.Errorf("registry: unsupported manifest media type %q", mediaType)
	}
	dig := store.NewDigest(store.DigestAlgoSHA256, strings.TrimPrefix(computed, "sha256:"))
	return body, dig, nil
}

func (c *Client) selectIndexChild(ctx context.Context, ref image.Ref, scope string, indexBytes []byte) ([]byte, store.Digest, error) {
	idx, err := image.ParseIndex(indexBytes)
	if err != nil {
		return nil, store.Digest{}, err
	}
	if len(idx.Manifests) == 0 {
		return nil, store.Digest{}, fmt.Errorf("registry: image index has no manifests")
	}

	var chosen image.Descriptor
	for _, d := range idx.Manifests {
		if p := d.Platform; p != nil && p.OS == "linux" && p.Architecture == runtime.GOARCH {
			chosen = d
			break
		}
	}
	if chosen.Digest == "" {
		chosen = idx.Manifests[0]
	}

	child, err := c.do(http.MethodGet, ref.Registry, "/v2/"+ref.Name+"/manifests/"+chosen.Digest,
		http.Header{"Accept": []string{acceptManifest}}, nil, scope)
	if err != nil {
		return nil, store.Digest{}, err
	}
	defer child.Body.Close()
	if err := httpOK(child, http.StatusOK); err != nil {
		return nil, store.Digest{}, err
	}
	body, err := io.ReadAll(child.Body)
	if err != nil {
		return nil, store.Digest{}, err
	}
	mediaType := image.NormalizeMediaType(child.Header.Get("Content-Type"))
	if !image.IsManifestMediaType(mediaType) {
		return nil, store.Digest{}, fmt.Errorf("registry: index entry %s has unsupported media type %q", chosen.Digest, mediaType)
	}
	got := sha256Hex(body)
	want, err := store.ParseDigest(chosen.Digest)
	if err != nil {
		return nil, store.Digest{}, err
	}
	if got != want.String() {
		return nil, store.Digest{}, fmt.Errorf("registry: index entry digest mismatch: got %s, expected %s", got, want)
	}
	return body, want, nil
}

func (c *Client) downloadBlob(ctx context.Context, is *image.ImageStore, layout string, ref image.Ref, scope string, d image.Descriptor) ([]byte, error) {
	dig, err := store.ParseDigest(d.Digest)
	if err != nil {
		return nil, err
	}
	if is.Store().HasBlob(dig) {
		if err := copyLocalBlob(is, layout, dig); err != nil {
			return nil, err
		}
		return os.ReadFile(layoutBlobWithin(layout, dig))
	}
	return c.downloadBlobRemote(ctx, layout, ref, scope, dig)
}

func (c *Client) downloadBlobRemote(ctx context.Context, layout string, ref image.Ref, scope string, dig store.Digest) ([]byte, error) {
	resp, err := c.do(http.MethodGet, ref.Registry, "/v2/"+ref.Name+"/blobs/"+dig.String(), nil, nil, scope)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := httpOK(resp, http.StatusOK); err != nil {
		return nil, err
	}

	dst := layoutBlobWithin(layout, dig)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		return nil, fmt.Errorf("registry: download blob %s: %w", dig, err)
	}
	got := store.NewDigest(store.DigestAlgoSHA256, hex.EncodeToString(h.Sum(nil)))
	if got.String() != dig.String() {
		return nil, fmt.Errorf("registry: blob %s is corrupt (recomputed %s)", dig, got)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return os.ReadFile(dst)
}

func (c *Client) downloadLayers(ctx context.Context, is *image.ImageStore, layout string, ref image.Ref, scope string, layers []image.Descriptor, maxCon int) (*layerStats, error) {
	if maxCon < 1 {
		maxCon = 1
	}
	sem := make(chan struct{}, maxCon)
	errCh := make(chan error, len(layers))
	var wg sync.WaitGroup
	var stats layerStats
	var statsMu sync.Mutex
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i := range layers {
		d := layers[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			dig, err := store.ParseDigest(d.Digest)
			if err != nil {
				errCh <- err
				cancel()
				return
			}
			if is.Store().HasBlob(dig) {
				if err := copyLocalBlob(is, layout, dig); err != nil {
					errCh <- err
					cancel()
					return
				}
				statsMu.Lock()
				stats.reused++
				statsMu.Unlock()
				return
			}
			if _, err := c.downloadBlobRemote(ctx, layout, ref, scope, dig); err != nil {
				errCh <- err
				cancel()
				return
			}
			statsMu.Lock()
			stats.downloaded++
			statsMu.Unlock()
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return nil, err
		}
	}
	return &stats, nil
}

type layerStats struct {
	downloaded int
	reused     int
}

func copyLocalBlob(is *image.ImageStore, layout string, dig store.Digest) error {
	dst := layoutBlobWithin(layout, dig)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	w, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := is.Store().CopyBlobTo(dig, w); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func writeLayoutBootstrap(layout string) error {
	blobDir := filepath.Join(layout, "blobs", "sha256")
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644)
}

func writeLayoutFile(layout string, dig store.Digest, data []byte) error {
	dst := layoutBlobWithin(layout, dig)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

func layoutBlobWithin(layout string, d store.Digest) string {
	return filepath.Join(layout, "blobs", d.Algo, d.Hex)
}
