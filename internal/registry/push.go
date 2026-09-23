package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"jailor/internal/image"
	"jailor/internal/store"
)

type PushOptions struct {
	MaxConcurrent int
}

func (o PushOptions) maxConcurrent(c *Client) int {
	if o.MaxConcurrent > 0 {
		return o.MaxConcurrent
	}
	return c.maxConcurrent()
}

type PushResult struct {
	Digest store.Digest

	BlobsUploaded int

	BlobsSkipped int
}

func (c *Client) Push(is *image.ImageStore, refStr string, opts PushOptions) (*PushResult, error) {
	ref, err := Resolve(refStr)
	if err != nil {
		return nil, err
	}
	if is == nil {
		return nil, errors.New("registry: no image store for push")
	}
	if ref.Digest.Valid() {
		return nil, errors.New("registry: pushing by digest is not supported; push a tag")
	}

	local, err := localPullTag(refStr)
	if err != nil {
		return nil, err
	}
	img, err := is.Get(local)
	if err != nil {
		return nil, fmt.Errorf("registry: local image %q not found (pull it or import it first): %w", local, err)
	}

	manBytes, err := readStoreBlob(is, img.Digest)
	if err != nil {
		return nil, fmt.Errorf("registry: read manifest %s: %w", img.Digest, err)
	}
	man, err := image.ParseManifest(manBytes)
	if err != nil {
		return nil, err
	}

	scope := "repository:" + ref.Name + ":pull,push"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	res := &PushResult{Digest: img.Digest}

	var single sync.Mutex
	if err := c.uploadBlob(ctx, is, ref, scope, man.Config, &single, res); err != nil {
		return nil, fmt.Errorf("registry: upload config: %w", err)
	}

	if err := c.uploadBlobs(ctx, is, ref, scope, man.Layers, res, opts.maxConcurrent(c)); err != nil {
		return nil, err
	}

	if err := c.uploadManifest(ctx, ref, scope, man, manBytes); err != nil {
		return nil, fmt.Errorf("registry: upload manifest: %w", err)
	}
	return res, nil
}

func (c *Client) uploadManifest(ctx context.Context, ref image.Ref, scope string, man *image.Manifest, manBytes []byte) error {
	if man.MediaType == "" {
		if man.Config.MediaType == image.MediaTypeDockerConfig {
			man.MediaType = image.MediaTypeDockerManifest
		} else {
			man.MediaType = image.MediaTypeOCIManifest
		}
	}
	header := http.Header{"Content-Type": []string{man.MediaType}}
	body := func() io.Reader { return strings.NewReader(string(manBytes)) }
	resp, err := c.do(http.MethodPut, ref.Registry, "/v2/"+ref.Name+"/manifests/"+ref.Tag, header, body, scope)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusAccepted, http.StatusOK:
		return nil
	}
	return apiError(resp)
}

func (c *Client) uploadBlobs(ctx context.Context, is *image.ImageStore, ref image.Ref, scope string, blobs []image.Descriptor, res *PushResult, maxCon int) error {
	if maxCon < 1 {
		maxCon = 1
	}
	sem := make(chan struct{}, maxCon)
	errCh := make(chan error, len(blobs))
	var wg sync.WaitGroup
	var resMu sync.Mutex
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i := range blobs {
		d := blobs[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			if err := c.uploadBlob(ctx, is, ref, scope, d, &resMu, res); err != nil {
				errCh <- err
				cancel()
				return
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) uploadBlob(ctx context.Context, is *image.ImageStore, ref image.Ref, scope string, d image.Descriptor, statsMu *sync.Mutex, res *PushResult) error {
	dig, err := store.ParseDigest(d.Digest)
	if err != nil {
		return err
	}
	size, err := is.Store().BlobSize(dig)
	if err != nil {
		return fmt.Errorf("registry: local blob %s missing: %w", dig, err)
	}

	head, err := c.do(http.MethodHead, ref.Registry, "/v2/"+ref.Name+"/blobs/"+dig.String(), nil, nil, scope)
	if err != nil {
		return err
	}
	head.Body.Close()
	if head.StatusCode == http.StatusOK {
		statsMu.Lock()
		res.BlobsSkipped++
		statsMu.Unlock()
		return nil
	}
	if head.StatusCode != http.StatusNotFound {
		return apiError(head)
	}

	resp, err := c.do(http.MethodPost, ref.Registry, "/v2/"+ref.Name+"/blobs/uploads/", nil, nil, scope)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return apiError(resp)
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return errors.New("registry: upload initiation returned no Location")
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}

	putURL, err := c.resolveLocation(ref.Registry, location, dig)
	if err != nil {
		return err
	}
	rc, err := is.Store().OpenBlob(dig)
	if err != nil {
		return err
	}
	defer rc.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, putURL, io.LimitReader(rc, size))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "jailor")
	upResp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer upResp.Body.Close()
	switch upResp.StatusCode {
	case http.StatusCreated, http.StatusAccepted:
		statsMu.Lock()
		res.BlobsUploaded++
		statsMu.Unlock()
		return nil
	}
	return apiError(upResp)
}

func readStoreBlob(is *image.ImageStore, d store.Digest) ([]byte, error) {
	rc, err := is.Store().OpenBlob(d)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (c *Client) resolveLocation(host, location string, dig store.Digest) (string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("registry: invalid upload location %q: %w", location, err)
	}
	if !u.IsAbs() {
		u.Scheme = c.scheme(host)
		u.Host = host
	}
	q := u.Query()
	q.Set("digest", dig.String())
	u.RawQuery = q.Encode()
	return u.String(), nil
}
