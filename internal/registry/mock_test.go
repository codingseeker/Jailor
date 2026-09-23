package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"

	"jailor/internal/image"
)

func testLayer(files map[string]string) (comp []byte, diffID string) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}

	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, name := range names {
		data := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			panic(err)
		}
		if _, err := tw.Write([]byte(data)); err != nil {
			panic(err)
		}
	}
	tw.Close()
	h := sha256.Sum256(raw.Bytes())
	diffID = "sha256:" + hex.EncodeToString(h[:])
	var compBuf bytes.Buffer
	gz := gzip.NewWriter(&compBuf)
	if _, err := gz.Write(raw.Bytes()); err != nil {
		panic(err)
	}
	gz.Close()
	return compBuf.Bytes(), diffID
}

type testImage struct {
	Blobs map[string][]byte

	MediaType map[string]string

	ManifestDigest string

	Tag string
}

func buildTestImage(tag string, layers [][]byte) *testImage {
	var diffIDs []string
	descriptors := make([]image.Descriptor, 0, len(layers))
	blobs := map[string][]byte{}
	media := map[string]string{}

	for _, comp := range layers {
		rd, err := gzip.NewReader(bytes.NewReader(comp))
		if err != nil {
			panic(err)
		}
		h := sha256.New()
		buf := make([]byte, 32*1024)
		for {
			n, err := rd.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		rd.Close()
		diffIDs = append(diffIDs, "sha256:"+hex.EncodeToString(h.Sum(nil)))
		dig := testDigest(comp)
		blobs[dig] = comp
		media[dig] = image.MediaTypeOCILayerGzip
		descriptors = append(descriptors, image.Descriptor{
			MediaType: image.MediaTypeOCILayerGzip,
			Digest:    dig,
			Size:      int64(len(comp)),
		})
	}

	cfg := image.ImageConfig{
		Architecture: "amd64",
		OS:           "linux",
		Created:      "2024-01-01T00:00:00Z",
		Config: image.RuntimeConfig{
			Env: []string{"PATH=/usr/bin:/bin"}, WorkingDir: "/", Cmd: []string{"/bin/sh"},
		},
		RootFS: image.ImageRootFS{Type: "layers", DiffIDs: diffIDs},
	}
	cfgData, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	cfgDigest := testDigest(cfgData)
	blobs[cfgDigest] = cfgData
	media[cfgDigest] = image.MediaTypeOCIConfig

	man := image.Manifest{
		SchemaVersion: 2,
		MediaType:     image.MediaTypeOCIManifest,
		Config: image.Descriptor{
			MediaType: image.MediaTypeOCIConfig,
			Digest:    cfgDigest,
			Size:      int64(len(cfgData)),
		},
		Layers: descriptors,
	}
	manData, err := json.Marshal(man)
	if err != nil {
		panic(err)
	}
	manDigest := testDigest(manData)
	blobs[manDigest] = manData
	media[manDigest] = image.MediaTypeOCIManifest

	return &testImage{Blobs: blobs, MediaType: media, ManifestDigest: manDigest, Tag: tag}
}

func (ti *testImage) layerDigest(i int) string {
	var man image.Manifest
	if err := json.Unmarshal(ti.Blobs[ti.ManifestDigest], &man); err != nil {
		panic(err)
	}
	return man.Layers[i].Digest
}

func testDigest(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

type mockRegistry struct {
	t   *testing.T
	mu  sync.Mutex
	img *testImage

	requireAuth bool
	token       string

	tokenAuthRequired bool
	tokenUser         string
	tokenPass         string

	rejectValidToken bool

	manifestFlake int

	layerGets int

	corruptDigest string

	truncateDigest string

	idx *testIndex

	pushedManifests map[string]string
	pushedBlobs     map[string][]byte
	blobHeads       int
	uploads         int
	rejectPushAuth  bool

	server *httptest.Server
}

type testIndex struct {
	Data  []byte
	Media string
}

func (m *mockRegistry) addr() string { return strings.TrimPrefix(m.server.URL, "http://") }

func newMockRegistry(t *testing.T, img *testImage) *mockRegistry {
	t.Helper()
	m := &mockRegistry{
		t:               t,
		img:             img,
		requireAuth:     false,
		token:           "test-token",
		pushedManifests: map[string]string{},
		pushedBlobs:     map[string][]byte{},
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockRegistry) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
		if m.requireAuth {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+m.server.URL+`/token",service="mock",scope="registry:mock:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 1 && parts[0] == "token" {
		m.serveToken(w, r)
		return
	}

	if m.requireAuth || m.rejectPushAuth {
		if r.Header.Get("Authorization") != "Bearer "+m.token {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+m.server.URL+`/token",service="mock",scope="repository:mock:pull,push"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	if m.rejectValidToken && r.Header.Get("Authorization") == "Bearer "+m.token {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+m.server.URL+`/token",service="mock",scope="repository:mock:pull,push"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if m.rejectPushAuth {

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	path := r.URL.Path
	if !strings.HasPrefix(path, "/v2/") && path != "/v2" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	switch {
	case r.Method == http.MethodPut && strings.Contains(path, "/manifests/"):
		name, tag, ok := apiPath(parts, "manifests")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body := new(bytes.Buffer)
		if _, err := body.ReadFrom(r.Body); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		m.pushedManifests[name+":"+tag] = body.String()
		w.Header().Set("Docker-Content-Digest", testDigest(body.Bytes()))
		w.WriteHeader(http.StatusCreated)
	case strings.Contains(path, "/manifests/"):
		name, ref, ok := apiPath(parts, "manifests")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		m.serveManifest(w, r, name, ref)
	case strings.Contains(path, "/blobs/uploads"):
		name, id, _ := apiPath(parts, "uploads")
		if id == "" {
			m.uploads++
			w.Header().Set("Location", "/v2/"+name+"/blobs/uploads/mock-upload")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		digest := r.URL.Query().Get("digest")
		body := new(bytes.Buffer)
		if _, err := body.ReadFrom(r.Body); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if testDigest(body.Bytes()) != digest {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		m.pushedBlobs[digest] = body.Bytes()
		w.WriteHeader(http.StatusCreated)
	case strings.Contains(path, "/blobs/"):
		_, digest, ok := apiPath(parts, "blobs")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodHead {
			m.blobHeads++
		}
		if r.Method == http.MethodGet {
			m.layerGets++
		}
		m.serveBlob(w, r, digest)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func apiPath(parts []string, kind string) (name, ref string, ok bool) {
	idx := -1
	for i, p := range parts {
		if p == kind {
			idx = i
			break
		}
	}
	if idx < 1 || idx+1 >= len(parts) {
		return "", "", false
	}
	return strings.Join(parts[1:idx], "/"), parts[idx+1], true
}

func (m *mockRegistry) serveToken(w http.ResponseWriter, r *http.Request) {
	if m.tokenAuthRequired {
		u, p, ok := r.BasicAuth()
		if !ok || u != m.tokenUser || p != m.tokenPass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token":"%s"}`, m.token)
}

func (m *mockRegistry) serveManifest(w http.ResponseWriter, r *http.Request, name, ref string) {
	if m.manifestFlake > 0 {
		m.manifestFlake--
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	if m.idx != nil && ref == m.img.Tag {
		w.Header().Set("Content-Type", m.idx.Media)
		w.Header().Set("Docker-Content-Digest", testDigest(m.idx.Data))
		w.Write(m.idx.Data)
		return
	}
	data := m.img.Blobs[m.img.ManifestDigest]
	if ref != m.img.Tag && ref != m.img.ManifestDigest {
		if d, ok := m.img.Blobs[ref]; ok {
			data = d
		}
	}
	if data == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", m.img.MediaType[m.img.ManifestDigest])
	w.Header().Set("Docker-Content-Digest", testDigest(data))
	w.Write(data)
}

func (m *mockRegistry) serveBlob(w http.ResponseWriter, r *http.Request, digest string) {
	if r.Method == http.MethodHead {
		if _, ok := m.blobBytes(digest); ok {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if digest == m.corruptDigest {
		data := m.img.Blobs[digest]
		corrupted := append([]byte(nil), data...)
		corrupted[len(corrupted)-1] ^= 0xff
		w.WriteHeader(http.StatusOK)
		w.Write(corrupted)
		return
	}
	if digest == m.truncateDigest {
		data := m.img.Blobs[digest]
		w.WriteHeader(http.StatusOK)
		w.Write(data[:len(data)/2])
		return
	}
	data, ok := m.blobBytes(digest)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (m *mockRegistry) blobBytes(digest string) ([]byte, bool) {
	if b, ok := m.img.Blobs[digest]; ok {
		return b, true
	}
	if b, ok := m.pushedBlobs[digest]; ok {
		return b, true
	}
	return nil, false
}

func twoLayerImage() *testImage {
	l1, _ := testLayer(map[string]string{"etc/base.conf": "base\n"})
	l2, _ := testLayer(map[string]string{"etc/app.conf": "app\n"})
	return buildTestImage("v1", [][]byte{l1, l2})
}

func indexOf(t *testing.T, img *testImage) *testIndex {
	t.Helper()
	idx := image.Index{
		SchemaVersion: 2,
		MediaType:     image.MediaTypeOCIIndex,
		Manifests: []image.Descriptor{
			{MediaType: image.MediaTypeOCIManifest, Digest: "sha256:" + strings.Repeat("0", 64), Size: 0,
				Platform: &image.Platform{OS: "linux", Architecture: "riscv64"}},
			{MediaType: image.MediaTypeOCIManifest, Digest: img.ManifestDigest, Size: int64(len(img.Blobs[img.ManifestDigest])),
				Platform: &image.Platform{OS: "linux", Architecture: runtime.GOARCH}},
		},
	}
	data, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	return &testIndex{Data: data, Media: image.MediaTypeOCIIndex}
}

func openTestStore(t *testing.T) *image.ImageStore {
	t.Helper()
	is, err := image.Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	return is
}

func pullClient(t *testing.T) *Client {
	t.Helper()
	c := New()
	c.MaxConcurrent = 2
	c.Retries = 3
	return c
}
