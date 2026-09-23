package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"jailor/internal/image"
)

func cliLayer(t *testing.T, name, content string) ([]byte, string) {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	h := sha256.Sum256(raw.Bytes())
	var comp bytes.Buffer
	gz := gzip.NewWriter(&comp)
	if _, err := gz.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	return comp.Bytes(), "sha256:" + hex.EncodeToString(h[:])
}

type cliImage struct {
	Blobs       map[string][]byte
	MediaType   map[string]string
	Manifest    []byte
	manifestDig string
	LayerDigs   []string
}

func newCLIImage(t *testing.T) *cliImage {
	t.Helper()
	l1, d1 := cliLayer(t, "etc/base.conf", "base\n")
	l2, d2 := cliLayer(t, "etc/app.conf", "app\n")
	blobs := map[string][]byte{}
	media := map[string]string{}
	for _, l := range [][]byte{l1, l2} {
		dig := "sha256:" + sha256Hex(l)
		blobs[dig] = l
		media[dig] = "application/vnd.oci.image.layer.v1.tar+gzip"
	}
	cfg := image.ImageConfig{
		Architecture: "amd64",
		OS:           "linux",
		Config: image.RuntimeConfig{
			Cmd: []string{"/bin/sh"}, Env: []string{"PATH=/usr/bin:/bin"}, WorkingDir: "/",
		},
		RootFS: image.ImageRootFS{Type: "layers", DiffIDs: []string{d1, d2}},
	}
	cfgData, _ := json.Marshal(cfg)
	cfgDig := "sha256:" + sha256Hex(cfgData)
	blobs[cfgDig] = cfgData
	media[cfgDig] = "application/vnd.oci.image.config.v1+json"
	man := image.Manifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Config:        image.Descriptor{MediaType: media[cfgDig], Digest: cfgDig, Size: int64(len(cfgData))},
		Layers: []image.Descriptor{
			{MediaType: media["sha256:"+sha256Hex(l1)], Digest: "sha256:" + sha256Hex(l1), Size: int64(len(l1))},
			{MediaType: media["sha256:"+sha256Hex(l2)], Digest: "sha256:" + sha256Hex(l2), Size: int64(len(l2))},
		},
	}
	manData, _ := json.Marshal(man)
	manDig := "sha256:" + sha256Hex(manData)
	blobs[manDig] = manData
	media[manDig] = "application/vnd.oci.image.manifest.v1+json"
	return &cliImage{
		Blobs: blobs, MediaType: media, Manifest: manData, manifestDig: manDig,
		LayerDigs: []string{"sha256:" + sha256Hex(l1), "sha256:" + sha256Hex(l2)},
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type cliRegistry struct {
	t               *testing.T
	srv             *httptest.Server
	mu              sync.Mutex
	img             *cliImage
	missingManifest bool
	pushedManifest  []byte
	blobPuts        int
	blobDigests     map[string]bool
}

func newCLIRegistry(t *testing.T, img *cliImage) *cliRegistry {
	t.Helper()
	r := &cliRegistry{t: t, img: img, blobDigests: map[string]bool{}}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *cliRegistry) host() string { return strings.TrimPrefix(r.srv.URL, "http://") }

func (r *cliRegistry) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()

	path := req.URL.Path
	switch {
	case path == "/v2/" || path == "/v2":
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
	case strings.Contains(path, "/manifests/"):
		_, _, ok := apiPathCLI(strings.Split(strings.Trim(path, "/"), "/"), "manifests")
		if req.Method == http.MethodPut {
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			body := readBody(r.t, req)
			r.pushedManifest = body
			w.Header().Set("Docker-Content-Digest", "sha256:"+sha256Hex(body))
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.missingManifest {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.img == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", r.img.MediaType[r.img.manifestDig])
		w.Header().Set("Docker-Content-Digest", r.img.manifestDig)
		w.Write(r.img.Manifest)
	case strings.Contains(path, "/blobs/uploads"):
		name, id, _ := apiPathCLI(strings.Split(strings.Trim(path, "/"), "/"), "uploads")
		if id == "" {
			w.Header().Set("Location", "/v2/"+name+"/blobs/uploads/mock")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		dig := req.URL.Query().Get("digest")
		body := readBody(r.t, req)
		if "sha256:"+sha256Hex(body) != dig {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.blobPuts++
		r.blobDigests[dig] = true
		w.WriteHeader(http.StatusCreated)
	case strings.Contains(path, "/blobs/"):
		_, dig, ok := apiPathCLI(strings.Split(strings.Trim(path, "/"), "/"), "blobs")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		data, found := []byte(nil), false
		if r.img != nil {
			data, found = r.img.Blobs[dig]
		}
		if r.blobDigests[dig] {
			found = true
		}
		if req.Method == http.MethodHead {
			if found {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", r.img.MediaType[dig])
		w.Write(data)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func apiPathCLI(parts []string, kind string) (name, ref string, ok bool) {
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

func readBody(t *testing.T, req *http.Request) []byte {
	t.Helper()
	defer req.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(req.Body); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestPullCLIRoundTrip(t *testing.T) {
	img := newCLIImage(t)
	reg := newCLIRegistry(t, img)
	ledgerDir := filepath.Join(t.TempDir(), "ledger")

	out, code := runCLI(t, ledgerDir, "pull", reg.host()+"/team/app:v1")
	if code != 0 {
		t.Fatalf("pull code = %d, out=%s", code, out)
	}
	if !strings.Contains(out, "2 layers") {
		t.Errorf("pull output missing layer count:\n%s", out)
	}

	imgs, icode := runCLI(t, ledgerDir, "images")
	if icode != 0 {
		t.Fatalf("images code = %d", icode)
	}
	if !strings.Contains(imgs, "team/app:v1") {
		t.Errorf("pulled image not listed:\n%s", imgs)
	}

	insp, xcode := runCLI(t, ledgerDir, "image", "inspect", "team/app:v1")
	if xcode != 0 {
		t.Fatalf("image inspect code = %d, out=%s", xcode, insp)
	}
	if !strings.Contains(insp, img.LayerDigs[0][7:19]) {
		t.Errorf("inspect missing first layer digest:\n%s", insp)
	}
}
func TestPullCLITagHandling(t *testing.T) {
	img := newCLIImage(t)
	reg := newCLIRegistry(t, img)
	ledgerDir := filepath.Join(t.TempDir(), "ledger")

	if out, code := runCLI(t, ledgerDir, "pull", "--tag", "custom", reg.host()+"/team/app:v1"); code != 0 {
		t.Fatalf("pull --tag code = %d, out=%s", code, out)
	}
	imgs, _ := runCLI(t, ledgerDir, "images")
	if !strings.Contains(imgs, "custom:latest") {
		t.Errorf("custom tag not listed:\n%s", imgs)
	}
}
func TestPullCLIMissingTag(t *testing.T) {
	reg := newCLIRegistry(t, newCLIImage(t))
	reg.missingManifest = true
	ledgerDir := filepath.Join(t.TempDir(), "ledger")

	_, code := runCLI(t, ledgerDir, "pull", reg.host()+"/team/app:missing")
	if code == 0 {
		t.Error("pull of a missing tag should fail")
	}
}

func TestPushCLIRoundTrip(t *testing.T) {
	srcImg := newCLIImage(t)
	src := newCLIRegistry(t, srcImg)
	dst := newCLIRegistry(t, nil)
	ledgerDir := filepath.Join(t.TempDir(), "ledger")

	if out, code := runCLI(t, ledgerDir, "pull", src.host()+"/team/app:v1"); code != 0 {
		t.Fatalf("pull code = %d, out=%s", code, out)
	}
	out, code := runCLI(t, ledgerDir, "push", dst.host()+"/team/app:v1")
	if code != 0 {
		t.Fatalf("push code = %d, out=%s", code, out)
	}
	if !strings.Contains(out, "pushed") {
		t.Errorf("push output missing confirmation:\n%s", out)
	}
	if len(dst.pushedManifest) == 0 {
		t.Error("destination registry received no manifest")
	}
	if dst.blobPuts < 3 {
		t.Errorf("destination recorded %d blob uploads, want >= 3 (config + 2 layers)", dst.blobPuts)
	}
	blobPuts := dst.blobPuts
	out2, code := runCLI(t, ledgerDir, "push", dst.host()+"/team/app:v1")
	if code != 0 {
		t.Fatalf("second push code = %d, out=%s", code, out2)
	}
	if dst.blobPuts != blobPuts {
		t.Errorf("second push re-uploaded blobs: %d -> %d", blobPuts, dst.blobPuts)
	}
}

func TestPushCLIMissingLocalImage(t *testing.T) {
	reg := newCLIRegistry(t, nil)
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	_, code := runCLI(t, ledgerDir, "push", reg.host()+"/ghost/app:v1")
	if code == 0 {
		t.Error("push of an unimported image should fail")
	}
}
