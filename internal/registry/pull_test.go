package registry

import (
	"errors"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	cases := map[string]struct {
		wantHost string
		wantName string
		wantTag  string
		wantErr  bool
	}{
		"alpine":           {wantHost: "registry-1.docker.io", wantName: "library/alpine", wantTag: "latest"},
		"alpine:3.19":      {wantHost: "registry-1.docker.io", wantName: "library/alpine", wantTag: "3.19"},
		"team/app":         {wantHost: "registry-1.docker.io", wantName: "team/app", wantTag: "latest"},
		"quay.io/team/app": {wantHost: "quay.io", wantName: "team/app", wantTag: "latest"},
		"ghcr.io/a/b:v1":   {wantHost: "ghcr.io", wantName: "a/b", wantTag: "v1"},
		"localhost:5000/a": {wantHost: "localhost:5000", wantName: "a", wantTag: "latest"},
		"":                 {wantErr: true},
		"UPPER/name":       {wantErr: true},
	}
	for in, tc := range cases {
		r, err := Resolve(in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("Resolve(%q) succeeded, want error", in)
			}
			continue
		}
		if err != nil {
			t.Errorf("Resolve(%q): %v", in, err)
			continue
		}
		if r.Registry != tc.wantHost || r.Name != tc.wantName || r.Tag != tc.wantTag {
			t.Errorf("Resolve(%q) = host %q name %q tag %q, want %q/%q/%q",
				in, r.Registry, r.Name, r.Tag, tc.wantHost, tc.wantName, tc.wantTag)
		}
	}
}

func TestParseChallenge(t *testing.T) {
	ch, ok := parseChallenge(`Bearer realm="https://auth.example/token",service="reg",scope="repo:a:pull"`)
	if !ok {
		t.Fatal("parseChallenge failed")
	}
	if ch.Scheme != "Bearer" || ch.Realm != "https://auth.example/token" ||
		ch.Service != "reg" || ch.Scope != "repo:a:pull" {
		t.Errorf("parsed challenge = %+v", ch)
	}
	if _, ok := parseChallenge(`Digest realm="x" account="y"`); ok {
		t.Error("Digest scheme should be unsupported")
	}
	if _, ok := parseChallenge("Basic realm=registry"); !ok {
		t.Error("Basic challenge should parse")
	}
}

func TestPullRoundTrip(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	is := openTestStore(t)

	ref := m.addr() + "/team/app:v1"
	res, err := pullClient(t).Pull(is, ref, PullOptions{})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if res.Image.Name != "team/app:v1" {
		t.Errorf("stored name = %q, want team/app:v1", res.Image.Name)
	}
	if len(res.Image.Layers) != 2 {
		t.Errorf("layers = %d, want 2", len(res.Image.Layers))
	}
	if res.LayersDownloaded != 2 {
		t.Errorf("downloaded = %d, want 2", res.LayersDownloaded)
	}
	got, err := is.Get("team/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest.String() != img.ManifestDigest {
		t.Errorf("manifest digest = %s, want %s", got.Digest, img.ManifestDigest)
	}
}

func TestPullLayerReuse(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	is := openTestStore(t)
	ref := m.addr() + "/team/app:v1"
	c := pullClient(t)

	if _, err := c.Pull(is, ref, PullOptions{}); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	afterFirst := m.layerGets
	m.mu.Unlock()

	res, err := c.Pull(is, ref, PullOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.LayersDownloaded != 0 {
		t.Errorf("second pull downloaded %d layers, want 0", res.LayersDownloaded)
	}
	if res.LayersReused != 2 {
		t.Errorf("second pull reused %d layers, want 2", res.LayersReused)
	}
	m.mu.Lock()
	if m.layerGets != afterFirst {
		t.Errorf("blob GETs grew after reuse: %d -> %d", afterFirst, m.layerGets)
	}
	m.mu.Unlock()
}

func TestPullRejectsCorruptLayer(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	is := openTestStore(t)

	m.corruptDigest = img.layerDigest(1)

	if _, err := pullClient(t).Pull(is, m.addr()+"/team/app:v1", PullOptions{}); err == nil {
		t.Fatal("pull of a corrupted layer should fail")
	} else if !strings.Contains(err.Error(), "digest mismatch") && !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPullRejectsTruncatedDownload(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	is := openTestStore(t)
	m.truncateDigest = img.layerDigest(0)

	if _, err := pullClient(t).Pull(is, m.addr()+"/team/app:v1", PullOptions{}); err == nil {
		t.Fatal("pull of a truncated (interrupted) download should fail")
	}
}

func TestPullAuthRequiredAnonymous(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	m.requireAuth = true
	m.tokenAuthRequired = true
	is := openTestStore(t)

	if _, err := pullClient(t).Pull(is, m.addr()+"/team/app:v1", PullOptions{}); err == nil {
		t.Fatal("pull without credentials should fail")
	} else if !errors.Is(err, ErrAuthRequired) {
		t.Errorf("want ErrAuthRequired, got %v", err)
	}
}

func TestPullAuthWithCredentials(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	m.requireAuth = true
	m.tokenAuthRequired = true
	m.tokenUser = "alice"
	m.tokenPass = "s3cret"
	is := openTestStore(t)

	c := pullClient(t)
	c.Creds = func(host string) Credential {
		return Credential{Username: "alice", Password: "s3cret"}
	}
	if _, err := c.Pull(is, m.addr()+"/team/app:v1", PullOptions{}); err != nil {
		t.Fatalf("Pull with credentials: %v", err)
	}
}

func TestPullRejectsPresentedCredentials(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	m.requireAuth = true
	m.rejectValidToken = true
	is := openTestStore(t)

	c := pullClient(t)
	c.Creds = func(host string) Credential {
		return Credential{Username: "alice", Password: "s3cret"}
	}
	if _, err := c.Pull(is, m.addr()+"/team/app:v1", PullOptions{}); err == nil {
		t.Fatal("pull with rejected credentials should fail")
	} else if !errors.Is(err, ErrAuthRequired) {
		t.Errorf("want ErrAuthRequired, got %v", err)
	}
}

func TestPullRetriesTransientNewManifest(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	m.manifestFlake = 2
	is := openTestStore(t)

	if _, err := pullClient(t).Pull(is, m.addr()+"/team/app:v1", PullOptions{}); err != nil {
		t.Fatalf("Pull after transient 503s: %v", err)
	}
}

func TestPullRejectsMalformedManifest(t *testing.T) {
	m := newMockRegistry(t, twoLayerImage())
	is := openTestStore(t)

	m.img.Blobs[m.img.ManifestDigest] = []byte("{not json")
	c := pullClient(t)
	if _, err := c.Pull(is, m.addr()+"/team/app:v1", PullOptions{}); err == nil {
		t.Fatal("pull of a malformed manifest should fail")
	}
}

func TestPullDefaultLocalTag(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	is := openTestStore(t)

	if _, err := pullClient(t).Pull(is, m.addr()+"/team/app:v1", PullOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := is.Get("team/app:v1"); err != nil {
		t.Errorf("derived local tag missing: %v", err)
	}
}

func TestPullCustomLocalTag(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	is := openTestStore(t)

	if _, err := pullClient(t).Pull(is, m.addr()+"/team/app:v1", PullOptions{Tag: "mytag"}); err != nil {
		t.Fatal(err)
	}
	if _, err := is.Get("mytag:latest"); err != nil {
		t.Errorf("custom local tag missing: %v", err)
	}
}

func TestPullResolvesMultiArchIndex(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	m.idx = indexOf(t, img)
	is := openTestStore(t)

	if _, err := pullClient(t).Pull(is, m.addr()+"/team/app:v1", PullOptions{}); err != nil {
		t.Fatalf("pull of a platform-matching index: %v", err)
	}
	got, err := is.Get("team/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest.String() != img.ManifestDigest {
		t.Errorf("resolved manifest = %s, want %s", got.Digest, img.ManifestDigest)
	}
}

func TestPullBoundedConcurrency(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	is := openTestStore(t)

	if _, err := pullClient(t).Pull(is, m.addr()+"/team/app:v1", PullOptions{MaxConcurrent: 1}); err != nil {
		t.Fatalf("pull with 1 worker: %v", err)
	}
	if _, err := is.Get("team/app:v1"); err != nil {
		t.Errorf("image missing after 1-worker pull: %v", err)
	}
}

func TestPullByDigestReference(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	is := openTestStore(t)

	if _, err := pullClient(t).Pull(is, m.addr()+"/team/app@"+img.ManifestDigest, PullOptions{}); err != nil {
		t.Fatalf("pull by digest: %v", err)
	}
	if _, err := is.Get("team/app:latest"); err != nil {
		t.Errorf("digest-pull image missing: %v", err)
	}
}
