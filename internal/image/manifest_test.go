package image

import (
	"strings"
	"testing"
)

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestParseManifestValid(t *testing.T) {
	data := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + digestA + `","size":100},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"` + digestB + `","size":200}]}`)
	m, err := ParseManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Layers) != 1 || m.Config.Digest != digestA {
		t.Fatalf("parsed manifest: %+v", m)
	}
}

func TestParseManifestMalformed(t *testing.T) {
	layers := `"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"` + digestB + `","size":200}]`
	cases := []string{
		``,
		`{`,
		`{"schemaVersion":1,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + digestA + `","size":1},` + layers + `}`,
		`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"not-a-digest","size":1},` + layers + `}`,
		`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + digestA + `","size":-1},` + layers + `}`,
		`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + digestA + `","size":1},"layers":[]}`,
		`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + digestA + `","size":1},"layers":[{"mediaType":"text/plain","digest":"` + digestB + `","size":2}]}`,
		`{"schemaVersion":2,"config":{"mediaType":"text/plain","digest":"` + digestA + `","size":1},` + layers + `}`,
		`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + digestA + `","size":1},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+zstd","digest":"` + digestB + `","size":2}]}`,
	}
	for i, c := range cases {
		if _, err := ParseManifest([]byte(c)); err == nil {
			t.Errorf("case %d should be rejected", i)
		}
	}
}

func TestParseManifestMediaTypeDefaults(t *testing.T) {
	data := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"` + digestA + `","size":1},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","digest":"` + digestB + `","size":2}]}`)
	m, err := ParseManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	if m.MediaType != MediaTypeDockerManifest {
		t.Errorf("default media type = %q", m.MediaType)
	}
}

func TestParseIndex(t *testing.T) {
	ok := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"` + digestA + `","size":1}]}`)
	if _, err := ParseIndex(ok); err != nil {
		t.Fatal(err)
	}
	if !IsIndexMediaType(MediaTypeOCIIndex) || !IsIndexMediaType(MediaTypeDockerManifestList) {
		t.Error("index media type helpers wrong")
	}
	if IsIndexMediaType(MediaTypeOCIManifest) {
		t.Error("manifest is not an index")
	}
	for _, bad := range []string{
		`{"schemaVersion":1,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"` + digestA + `","size":1}]}`,
		`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"junk","size":1}]}`,
	} {
		if _, err := ParseIndex([]byte(bad)); err == nil {
			t.Errorf("index %s should be rejected", bad)
		}
	}
}

func TestParseImageConfig(t *testing.T) {
	good := `{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["` + digestA + `"]}}`
	if _, err := ParseImageConfig([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"architecture":"amd64","os":"linux","rootfs":{"type":"photos","diff_ids":["` + digestA + `"]}}`,
		`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:junk"]}}`,
		`{"architecture":"amd64","os":"linux"}`,
	} {
		if _, err := ParseImageConfig([]byte(bad)); err == nil {
			t.Errorf("config %s should be rejected", bad)
		}
	}
}

func TestNormalizeMediaType(t *testing.T) {
	if got := NormalizeMediaType("application/vnd.oci.image.manifest.v1+json, vendored"); got != "application/vnd.oci.image.manifest.v1+json" {
		t.Errorf("NormalizeMediaType = %q", got)
	}
	if got := NormalizeMediaType(strings.TrimSuffix("x", "x")); got != "" {
		t.Errorf("empty normalize = %q", got)
	}
}
