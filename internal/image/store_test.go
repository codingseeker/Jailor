package image

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func newTestStore(t *testing.T) *ImageStore {
	t.Helper()
	is, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	return is
}

func TestImportListInspect(t *testing.T) {
	is := newTestStore(t)
	layout := t.TempDir()
	twoLayerImage(layout, "app:v1")

	img, err := is.ImportLayout(layout, ImportOptions{Tag: "myapp:v1"})
	if err != nil {
		t.Fatal(err)
	}
	if img.Name != "myapp:v1" || len(img.Layers) != 2 {
		t.Fatalf("imported image = %+v", img)
	}
	if img.Config.Config.Cmd[0] != "/bin/sh" {
		t.Errorf("config cmd not parsed: %+v", img.Config.Config.Cmd)
	}

	got, err := is.Inspect("myapp:v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Architecture != "amd64" || got.OS != "linux" {
		t.Errorf("inspect arch/os = %q/%q", got.Architecture, got.OS)
	}
	if got.Size <= 0 {
		t.Errorf("size = %d", got.Size)
	}
	if got.Created.IsZero() {
		t.Error("missing created")
	}

	if _, err := is.ImportLayout(layout, ImportOptions{Tag: "alias:latest"}); err != nil {
		t.Fatal(err)
	}
	images, err := is.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != 2 {
		t.Fatalf("List() has %d images, want 2", len(images))
	}
	if !strings.HasPrefix(images[0].Name, "alias") && !strings.HasPrefix(images[1].Name, "alias") {
		t.Errorf("both tags should be listed: %s, %s", images[0].Name, images[1].Name)
	}

	if _, err := is.Get("nope:latest"); err == nil {
		t.Error("Get(missing) should fail")
	}
}

func TestImportRejectsLayoutErrors(t *testing.T) {
	is := newTestStore(t)
	layout := t.TempDir()

	if _, err := is.ImportLayout(layout, ImportOptions{Tag: "x"}); err == nil {
		t.Error("missing oci-layout should fail")
	}
	os.WriteFile(filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"9.0"}`), 0o644)
	if _, err := is.ImportLayout(layout, ImportOptions{Tag: "x"}); err == nil {
		t.Error("unsupported layout version should fail")
	}
	os.WriteFile(filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644)
	os.WriteFile(filepath.Join(layout, "index.json"), []byte(`{`), 0o644)
	if _, err := is.ImportLayout(layout, ImportOptions{Tag: "x"}); err == nil {
		t.Error("malformed index should fail")
	}
	os.WriteFile(filepath.Join(layout, "index.json"), []byte(`{"schemaVersion":2,"manifests":[]}`), 0o644)
	if _, err := is.ImportLayout(layout, ImportOptions{Tag: "x"}); err == nil {
		t.Error("empty index should fail")
	}
	os.Remove(filepath.Join(layout, "index.json"))
	if _, err := is.ImportLayout(t.TempDir(), ImportOptions{Tag: "quay.io/corp/app:v1"}); err == nil {
		t.Error("registry-qualified import tag should fail")
	}
}

func TestImportRejectsCorruptManifestDigest(t *testing.T) {
	is := newTestStore(t)
	layout := t.TempDir()
	man := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + digestA + `","size":1},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"` + digestB + `","size":2}]}`)
	writeBlob(layout, man)
	os.WriteFile(filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644)
	idx := Index{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIIndex,
		Manifests: []Descriptor{{
			MediaType: MediaTypeOCIManifest,
			Digest:    "sha256:" + strings.Repeat("0", 64),
			Size:      int64(len(man)),
		}},
	}
	data, _ := json.Marshal(idx)
	os.WriteFile(filepath.Join(layout, "index.json"), data, 0o644)

	if _, err := is.ImportLayout(layout, ImportOptions{Tag: "bad"}); err == nil {
		t.Fatal("import of a layout whose manifest does not match its digest must fail")
	}
}

func TestImportRejectsCorruptLayer(t *testing.T) {
	is := newTestStore(t)
	layout := t.TempDir()
	l1, _ := makeLayer(map[string]string{"a.txt": "hello\n"})
	cfg, _ := makeLayer(map[string]string{"cfg": "config\n"})
	writeLayout(layout, "corrupt:latest", [][]byte{l1}, ImageConfig{})
	_ = cfg
	blobDir := filepath.Join(layout, "blobs", "sha256")
	entries, _ := os.ReadDir(blobDir)
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 blobs, got %d", len(entries))
	}
	for _, e := range entries {
		path := filepath.Join(blobDir, e.Name())
		data, _ := os.ReadFile(path)
		if !json.Valid(data) {
			if err := os.WriteFile(path, []byte("corrupted!"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := is.ImportLayout(layout, ImportOptions{Tag: "corrupt"}); err == nil {
		t.Fatal("import of a corrupt layer must fail")
	}
}

func TestImageTagRemoveSharedLayers(t *testing.T) {
	is := newTestStore(t)

	base, _ := makeLayer(map[string]string{"etc/base.conf": "base\n"})
	lA, _ := makeLayer(map[string]string{"etc/a.conf": "a\n"})
	lB, _ := makeLayer(map[string]string{"etc/b.conf": "b\n"})

	layoutA := t.TempDir()
	writeLayout(layoutA, "appa:v1", [][]byte{base, lA}, ImageConfig{})
	layoutB := t.TempDir()
	writeLayout(layoutB, "appb:v1", [][]byte{base, lB}, ImageConfig{})

	if _, err := is.ImportLayout(layoutA, ImportOptions{Tag: "appa:v1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := is.ImportLayout(layoutB, ImportOptions{Tag: "appb:v1"}); err != nil {
		t.Fatal(err)
	}
	if cnt, _ := is.Count(); cnt != 2 {
		t.Fatalf("count = %d", cnt)
	}

	if err := is.Tag("appa:v1", "appa:latest"); err != nil {
		t.Fatal(err)
	}

	if err := is.Remove("appb:v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := is.Get("appa:latest"); err != nil {
		t.Fatalf("appa lost: %v", err)
	}

	ai, err := is.Get("appa:latest")
	if err != nil {
		t.Fatal(err)
	}
	wantFile := []string{"etc/base.conf", "etc/a.conf"}
	if len(ai.Layers) != len(wantFile) {
		t.Fatalf("appa has %d layers", len(ai.Layers))
	}
	for i, d := range ai.Layers {
		dir, err := is.Store().EnsureLayer(d)
		if err != nil {
			t.Fatalf("layer %s lost while still tagged: %v", d, err)
		}
		if _, err := os.Stat(filepath.Join(dir, wantFile[i])); err != nil {
			t.Errorf("%s missing in layer tree %s", wantFile[i], dir)
		}
	}

	if err := is.Remove("appa:latest"); err != nil {
		t.Fatal(err)
	}
	if err := is.Remove("appa:v1"); err != nil {
		t.Fatal(err)
	}
	if cnt, _ := is.Count(); cnt != 0 {
		t.Fatalf("expected no images after removing tags, got %d", cnt)
	}
}

func TestGarbageCollection(t *testing.T) {
	is := newTestStore(t)
	layout := t.TempDir()
	twoLayerImage(layout, "gcimg:latest")
	if _, err := is.ImportLayout(layout, ImportOptions{Tag: "gcimg:latest"}); err != nil {
		t.Fatal(err)
	}

	gc, err := is.GC()
	if err != nil {
		t.Fatal(err)
	}
	if gc.Blobs != 0 || gc.Layers != 0 || gc.Tags != 0 {
		t.Fatalf("GC removed referenced content: %+v", gc)
	}

	m, _, err := is.Assemble("cid", "gcimg:latest", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"etc/base.conf", "etc/app.conf"} {
		if _, err := os.Stat(filepath.Join(m.Rootfs, f)); err != nil {
			t.Errorf("container rootfs missing %s: %v", f, err)
		}
	}
	if err := os.WriteFile(filepath.Join(m.Rootfs, "etc/app.conf"), []byte("edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := is.Disassemble("cid"); err != nil {
		t.Fatal(err)
	}
	if err := is.Remove("gcimg:latest"); err != nil {
		t.Fatal(err)
	}
	gc, err = is.GC()
	if err != nil {
		t.Fatal(err)
	}
	if gc.Layers != 0 {
		t.Fatalf("GC removed container-pinned layers: %+v", gc)
	}
	gc, err = is.GC()
	if err != nil {
		t.Fatal(err)
	}
	if gc.Blobs != 0 {
		t.Fatalf("second GC removed content: %+v", gc)
	}
	if err := is.Delete("cid"); err != nil {
		t.Fatal(err)
	}
	gc, err = is.GC()
	if err != nil {
		t.Fatal(err)
	}
	if gc.Blobs == 0 || gc.Layers == 0 {
		t.Fatalf("GC did not reclaim unreferenced content: %+v", gc)
	}
	if gc.Tags != 0 {
		t.Errorf("unexpected tag pruning: %+v", gc)
	}
}

func TestGCPrunesBrokenTag(t *testing.T) {
	is := newTestStore(t)
	layout := t.TempDir()
	twoLayerImage(layout, "broken:latest")
	if _, err := is.ImportLayout(layout, ImportOptions{Tag: "broken:latest"}); err != nil {
		t.Fatal(err)
	}
	img, err := is.Get("broken:latest")
	if err != nil {
		t.Fatal(err)
	}
	if err := is.Store().RemoveBlob(img.Digest); err != nil {
		t.Fatal(err)
	}
	gc, err := is.GC()
	if err != nil {
		t.Fatal(err)
	}
	if gc.Tags != 1 {
		t.Fatalf("GC should prune the broken tag, got %+v", gc)
	}
	if cnt, _ := is.Count(); cnt != 0 {
		t.Fatalf("count = %d after pruning", cnt)
	}
}

func TestAssembleRejectsBadID(t *testing.T) {
	is := newTestStore(t)
	for _, id := range []string{"", "..", "a/b", "../escape", "a\\b"} {
		if _, _, err := is.Assemble(id, "anything", false); err == nil {
			t.Errorf("Assemble(%q) should be rejected", id)
		}
		if err := is.Disassemble(id); err == nil {
			t.Errorf("Disassemble(%q) should be rejected", id)
		}
	}
}

func TestConcurrentImportsAndTags(t *testing.T) {
	is := newTestStore(t)
	layout := t.TempDir()
	twoLayerImage(layout, "shared:v1")

	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			tag := "shared:v1"
			if _, err := is.ImportLayout(layout, ImportOptions{Tag: tag}); err != nil {
				errCh <- err
			}
			if err := is.Tag(tag, "alias"); err != nil {
				errCh <- err
			}
			if _, err := is.List(); err != nil {
				errCh <- err
			}
			_ = n
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent op failed: %v", err)
	}
	if cnt, _ := is.Count(); cnt != 2 {
		t.Fatalf("expected 2 tags (shared:v1 + alias), got %d", cnt)
	}
}

func TestImagePersistenceAcrossReopen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	is, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	layout := t.TempDir()
	twoLayerImage(layout, "persist:v1")
	if _, err := is.ImportLayout(layout, ImportOptions{Tag: "persist:v1"}); err != nil {
		t.Fatal(err)
	}
	is2, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	img, err := is2.Get("persist:v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Layers) != 2 {
		t.Fatalf("reopened image has %d layers", len(img.Layers))
	}
	for _, d := range img.Layers {
		if _, err := is2.Store().EnsureLayer(d); err != nil {
			t.Fatalf("layer not available after reopen: %v", err)
		}
	}
}
