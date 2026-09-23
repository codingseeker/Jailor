package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testLayer(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}

	for i := 0; i < len(paths); i++ {
		for j := i + 1; j < len(paths); j++ {
			if paths[j] < paths[i] {
				paths[i], paths[j] = paths[j], paths[i]
			}
		}
	}
	for _, p := range paths {
		content := files[p]
		if err := tw.WriteHeader(&tar.Header{
			Name:     p,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPutBlobAndDigestCalculation(t *testing.T) {
	s := openTestStore(t)
	d, err := s.PutBlob(bytes.NewReader([]byte("hello world")))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Valid() {
		t.Fatalf("bad digest %s", d)
	}
	if !s.HasBlob(d) {
		t.Fatal("blob should exist after PutBlob")
	}

	got, err := DigestOf(bytes.NewReader([]byte("hello world")))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != d.String() {
		t.Fatalf("digest = %s want %s", d, got)
	}

	if _, err := os.Stat(s.BlobPath(d)); err != nil {
		t.Fatal(err)
	}
}

func TestDigestMismatchDetected(t *testing.T) {
	s := openTestStore(t)
	d, err := s.PutBlob(bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(s.BlobPath(d), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyBlob(d); err == nil {
		t.Fatal("VerifyBlob should reject corrupted content")
	}
	if _, err := s.PutBlob(bytes.NewReader([]byte("payload2"))); err != nil {
		t.Fatal(err)
	}

	blob := testLayer(t, map[string]string{"a.txt": "a"})
	dl, _ := s.PutBlob(bytes.NewReader(blob))
	if err := os.WriteFile(s.BlobPath(dl), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureLayer(dl); err == nil {
		t.Fatal("EnsureLayer should reject corrupted layer blob")
	}
}

func TestDuplicateLayersDeduped(t *testing.T) {
	s := openTestStore(t)
	blob := testLayer(t, map[string]string{"f.txt": "same content"})
	d1, err := s.PutLayer(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	d2, err := s.PutLayer(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if d1.String() != d2.String() {
		t.Fatalf("identical blobs should share a digest: %s vs %s", d1, d2)
	}

	dir, err := s.EnsureLayer(d1)
	if err != nil {
		t.Fatal(err)
	}
	dir2, err := s.EnsureLayer(d2)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(dir) != filepath.Clean(dir2) {
		t.Fatalf("identical layers should share one tree: %s vs %s", dir, dir2)
	}
}

func TestInterruptedWritesCleaned(t *testing.T) {
	s := openTestStore(t)

	leftovers := []string{
		filepath.Join(s.BlobsDir(), ".tmp-abc123"),
		filepath.Join(s.Root, ".tmp-other"),
	}
	for _, p := range leftovers {
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	old := s.Root
	if _, err := Open(old); err != nil {
		t.Fatal(err)
	}
	for _, p := range leftovers {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("leftover temp %s should be removed on open", p)
		}
	}

	partial := filepath.Join(s.BlobsDir(), "dst")
	tmp, _ := os.CreateTemp(s.BlobsDir(), ".tmp-*")
	tmp.WriteString("junk")
	tmp.Close()
	if err := os.Rename(tmp.Name(), partial); err != nil {
		t.Fatal(err)
	}

	if err := AtomicWrite(partial, []byte("complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(partial)
	if string(data) != "complete" {
		t.Fatalf("AtomicWrite left stale content %q", data)
	}
}

func TestExtractionRejectsTraversal(t *testing.T) {
	s := openTestStore(t)
	for _, name := range []string{"../escape.txt", "/absolute.txt", "a/../../b.txt"} {
		blob := testLayer(t, map[string]string{name: "evil"})
		if _, err := s.PutLayer(bytes.NewReader(blob)); err != nil {

		}
	}

	evil := buildTar(t, "/etc/passwd", "root:x:0:0")
	d, err := s.PutLayer(bytes.NewReader(evil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureLayer(d); err == nil {
		t.Fatal("extraction should reject absolute member names")
	}
}

func buildTar(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte(content))
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestSharedLowerLayersIndependentWritable(t *testing.T) {
	s := openTestStore(t)
	base := testLayer(t, map[string]string{"base.txt": "base", "shared.txt": "shared"})
	extra := testLayer(t, map[string]string{"extra.txt": "extra"})
	dbase, _ := s.PutBlob(bytes.NewReader(base))
	dextra, _ := s.PutBlob(bytes.NewReader(extra))
	if _, err := s.EnsureLayer(dbase); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureLayer(dextra); err != nil {
		t.Fatal(err)
	}
	baseDir := s.LayerDir(dbase)

	for _, id := range []string{"cA", "cB"} {
		m, err := s.MountContainerFS(id, []Digest{dbase, dextra}, false)
		if err != nil {
			t.Fatal(err)
		}
		if m.Rootfs == "" {
			t.Fatal("no rootfs from mount")
		}

		for _, want := range []string{"base.txt", "extra.txt", "shared.txt"} {
			if _, err := os.Stat(filepath.Join(m.Rootfs, want)); err != nil {
				t.Errorf("container %s missing %s: %v", id, want, err)
			}
		}

		if m.Driver == "overlay" || m.Driver == "copy" {
			write, err := os.Create(filepath.Join(m.Rootfs, "shared.txt"))
			if err != nil {
				t.Fatal(err)
			}
			write.WriteString("modified by A")
			write.Close()
		}
		if err := s.UnmountContainerFS(id); err != nil {
			t.Fatal(err)
		}
	}

	data, err := os.ReadFile(filepath.Join(baseDir, "shared.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "shared" {
		t.Fatalf("immutable lower layer was modified: %q", data)
	}

	mB, err := s.MountContainerFS("cB", []Digest{dbase, dextra}, false)
	if err != nil {
		t.Fatal(err)
	}
	if mB.Driver == "copy" {

	} else if data, err := os.ReadFile(filepath.Join(mB.Rootfs, "shared.txt")); err == nil && string(data) == "modified by A" {

		t.Fatalf("container B saw container A's write (upper isolation broken)")
	}
	if err := s.DeleteContainerFS("cA"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteContainerFS("cB"); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlyRootfs(t *testing.T) {
	s := openTestStore(t)
	blob := testLayer(t, map[string]string{"ro.txt": "ro"})
	d, _ := s.PutBlob(bytes.NewReader(blob))
	m, err := s.MountContainerFS("ro", []Digest{d}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !m.ReadOnly {
		t.Fatal("read-only requested but mount reports writable")
	}
	if err := s.UnmountContainerFS("ro"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteContainerFS("ro"); err != nil {
		t.Fatal(err)
	}

}

func TestStorageRecovery(t *testing.T) {
	s := openTestStore(t)
	blob := testLayer(t, map[string]string{"x.txt": "x"})
	d, err := s.PutBlob(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}

	dir := s.LayerDir(d)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "partial.txt"), []byte("p"), 0o644)

	if _, err := s.EnsureLayer(d); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".complete")); err != nil {
		t.Fatal("re-extraction should mark the layer complete")
	}
	if _, err := os.Stat(filepath.Join(dir, "x.txt")); err != nil {
		t.Fatal("extracted content missing after recovery")
	}
}

func TestConcurrentLayerCreation(t *testing.T) {
	s := openTestStore(t)
	blob := testLayer(t, map[string]string{"c.txt": "concurrent"})
	const n = 10
	digests := make(chan Digest, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d2, e := s.PutLayer(bytes.NewReader(blob))
			if e != nil {
				errs <- e
				return
			}
			digests <- d2
		}()
	}
	wg.Wait()
	close(digests)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for d := range digests {
		seen[d.String()] = true
	}
	if len(seen) != 1 {
		t.Fatalf("identical concurrent layers must dedupe to one digest, got %v", seen)
	}
	var d Digest
	for s := range seen {
		d = MustDigest(s)
		break
	}
	dir, err := s.EnsureLayer(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "c.txt")); err != nil {
		t.Fatal(err)
	}

	if err := s.RemoveBlob(d); err != nil {
		t.Fatal(err)
	}
}

func TestDiffID(t *testing.T) {
	s := openTestStore(t)
	blob := testLayer(t, map[string]string{"d.txt": "diffid"})
	d, err := s.PutBlob(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	diff, err := s.DiffID(d)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Valid() {
		t.Fatal("invalid diff id")
	}

	tarBytes := testLayerRaw(t, "d.txt", "diffid")
	want, _ := DigestOf(bytes.NewReader(tarBytes))
	if diff.String() != want.String() {
		t.Fatalf("diff = %s want %s", diff, want)
	}
}

func TestLayerDigestsAndRemoveBlob(t *testing.T) {
	s := openTestStore(t)
	blob := testLayer(t, map[string]string{"r.txt": "r"})
	d, _ := s.PutBlob(bytes.NewReader(blob))
	if _, err := s.EnsureLayer(d); err != nil {
		t.Fatal(err)
	}
	digs, err := s.LayerDigests()
	if err != nil {
		t.Fatal(err)
	}
	if len(digs) != 1 || digs[0].String() != d.String() {
		t.Fatalf("LayerDigests = %v want [%s]", digs, d)
	}
	if err := s.RemoveBlob(d); err != nil {
		t.Fatal(err)
	}
	digs, _ = s.LayerDigests()
	if len(digs) != 0 {
		t.Fatalf("layer should be gone after RemoveBlob, got %v", digs)
	}
	if s.HasBlob(d) {
		t.Fatal("blob should be gone after RemoveBlob")
	}
}

func TestBlobWriteTempCleanupOnError(t *testing.T) {
	s := openTestStore(t)

	bad := io.MultiReader(bytes.NewReader([]byte("partial data")), errReader{})
	if _, err := s.PutBlob(bad); err == nil {
		t.Fatal("PutBlob should propagate reader error")
	}
	entries, err := os.ReadDir(s.BlobsDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("failed write left temp file %s", e.Name())
		}
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, fmt.Errorf("boom") }

func testLayerRaw(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestConcurrentOverlayMounts(t *testing.T) {
	s := openTestStore(t)
	base := testLayer(t, map[string]string{"common.txt": "common"})
	dbase, _ := s.PutBlob(bytes.NewReader(base))
	if _, err := s.EnsureLayer(dbase); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("c%d", n)
			m, err := s.MountContainerFS(id, []Digest{dbase}, false)
			if err != nil {
				errs <- err
				return
			}
			if _, err := os.Stat(filepath.Join(m.Rootfs, "common.txt")); err != nil {
				errs <- fmt.Errorf("container %s missing file: %v", id, err)
			}
			if err := s.UnmountContainerFS(id); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
