package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"path/filepath"
	"testing"
)

func benchStore(b *testing.B) *Store {
	s, err := Open(filepath.Join(b.TempDir(), "store"))
	if err != nil {
		b.Fatal(err)
	}
	return s
}

func BenchmarkPutBlob(b *testing.B) {
	s := benchStore(b)
	payload := bytes.Repeat([]byte("jailor-blob-payload-"), 64)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.PutBlob(bytes.NewReader(payload)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPutLayer(b *testing.B) {
	s := benchStore(b)
	blob := benchLayer(b, map[string]string{
		"usr/bin/program": "#!/bin/sh\necho hello jailor\n",
		"etc/version.txt": "1.0.0\n",
	})
	b.SetBytes(int64(len(blob)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.PutLayer(bytes.NewReader(blob)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyBlob(b *testing.B) {
	s := benchStore(b)
	payload := bytes.Repeat([]byte("verify-me"), 4096)
	d, err := s.PutBlob(bytes.NewReader(payload))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.VerifyBlob(d); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEnsureLayer(b *testing.B) {
	s := benchStore(b)
	blob := benchLayer(b, map[string]string{
		"etc/passwd":   "root:x:0:0:root:/root:/bin/sh\n",
		"bin/sh":       "#!/bin/sh\n",
		"lib/ld.so":    "loader",
		"data/file.go": "// content",
	})
	d, err := s.PutLayer(bytes.NewReader(blob))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(blob)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.EnsureLayer(d); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDiffID(b *testing.B) {
	s := benchStore(b)
	blob := benchLayer(b, map[string]string{"a.txt": "diff id content"})
	d, err := s.PutLayer(bytes.NewReader(blob))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.DiffID(d); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMountContainerCopy(b *testing.B) {
	s := benchStore(b)
	blob := benchLayer(b, map[string]string{
		"etc/passwd":     "root:x:0:0:\n",
		"usr/share/file": "a modestly sized base file for the copy benchmark\n",
	})
	d, err := s.PutLayer(bytes.NewReader(blob))
	if err != nil {
		b.Fatal(err)
	}
	if _, err := s.EnsureLayer(d); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := "bench"
		if _, err := s.MountContainerFS(id, []Digest{d}, false); err != nil {
			b.Fatal(err)
		}
		if err := s.UnmountContainerFS(id); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBlobToDiskThroughput(b *testing.B) {
	s := benchStore(b)
	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	d, err := s.PutBlob(bytes.NewReader(payload))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.CopyBlobTo(d, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func benchLayer(b *testing.B, files map[string]string) []byte {
	b.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			b.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			b.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		b.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		b.Fatal(err)
	}
	return buf.Bytes()
}
