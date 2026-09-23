package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

func makeLayer(files map[string]string) (comp []byte, diffID string) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, name := range sortedKeys(files) {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(files[name])), Typeflag: tar.TypeReg,
		}); err != nil {
			panic(err)
		}
		tw.Write([]byte(files[name]))
	}
	tw.Close()
	h := sha256.Sum256(raw.Bytes())
	diffID = "sha256:" + hex.EncodeToString(h[:])
	var compBuf bytes.Buffer
	gz := gzip.NewWriter(&compBuf)
	gz.Write(raw.Bytes())
	gz.Close()
	return compBuf.Bytes(), diffID
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func writeBlob(dir string, data []byte) string {
	h := sha256.Sum256(data)
	hexStr := hex.EncodeToString(h[:])
	path := filepath.Join(dir, "blobs", "sha256", hexStr)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		panic(err)
	}
	return "sha256:" + hexStr
}

func writeLayout(dir, tag string, layers [][]byte, config ImageConfig) {
	var diffIDs []string
	var descriptors []Descriptor
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
		descriptors = append(descriptors, Descriptor{
			MediaType: MediaTypeOCILayerGzip,
			Digest:    writeBlob(dir, comp),
			Size:      int64(len(comp)),
		})
	}
	config.RootFS = ImageRootFS{Type: "layers", DiffIDs: diffIDs}
	if config.Architecture == "" {
		config.Architecture = "amd64"
	}
	if config.OS == "" {
		config.OS = "linux"
	}
	cfgData, _ := json.Marshal(config)
	cfgDigest := writeBlob(dir, cfgData)

	man := Manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config:        Descriptor{MediaType: MediaTypeOCIConfig, Digest: cfgDigest, Size: int64(len(cfgData))},
		Layers:        descriptors,
	}
	manData, _ := json.Marshal(man)
	manDigest := writeBlob(dir, manData)

	idx := Index{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIIndex,
		Manifests: []Descriptor{{
			MediaType:   MediaTypeOCIManifest,
			Digest:      manDigest,
			Size:        int64(len(manData)),
			Annotations: map[string]string{annotationRefName: tag},
		}},
	}
	idxData, _ := json.Marshal(idx)
	if err := os.WriteFile(filepath.Join(dir, "index.json"), idxData, 0o644); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		panic(err)
	}
}
func twoLayerImage(dir, tag string) {
	l1, _ := makeLayer(map[string]string{"etc/base.conf": "base\n"})
	l2, _ := makeLayer(map[string]string{"etc/app.conf": "app\n"})
	writeLayout(dir, tag, [][]byte{l1, l2}, ImageConfig{
		Created: "2024-01-01T00:00:00Z",
		Config:  RuntimeConfig{Env: []string{"PATH=/usr/bin:/bin"}, WorkingDir: "/", Cmd: []string{"/bin/sh"}},
	})
}
