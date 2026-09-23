package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCLILayout(t *testing.T, dir, tag string, files map[string]string) {
	t.Helper()
	writeBlobAt := func(data []byte) string {
		sum := sha256.Sum256(data)
		if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "blobs", "sha256", hex.EncodeToString(sum[:])), data, 0o644); err != nil {
			t.Fatal(err)
		}
		return "sha256:" + hex.EncodeToString(sum[:])
	}

	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, name := range []string{"bin/sh", "etc/os-release"} {
		content := "jailor-test\n"
		if name == "bin/sh" {
			content = "#!/bin/sh\nexit 0\n"
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(content))
	}
	tw.Close()
	sum := sha256.Sum256(raw.Bytes())
	diffID := "sha256:" + hex.EncodeToString(sum[:])
	var comp bytes.Buffer
	gz := gzip.NewWriter(&comp)
	gz.Write(raw.Bytes())
	gz.Close()
	layerDigest := writeBlobAt(comp.Bytes())

	cfgData := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["` + diffID + `"]},"config":{"Cmd":["/bin/sh"]}}`)
	cfgDigest := writeBlobAt(cfgData)

	man := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    cfgDigest,
			"size":      len(cfgData),
		},
		"layers": []map[string]any{{
			"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest":    layerDigest,
			"size":      comp.Len(),
		}},
	}
	manData, _ := json.Marshal(man)
	manDigest := writeBlobAt(manData)

	idx := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]any{{
			"mediaType":   "application/vnd.oci.image.manifest.v1+json",
			"digest":      manDigest,
			"size":        len(manData),
			"annotations": map[string]string{"org.opencontainers.image.ref.name": tag},
		}},
	}
	idxData, _ := json.Marshal(idx)
	if err := os.WriteFile(filepath.Join(dir, "index.json"), idxData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestImageImportListInspectGc(t *testing.T) {
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	layout := t.TempDir()
	writeCLILayout(t, layout, "app:v1", nil)

	out, code := runCLI(t, ledgerDir, "image", "import", "--tag", "app:v1", layout)
	if code != 0 {
		t.Fatalf("import code = %d, out=%s", code, out)
	}
	if !strings.Contains(out, "imported app:v1") {
		t.Errorf("import output: %s", out)
	}

	out, code = runCLI(t, ledgerDir, "images")
	if code != 0 || !strings.Contains(out, "app") {
		t.Fatalf("images code = %d, out=%s", code, out)
	}

	out, code = runCLI(t, ledgerDir, "image", "inspect", "app:v1")
	if code != 0 || !strings.Contains(out, "amd64") {
		t.Fatalf("inspect code = %d, out=%s", code, out)
	}
	if !strings.Contains(out, "Image") && !strings.Contains(out, "Layer") {
		t.Errorf("inspect should show image metadata: %s", out)
	}

	out, code = runCLI(t, ledgerDir, "image", "gc")
	if code != 0 {
		t.Fatalf("gc code = %d, out=%s", code, out)
	}
	if !strings.Contains(out, "no unreferenced") && !strings.Contains(out, "reclaimed 0") {
		if strings.Contains(out, "0 blob") && !strings.Contains(out, "reclaimed 0") {
			t.Errorf("gc unexpectedly reclaimed content: %s", out)
		}
	}

	out, code = runCLI(t, ledgerDir, "image", "tag", "app:v1", "alias:latest")
	if code != 0 {
		t.Fatalf("tag code = %d, out=%s", code, out)
	}
	out, code = runCLI(t, ledgerDir, "images")
	if code != 0 || !strings.Contains(out, "alias") {
		t.Fatalf("images after tag code = %d, out=%s", code, out)
	}

	out, code = runCLI(t, ledgerDir, "image", "rm", "alias:latest")
	if code != 0 {
		t.Fatalf("rm code = %d, out=%s", code, out)
	}
	out, code = runCLI(t, ledgerDir, "images")
	if code != 0 || strings.Contains(out, "alias") {
		t.Fatalf("images after rm code = %d, out=%s", code, out)
	}
	if !strings.Contains(out, "app") {
		t.Errorf("app image should remain: %s", out)
	}

	out, code = runCLI(t, ledgerDir, "image", "rm", "app:v1")
	if code != 0 {
		t.Fatalf("rm code = %d, out=%s", code, out)
	}
	out, code = runCLI(t, ledgerDir, "images")
	if code != 0 || !strings.Contains(out, "no images yet") {
		t.Fatalf("images after final rm code = %d, out=%s", code, out)
	}

	out, code = runCLI(t, ledgerDir, "image", "gc")
	if code != 0 {
		t.Fatalf("gc after rm code = %d, out=%s", code, out)
	}
	if !strings.Contains(out, "reclaimed") {
		t.Errorf("gc output: %s", out)
	}
}

func TestImageImportMissingLayout(t *testing.T) {
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	_, code := runCLI(t, ledgerDir, "image", "import", filepath.Join(t.TempDir(), "nope"))
	if code == 0 {
		t.Error("importing a missing layout should fail")
	}
}

func TestImageUnknownRefs(t *testing.T) {
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	_, code := runCLI(t, ledgerDir, "images")
	if code != 0 {
		t.Errorf("images on empty store code = %d", code)
	}
	_, code = runCLI(t, ledgerDir, "image", "inspect", "missing:latest")
	if code == 0 {
		t.Error("inspecting a missing image should fail")
	}
	_, code = runCLI(t, ledgerDir, "image", "rm", "missing:latest")
	if code == 0 {
		t.Error("removing a missing image should fail")
	}
}

func TestRunImageProjectionUnused(t *testing.T) {
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	layout := t.TempDir()
	writeCLILayout(t, layout, "x:v1", nil)
	if _, code := runCLI(t, ledgerDir, "image", "import", "--tag", "x:v1", layout); code != 0 {
		t.Fatal("import failed")
	}
	out, code := runCLI(t, ledgerDir, "images", "--ledger", ledgerDir)
	if code != 0 || !strings.Contains(out, "x") {
		t.Fatalf("images --ledger code = %d, out=%s", code, out)
	}
}

func TestInspectImageCommandAlias(t *testing.T) {
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	layout := t.TempDir()
	writeCLILayout(t, layout, "insp:v1", nil)
	if _, code := runCLI(t, ledgerDir, "image", "import", "--tag", "insp:v1", layout); code != 0 {
		t.Fatal("import failed")
	}
	out, code := runCLI(t, ledgerDir, "inspect", "image", "insp:v1")
	if code != 0 || !strings.Contains(out, "Digest") || !strings.Contains(out, "Layer") {
		t.Fatalf("inspect image code = %d, out=%s", code, out)
	}
	_, code = runCLI(t, ledgerDir, "inspect", "not-a-jail")
	if code == 0 {
		t.Error("inspect of an unknown jail should fail")
	}
	_, code = runCLI(t, ledgerDir, "inspect")
	if code == 0 {
		t.Error("inspect with no target should fail")
	}
}

func TestImageBackedJailLifecycle(t *testing.T) {
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	layout := t.TempDir()
	writeCLILayout(t, layout, "lcimg:latest", nil)
	if _, code := runCLI(t, ledgerDir, "image", "import", "--tag", "lcimg:latest", layout); code != 0 {
		t.Fatal("import failed")
	}

	out, code := runCLI(t, ledgerDir, "jail", "create", "--image", "lcimg:latest", "--", "/bin/sh")
	if code != 0 {
		t.Fatalf("jail create --image code = %d, out=%s", code, out)
	}
	id := strings.TrimSpace(out)
	if id == "" {
		t.Fatal("no jail id")
	}
	recPath := filepath.Join(ledgerDir, id, "jail.json")
	data, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"image": "lcimg:latest"`) {
		t.Errorf("record missing image ref:\n%s", string(data))
	}
	if !strings.Contains(string(data), "store/containers") || !strings.Contains(string(data), "rootfs") {
		t.Errorf("record missing assembled image rootfs:\n%s", string(data))
	}
	inspect, icode := runCLI(t, ledgerDir, "jail", "inspect", id)
	if icode != 0 {
		t.Fatalf("inspect code = %d, out=%s", icode, inspect)
	}
	if !strings.Contains(inspect, "lcimg:latest") {
		t.Errorf("inspect should show image ref: %s", inspect)
	}
	del, dcode := runCLI(t, ledgerDir, "jail", "delete", id)
	if dcode != 0 {
		t.Fatalf("delete code = %d, out=%s", dcode, del)
	}
	storeContainers := filepath.Join(ledgerDir, "store", "containers", id)
	if _, err := os.Stat(storeContainers); !os.IsNotExist(err) {
		t.Errorf("container filesystem should be released on delete (stat err=%v)", err)
	}
	gc, gcode := runCLI(t, ledgerDir, "image", "gc")
	if gcode != 0 {
		t.Fatalf("gc code = %d", gcode)
	}
	if strings.Contains(gc, "reclaimed 2") || strings.Contains(gc, "reclaimed 1") {
		t.Errorf("gc reclaimed still-tagged image content: %s", gc)
	}
}

func TestImageBackedJailRootfsConflict(t *testing.T) {
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	layout := t.TempDir()
	writeCLILayout(t, layout, "conflict:v1", nil)
	if _, code := runCLI(t, ledgerDir, "image", "import", "--tag", "conflict:v1", layout); code != 0 {
		t.Fatal("import failed")
	}
	_, code := runCLI(t, ledgerDir, "jail", "create", "--image", "conflict:v1", "--rootfs", t.TempDir(), "--", "/bin/sh")
	if code == 0 {
		t.Error("jail create with both --image and --rootfs should fail")
	}
}
