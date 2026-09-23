package cell

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewRejectsHostRoot(t *testing.T) {
	if _, err := New("/", false); err == nil {
		t.Error("New('/') should refuse to use the host root as a Cell")
	}
}

func TestNewRejectsEmpty(t *testing.T) {
	if _, err := New("", false); err == nil {
		t.Error("New('') should error")
	}
}

func TestNewRejectsNonDirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(f, false); err == nil {
		t.Error("New(file) should error")
	}
}

func TestNewRejectsMissingRootfs(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "nope"), false); err == nil {
		t.Error("New(missing) should error")
	}
}

func TestNewValidAndResolves(t *testing.T) {
	dir := t.TempDir()
	c, err := New(dir, true)
	if err != nil {
		t.Fatalf("New valid: %v", err)
	}
	if !c.ReadOnly {
		t.Error("ReadOnly not preserved")
	}
	want, _ := filepath.Abs(dir)
	if c.Root != want {
		t.Errorf("Root = %q, want %q", c.Root, want)
	}
}

func TestValidateRejectsMissingShell(t *testing.T) {
	c := &Cell{Root: t.TempDir()}
	if c.ShellExists() {
		t.Error("empty root should not have /bin/sh")
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate on shell-less rootfs should fail")
	}
}

func TestValidateRejectsMissingLoader(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &Cell{Root: dir}
	if err := c.Validate(); err == nil {
		t.Error("Validate without a dynamic loader should fail")
	}
}

func TestValidateAcceptsShellAndLoader(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "lib64"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib64", "ld-linux-x86-64.so.2"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &Cell{Root: dir}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate with shell and loader should pass: %v", err)
	}
}

func TestCleanupSafety(t *testing.T) {
	if err := (&Cell{Root: "/"}).Cleanup(); err == nil {
		t.Error("Cleanup of host root should refuse")
	}
	if err := (&Cell{}).Cleanup(); err != nil {
		t.Errorf("Cleanup of empty cell should be a no-op: %v", err)
	}
	if err := (&Cell{Root: t.TempDir()}).Cleanup(); err != nil {
		t.Errorf("Cleanup of temp cell: %v", err)
	}
}
