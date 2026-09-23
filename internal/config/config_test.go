package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestDefault(t *testing.T) {
	c := Default()
	if c.Version != Version {
		t.Errorf("default version = %d, want %d", c.Version, Version)
	}
	if len(c.Bars.Namespaces) == 0 {
		t.Error("default should enable namespace bars")
	}
	if c.Gate.Mode == "" {
		t.Error("default gate mode should not be empty")
	}
	if c.Cell.WorkDir != "/" {
		t.Errorf("default workdir = %q, want /", c.Cell.WorkDir)
	}
	c.Command = []string{"/bin/true"}
	if err := c.Validate(); err != nil {
		t.Errorf("default config should validate: %v", err)
	}
}

func TestValidateCommandRequired(t *testing.T) {
	c := Default()
	c.Command = nil
	if err := c.Validate(); err == nil {
		t.Error("config without command should fail validation")
	}
}

func TestValidateVersion(t *testing.T) {
	c := Default()
	c.Version = 99
	if err := c.Validate(); err == nil {
		t.Error("config with unsupported version should fail validation")
	}
}

func TestValidateEnv(t *testing.T) {
	good := []string{"A=1", "B=two=three", "HOME=/root"}
	for _, e := range good {
		c := Default()
		c.Command = []string{"/bin/true"}
		c.Cell.Env = []string{e}
		if err := c.Validate(); err != nil {
			t.Errorf("env %q should validate: %v", e, err)
		}
	}
	bad := []string{"NOEQUALS", "=value", "A\x00=1"}
	for _, e := range bad {
		c := Default()
		c.Command = []string{"/bin/true"}
		c.Cell.Env = []string{e}
		if err := c.Validate(); err == nil {
			t.Errorf("env %q should fail validation", e)
		}
	}
}

func TestValidateBarKinds(t *testing.T) {
	c := Default()
	c.Bars.Namespaces = []string{"pid", "bogus"}
	if err := c.Validate(); err == nil {
		t.Error("config with unknown bar should fail validation")
	}
}

func TestValidateGateMode(t *testing.T) {
	c := Default()
	c.Gate.Mode = "sidewinder"
	if err := c.Validate(); err == nil {
		t.Error("config with invalid gate mode should fail validation")
	}
}

func TestValidateUserns(t *testing.T) {
	c := Default()
	c.Privileges.Userns = "sometimes"
	if err := c.Validate(); err == nil {
		t.Error("config with invalid userns policy should fail validation")
	}
}

func TestLoadAndValidation(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "jail.json", `{
	  "version": 1,
	  "command": ["/bin/echo", "hello"],
	  "cell": {"workdir": "/", "readOnly": true},
	  "bars": {"namespaces": ["pid", "uts", "mnt"]},
	  "gate": {"mode": "none"},
	  "privileges": {"userns": "on", "seccomp": true}
	}`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Version != 1 {
		t.Errorf("version = %d", c.Version)
	}
	if len(c.Command) != 2 || c.Command[0] != "/bin/echo" {
		t.Errorf("command = %v", c.Command)
	}
	if !c.Cell.ReadOnly {
		t.Error("readOnly should be true")
	}
	if !c.Privileges.Seccomp {
		t.Error("seccomp should be true")
	}
	if c.UsernsPolicy() != "on" {
		t.Errorf("userns policy = %q", c.UsernsPolicy())
	}
}

func TestLoadRejectsInvalidCommand(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "bad.json", `{"version":1}`)
	if _, err := Load(path); err == nil {
		t.Fatal("config without command should be rejected at load")
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("missing config should error")
	}
}

func TestCapabilityList(t *testing.T) {
	c := Default()
	c.Privileges.Capabilities = "all"
	if got := c.CapabilityList(); len(got) != 1 || got[0] != "all" {
		t.Errorf("CapabilityList(all) = %v", got)
	}
	c.Privileges.Capabilities = "CAP_CHOWN,CAP_KILL"
	got := c.CapabilityList()
	if len(got) != 2 {
		t.Errorf("CapabilityList = %v", got)
	}
}

func TestValidateRejectsUnknownCapability(t *testing.T) {
	c := Default()
	c.Command = []string{"/bin/true"}
	c.Privileges.Capabilities = "CAP_CHOWN,CAP_NOT_REAL"
	if err := c.Validate(); err == nil {
		t.Fatal("expected unknown capability to be rejected")
	}
	c.Privileges.Capabilities = "all"
	if err := c.Validate(); err != nil {
		t.Fatalf("'all' should validate: %v", err)
	}
}

func TestValidateHostnameBounds(t *testing.T) {
	c := Default()
	c.Command = []string{"/bin/true"}
	c.Cell.Hostname = string(make([]byte, 64))
	if err := c.Validate(); err == nil {
		t.Fatal("expected over-long hostname to be rejected")
	}
	c.Cell.Hostname = "\x00bad"
	if err := c.Validate(); err == nil {
		t.Fatal("expected NUL hostname to be rejected")
	}
	c.Cell.Hostname = "my-jail"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid hostname rejected: %v", err)
	}
}

func TestValidateCellImage(t *testing.T) {
	c := Default()
	c.Command = []string{"/bin/true"}
	c.Cell.Image = "myapp:v1"
	if err := c.Validate(); err != nil {
		t.Fatalf("cell.image should validate: %v", err)
	}
	c.Cell.Rootfs = "/some/rootfs"
	if err := c.Validate(); err == nil {
		t.Fatal("cell.rootfs and cell.image together should be rejected")
	}
	c.Cell.Rootfs = ""
	c.Cell.Image = "../escape"
	if err := c.Validate(); err == nil {
		t.Fatal("path-like image ref should be rejected")
	}
	c.Cell.Image = "/abs/path"
	if err := c.Validate(); err == nil {
		t.Fatal("absolute image ref should be rejected")
	}

	c2 := Default()
	c2.Cell.Image = "app:latest"
	c2.Command = []string{"/bin/sh"}
	if err := c2.Validate(); err != nil {
		t.Fatalf("valid config with image failed: %v", err)
	}
}

func TestValidateGateNetwork(t *testing.T) {
	c := Default()
	c.Command = []string{"/bin/true"}
	c.Gate.Mode = "bridge"
	c.Gate.Name = "mynet"
	c.Gate.Ports = []string{"8080:80"}
	c.Gate.DNS = []string{"1.1.1.1"}
	if err := c.Validate(); err != nil {
		t.Fatalf("bridge + name + ports + dns should validate: %v", err)
	}

	c.Gate.Name = "Bad"
	if err := c.Validate(); err == nil {
		t.Fatal("uppercase network name should be rejected")
	}
	c.Gate.Name = "mynet"
	c.Gate.Ports = []string{"0:80"}
	if err := c.Validate(); err == nil {
		t.Fatal("port 0 should be rejected")
	}
	c.Gate.Ports = []string{"web:80"}
	if err := c.Validate(); err == nil {
		t.Fatal("non-numeric host port should be rejected")
	}
	c.Gate.Ports = nil
	c.Gate.DNS = []string{"not-an-ip"}
	if err := c.Validate(); err == nil {
		t.Fatal("bad dns should be rejected")
	}

	c.Gate.DNS = nil
	c.Gate.Mode = "none"
	c.Gate.Name = "mynet"
	if err := c.Validate(); err == nil {
		t.Fatal("gate.name in none mode should be rejected")
	}
}
