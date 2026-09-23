package oci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailor/internal/config"
)

func writeBundle(t *testing.T, dir, configJSON string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, RootfsDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadBundle(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, `{
		"ociVersion": "1.0",
		"process": {
			"args": ["/bin/echo", "hello"],
			"cwd": "/app",
			"noNewPrivileges": true,
			"capabilities": {"bounding": ["CAP_CHOWN","CAP_SETUID"]}
		},
		"root": {"path": "rootfs", "readonly": true},
		"hostname": "oci-jail",
		"linux": {
			"namespaces": [{"type":"pid"},{"type":"mount"},{"type":"network"}],
			"resources": {
				"memory": {"limit": 268435456},
				"cpu": {"quota": 50000, "period": 100000},
				"pids": {"limit": 100}
			},
			"seccomp": true
		},
		"jailor": {"network": "bridge", "userns": "on"}
	}`)

	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	c := b.Config
	if c.Command[0] != "/bin/echo" || c.Command[1] != "hello" {
		t.Errorf("command = %v", c.Command)
	}
	if c.Cell.Rootfs != filepath.Join(dir, "rootfs") {
		t.Errorf("rootfs = %q, want bundle-relative %q", c.Cell.Rootfs, filepath.Join(dir, "rootfs"))
	}
	if !c.Cell.ReadOnly {
		t.Error("readonly not mapped")
	}
	if c.Cell.Hostname != "oci-jail" {
		t.Errorf("hostname = %q", c.Cell.Hostname)
	}
	if c.Gate.Mode != "bridge" {
		t.Errorf("network = %q, want bridge", c.Gate.Mode)
	}
	if c.Privileges.Userns != "on" {
		t.Errorf("userns = %q, want on", c.Privileges.Userns)
	}
	if !c.Privileges.NoNewPrivs || !c.Privileges.Seccomp {
		t.Error("noNewPrivs/seccomp not mapped")
	}
	if c.Rations.PIDs != 100 {
		t.Errorf("pids = %d, want 100", c.Rations.PIDs)
	}
	if got := c.Rations.CPUs; got < 0.49 || got > 0.51 {
		t.Errorf("cpu = %v, want ~0.5", got)
	}
	if !strings.Contains(c.Privileges.Capabilities, "CAP_CHOWN") {
		t.Errorf("capabilities = %q", c.Privileges.Capabilities)
	}

	if len(c.Bars.Namespaces) != 3 {
		t.Errorf("namespaces = %v", c.Bars.Namespaces)
	}
}

func TestLoadBundleMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nope")
	if _, err := LoadBundle(dir); err == nil {
		t.Fatal("expected error for missing bundle")
	}
}

func TestLoadBundleRejectsBadConfig(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, `{"ociVersion":"1.0","process":{"args":[]}}`)
	if _, err := LoadBundle(dir); err == nil {
		t.Fatal("expected error for config with no process args")
	}
}

func TestLoadBundleRejectsUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, `{"ociVersion":"9.9","process":{"args":["/bin/true"]}}`)
	if _, err := LoadBundle(dir); err == nil {
		t.Fatal("expected error for unknown ociVersion")
	}
}

func TestLoadBundleRejectsUnknownCapability(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, `{"ociVersion":"1.0","process":{"args":["/bin/true"],"capabilities":{"bounding":["CAP_BOGUS"]}}}`)
	if _, err := LoadBundle(dir); err == nil {
		t.Fatal("expected error for unknown capability")
	}
}

func TestLoadBundleDefaults(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, `{"ociVersion":"1.0","process":{"args":["/bin/true"]}}`)
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	c := b.Config
	if c.Cell.Rootfs != "" {
		t.Errorf("default rootfs = %q, want empty", c.Cell.Rootfs)
	}
	if c.Gate.Mode != "none" {
		t.Errorf("default network = %q, want none", c.Gate.Mode)
	}
	if c.Privileges.Userns != "auto" {
		t.Errorf("default userns = %q, want auto", c.Privileges.Userns)
	}
}

func TestLoadBundleMapsEnv(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, `{
		"ociVersion":"1.0",
		"process":{"args":["/bin/true"],"env":["A=1","B=two=three"]}
	}`)
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	c := b.Config
	if len(c.Cell.Env) != 2 || c.Cell.Env[0] != "A=1" || c.Cell.Env[1] != "B=two=three" {
		t.Errorf("env = %v, want [A=1 B=two=three]", c.Cell.Env)
	}
}

func TestLoadBundleRejectsUnsupported(t *testing.T) {
	cases := []struct {
		name, json string
		want       string
	}{
		{"terminal", `{"ociVersion":"1.0","process":{"args":["/bin/true"],"terminal":true}}`, "terminal"},
		{"consoleSize", `{"ociVersion":"1.0","process":{"args":["/bin/true"],"consoleSize":{"height":24,"width":80}}}`, "consoleSize"},
		{"user uid", `{"ociVersion":"1.0","process":{"args":["/bin/true"],"user":{"uid":1000,"gid":1000}}}`, "process.user"},
		{"umask", `{"ociVersion":"1.0","process":{"args":["/bin/true"],"user":{"umask":63}}}`, "umask"},
		{"additionalGids", `{"ociVersion":"1.0","process":{"args":["/bin/true"],"user":{"additionalGids":[100]}}}`, "additionalGids"},
		{"mounts", `{"ociVersion":"1.0","process":{"args":["/bin/true"]},"mounts":[{"destination":"/data","type":"bind","source":"/x"}]}`, "mounts"},
		{"hooks prestart", `{"ociVersion":"1.0","process":{"args":["/bin/true"]},"hooks":{"prestart":[{"path":"/bin/true"}]}}`, "hooks"},
		{"hooks poststop", `{"ociVersion":"1.0","process":{"args":["/bin/true"]},"hooks":{"poststop":[{"path":"/bin/true"}]}}`, "hooks"},
		{"cgroup namespace", `{"ociVersion":"1.0","process":{"args":["/bin/true"]},"linux":{"namespaces":[{"type":"cgroup"}]}}`, "namespaces type \"cgroup\""},
		{"unknown namespace", `{"ociVersion":"1.0","process":{"args":["/bin/true"]},"linux":{"namespaces":[{"type":"foobar"}]}}`, "namespaces type \"foobar\""},
		{"seccomp object", `{"ociVersion":"1.0","process":{"args":["/bin/true"]},"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW"}}}`, "seccomp"},
		{"uidMappings", `{"ociVersion":"1.0","process":{"args":["/bin/true"]},"linux":{"uidMappings":[{"containerID":0,"hostID":1000,"size":1}]}}`, "uidMappings"},
		{"gidMappings", `{"ociVersion":"1.0","process":{"args":["/bin/true"]},"linux":{"gidMappings":[{"containerID":0,"hostID":1000,"size":1}]}}`, "gidMappings"},
		{"sysctl", `{"ociVersion":"1.0","process":{"args":["/bin/true"]},"linux":{"sysctl":{"net.core.somaxconn":"1024"}}}`, "sysctl"},
		{"maskedPaths", `{"ociVersion":"1.0","process":{"args":["/bin/true"]},"linux":{"maskedPaths":["/proc/kcore"]}}`, "maskedPaths"},
		{"readonlyPaths", `{"ociVersion":"1.0","process":{"args":["/bin/true"]},"linux":{"readonlyPaths":["/proc/sys"]}}`, "readonlyPaths"},
		{"cpu shares", `{"ociVersion":"1.0","process":{"args":["/bin/true"]},"linux":{"resources":{"cpu":{"shares":1024}}}}`, "cpu.shares"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeBundle(t, dir, tc.json)
			_, err := LoadBundle(dir)
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

func TestLoadBundleMergesAllCapSets(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, `{
		"ociVersion":"1.0",
		"process":{"args":["/bin/true"],"capabilities":{
			"bounding":["CAP_CHOWN"],"effective":["CAP_SETUID"],
			"permitted":["CAP_SETGID"],"inheritable":["CAP_NET_RAW"]
		}}
	}`)
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	c := b.Config
	for _, want := range []string{"CAP_CHOWN", "CAP_SETUID", "CAP_SETGID", "CAP_NET_RAW"} {
		if !strings.Contains(c.Privileges.Capabilities, want) {
			t.Errorf("capabilities %q missing %s", c.Privileges.Capabilities, want)
		}
	}
}

func TestExportRoundTrip(t *testing.T) {
	c := config.Default()
	c.Command = []string{"/bin/echo", "hi"}
	c.Cell.WorkDir = "/app"
	c.Cell.Hostname = "roundtrip"
	c.Cell.ReadOnly = true
	c.Cell.Env = []string{"A=1", "B=2"}
	c.Bars.Namespaces = []string{"pid", "mnt", "uts"}
	c.Privileges.NoNewPrivs = true
	c.Privileges.Seccomp = true
	c.Privileges.Capabilities = "CAP_CHOWN,CAP_SETUID"
	c.Rations.Memory = "268435456"
	c.Rations.CPUs = 0.5
	c.Rations.PIDs = 100

	data, err := Export(&c)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	dir := t.TempDir()
	writeBundle(t, dir, string(data))

	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle(exported): %v\n%s", err, data)
	}
	got := b.Config
	if got.Cell.WorkDir != "/app" || got.Cell.Hostname != "roundtrip" {
		t.Errorf("cell mismatch: workdir=%q hostname=%q", got.Cell.WorkDir, got.Cell.Hostname)
	}
	if !got.Cell.ReadOnly {
		t.Error("readonly lost in round-trip")
	}
	if !got.Privileges.NoNewPrivs || !got.Privileges.Seccomp {
		t.Error("privileges lost in round-trip")
	}
	if got.Rations.CPUs < 0.49 || got.Rations.CPUs > 0.51 {
		t.Errorf("cpus = %v, want ~0.5", got.Rations.CPUs)
	}
	if got.Rations.PIDs != 100 {
		t.Errorf("pids = %d, want 100", got.Rations.PIDs)
	}
	if len(got.Cell.Env) != 2 || got.Cell.Env[0] != "A=1" {
		t.Errorf("env = %v, want [A=1 B=2]", got.Cell.Env)
	}
	for _, want := range []string{"CAP_CHOWN", "CAP_SETUID"} {
		if !strings.Contains(got.Privileges.Capabilities, want) {
			t.Errorf("caps %q missing %s", got.Privileges.Capabilities, want)
		}
	}
}

func TestExportRejectsInvalid(t *testing.T) {
	c := config.Default()
	c.Command = nil
	if _, err := Export(&c); err == nil {
		t.Fatal("expected error exporting a config with no command")
	}
}

func TestValidFixtureRoundTrip(t *testing.T) {
	dir := filepath.Join("testdata", "valid")
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle(testdata/valid): %v", err)
	}
	c := b.Config
	if c.Command[0] != "/bin/sleep" {
		t.Errorf("command = %v", c.Command)
	}
	if len(c.Cell.Env) != 2 || c.Cell.Env[0] != "JAILOR_FIXTURE=1" {
		t.Errorf("env = %v", c.Cell.Env)
	}
	if !c.Cell.ReadOnly || c.Cell.Hostname != "fixture" {
		t.Errorf("cell = %+v", c.Cell)
	}
	if c.Rations.PIDs != 100 || c.Rations.CPUs < 0.49 || c.Rations.CPUs > 0.51 {
		t.Errorf("rations = %+v", c.Rations)
	}
	if !c.Privileges.Seccomp || !c.Privileges.NoNewPrivs {
		t.Errorf("privileges = %+v", c.Privileges)
	}
	for _, want := range []string{"CAP_CHOWN", "CAP_SETUID"} {
		if !strings.Contains(c.Privileges.Capabilities, want) {
			t.Errorf("caps %q missing %s", c.Privileges.Capabilities, want)
		}
	}
	if len(c.Bars.Namespaces) != 3 {
		t.Errorf("namespaces = %v", c.Bars.Namespaces)
	}

	data, err := Export(c)
	if err != nil {
		t.Fatalf("Export(fixture config): %v", err)
	}
	tmp := t.TempDir()
	writeBundle(t, tmp, string(data))
	b2, err := LoadBundle(tmp)
	if err != nil {
		t.Fatalf("LoadBundle(exported fixture): %v\n%s", err, data)
	}
	c2 := b2.Config
	if c2.Cell.Hostname != "fixture" || c2.Rations.PIDs != 100 {
		t.Errorf("round-trip drift: hostname=%q pids=%d", c2.Cell.Hostname, c2.Rations.PIDs)
	}
}

func TestUnsupportedFixtureRejected(t *testing.T) {
	dir := filepath.Join("testdata", "unsupported")
	_, err := LoadBundle(dir)
	if err == nil {
		t.Fatal("testdata/unsupported must be rejected")
	}
	if !strings.Contains(err.Error(), "terminal") {
		t.Errorf("error %q does not name the terminal feature (individual unsupported features are table-tested in TestLoadBundleRejectsUnsupported)", err.Error())
	}
}
