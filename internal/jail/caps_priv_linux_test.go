//go:build linux && jailor_priv

package jail

import (
	"os"
	"strings"
	"syscall"
	"testing"

	"jailor/internal/bars"
)

func TestCapabilitySetsAfterPolicy(t *testing.T) {
	if os.Geteuid() != 0 && !canUseNamespaces() {
		t.Fatalf("the capability policy needs a user namespace, euid is %d", os.Geteuid())
	}
	out, code := runConfigured(t, &InitConfig{
		Args:         []string{testExe, "__probe", "caps"},
		Capabilities: []string{"CAP_CHOWN", "CAP_KILL"},
	}, true)
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)
	wantEff := "0000000000000021"
	if m["caps_capeff"] != wantEff {
		t.Errorf("CapEff = %q, want %q (CAP_CHOWN|CAP_KILL)", m["caps_capeff"], wantEff)
	}
	if m["caps_capprm"] != wantEff {
		t.Errorf("CapPrm = %q, want %q", m["caps_capprm"], wantEff)
	}
	if m["caps_capbnd"] != wantEff {
		t.Errorf("CapBnd = %q, want %q", m["caps_capbnd"], wantEff)
	}
	if m["caps_capinh"] != "0000000000000000" {
		t.Errorf("CapInh = %q, want 0", m["caps_capinh"])
	}
}

func TestNoCapabilitiesYieldsEmptySet(t *testing.T) {
	if os.Geteuid() != 0 && !canUseNamespaces() {
		t.Fatalf("the capability policy needs a user namespace, euid is %d", os.Geteuid())
	}
	out, code := runConfigured(t, &InitConfig{
		Args: []string{testExe, "__probe", "caps"},
	}, true)
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)
	for _, key := range []string{"caps_capeff", "caps_capprm", "caps_capbnd"} {
		if m[key] != "0000000000000000" {
			t.Errorf("%s = %q, want an empty set", key, m[key])
		}
	}
}

func TestUnknownCapabilityFailsClosed(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	out := &syncBuf{}
	cfg := &InitConfig{
		Args:         []string{testExe, "__probe", "caps"},
		Capabilities: []string{"CAP_MADE_UP"},
	}
	child, err := Spawn(SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      out,
		Stderr:      out,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}, cfg)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err == nil {
		t.Fatal("an invalid capability policy must fail closed before readiness")
	}
	if code := child.Wait(); code == 0 {
		t.Fatal("jail must exit non-zero when the capability policy is invalid")
	}
	if !strings.Contains(out.String(), "CAP_MADE_UP") {
		t.Errorf("failure must name the offending capability: %s", out.String())
	}
}
