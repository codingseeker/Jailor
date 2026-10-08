//go:build linux

package jail

import (
	"os"
	"sort"
	"strings"
	"syscall"
	"testing"

	"jailor/internal/bars"
)

func TestCapMaskForNoCapabilities(t *testing.T) {
	mask, err := capMaskFor(nil)
	if err != nil {
		t.Fatalf("capMaskFor(nil): %v", err)
	}
	if mask != 0 {
		t.Errorf("no requested capabilities must yield an empty mask, got %#x", mask)
	}
}

func TestCapMaskForSingleCapability(t *testing.T) {
	mask, err := capMaskFor([]string{"CAP_CHOWN"})
	if err != nil {
		t.Fatalf("capMaskFor(CAP_CHOWN): %v", err)
	}
	if mask != 1 {
		t.Errorf("CAP_CHOWN mask = %#x, want 0x1", mask)
	}
}

func TestCapMaskForMultipleCapabilities(t *testing.T) {
	mask, err := capMaskFor([]string{"CAP_CHOWN", "CAP_KILL", "CAP_NET_RAW"})
	if err != nil {
		t.Fatalf("capMaskFor: %v", err)
	}
	want := uint64(1) | uint64(1)<<5 | uint64(1)<<13
	if mask != want {
		t.Errorf("mask = %#x, want %#x", mask, want)
	}
}

func TestCapMaskForHighestCapability(t *testing.T) {
	mask, err := capMaskFor([]string{"CAP_CHECKPOINT_RESTORE"})
	if err != nil {
		t.Fatalf("capMaskFor: %v", err)
	}
	if mask != uint64(1)<<capNumberOrFail(t, "CAP_CHECKPOINT_RESTORE") {
		t.Errorf("mask = %#x for the highest capability", mask)
	}
}

func capNumberOrFail(t *testing.T, name string) int {
	t.Helper()
	num, ok := capNumber(name)
	if !ok {
		t.Fatalf("capability %s is unknown", name)
	}
	return num
}

func TestCapMaskForInvalidCapability(t *testing.T) {
	for _, name := range []string{"CAP_NOT_REAL", "cap_chown", "", "CAP_", "CAP_CHOWNX"} {
		if _, err := capMaskFor([]string{name}); err == nil {
			t.Errorf("capability %q must be rejected", name)
		}
	}
}

func TestCapMaskRejectsInvalidAlongsideValid(t *testing.T) {
	mask, err := capMaskFor([]string{"CAP_CHOWN", "CAP_NOPE"})
	if err == nil {
		t.Fatalf("invalid capability in list must fail, got mask %#x", mask)
	}
	if mask != 0 {
		t.Errorf("mask must not be partially applied, got %#x", mask)
	}
	if !strings.Contains(err.Error(), "CAP_NOPE") {
		t.Errorf("error must name the offending capability: %v", err)
	}
}

func TestCapMaskForDuplicateCapabilities(t *testing.T) {
	once, err := capMaskFor([]string{"CAP_CHOWN"})
	if err != nil {
		t.Fatal(err)
	}
	twice, err := capMaskFor([]string{"CAP_CHOWN", "CAP_CHOWN"})
	if err != nil {
		t.Fatal(err)
	}
	if once != twice {
		t.Errorf("duplicates changed the mask: %#x vs %#x", once, twice)
	}
}

func TestCapMaskCoversEveryKnownCapability(t *testing.T) {
	names := knownCapabilityNames()
	if len(names) != len(capNames) {
		t.Fatalf("knownCapabilityNames returned %d names, want %d", len(names), len(capNames))
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("capability names must be reported in a stable order: %v", names)
	}
	mask, err := capMaskFor(names)
	if err != nil {
		t.Fatalf("every known capability must be accepted: %v", err)
	}
	var want uint64
	for _, num := range capNames {
		want |= 1 << uint(num)
	}
	if mask != want {
		t.Errorf("full mask = %#x, want %#x", mask, want)
	}
}

func TestCapNameLookup(t *testing.T) {
	for name, num := range capNames {
		got, ok := capNumber(name)
		if !ok || got != num {
			t.Errorf("capNumber(%q) = %d, %v, want %d, true", name, got, ok, num)
		}
		if capNameOf(num) != name {
			t.Errorf("capNameOf(%d) = %q, want %q", num, capNameOf(num), name)
		}
	}
}

func TestCapNumberUnknown(t *testing.T) {
	if _, ok := capNumber("CAP_DOES_NOT_EXIST"); ok {
		t.Error("unknown capability must not resolve")
	}
}

func TestApplyCapabilityPolicyRejectsUnknown(t *testing.T) {
	if err := applyCapabilityPolicy([]string{"CAP_IMAGINARY"}); err == nil {
		t.Error("applyCapabilityPolicy must reject an unknown capability")
	}
}

func TestApplyCapabilityPolicyRejectsInvalidTransition(t *testing.T) {
	if _, err := capMaskFor([]string{"CAP_NOT_A_REAL_NAME"}); err == nil {
		t.Error("an impossible capability transition must be reported")
	}
}

func TestCapabilitySetsAfterPolicy(t *testing.T) {
	if os.Geteuid() != 0 && !canUseNamespaces() {
		t.Skip("capability policy needs a user namespace")
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
		t.Skip("capability policy needs a user namespace")
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
		t.Skip("environment cannot create namespaces")
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
