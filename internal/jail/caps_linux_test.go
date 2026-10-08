//go:build linux

package jail

import (
	"sort"
	"strings"
	"testing"
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
