package security

import (
	"testing"

	"jailor/internal/idmap"
)

func TestAutoUsernsResolution(t *testing.T) {
	rootReport, err := Compile(Policy{Userns: UsernsAuto, Seccomp: SeccompNone},
		Context{}, Host{Root: true, UsernsSupported: true})
	if err != nil {
		t.Fatalf("rootful auto compile: %v", err)
	}
	if rootReport.UsernsMode != UsernsOff {
		t.Fatalf("rootful auto should resolve to off, got %q", rootReport.UsernsMode)
	}

	rootless := Host{Root: false, UsernsSupported: true,
		SubUID:       []idmap.Range{{Start: 100000, Size: 65536}},
		SubGID:       []idmap.Range{{Start: 100000, Size: 65536}},
		HasNewUIDMap: true,
		HasNewGIDMap: true,
	}
	rootlessReport, err := Compile(Policy{Userns: UsernsAuto, Seccomp: SeccompNone},
		Context{}, rootless)
	if err != nil {
		t.Fatalf("rootless auto compile: %v", err)
	}
	if rootlessReport.UsernsMode != UsernsOn {
		t.Fatalf("rootless auto should resolve to on, got %q", rootlessReport.UsernsMode)
	}
	if !rootlessReport.UsernsApplied {
		t.Fatal("rootless auto with subordinate ranges should be applied")
	}
	if len(rootlessReport.UidRanges) == 0 || len(rootlessReport.GidRanges) == 0 {
		t.Fatal("rootless report must carry UID/GID ranges")
	}
}

func TestRootlessWithoutSubordinateRanges(t *testing.T) {
	host := Host{Root: false, UsernsSupported: true}
	report, err := Compile(Policy{Userns: UsernsOn, Seccomp: SeccompNone}, Context{}, host)
	if err == nil {
		t.Fatal("userns on without subordinate ranges must be refused")
	}
	if !IsUnavailable(err) {
		t.Fatalf("want typed *Unavailable, got %v", err)
	}
	if report == nil || report.Unavailable == nil {
		t.Fatal("report must carry the unavailable feature")
	}
}

func TestStrictSeccompImpliesNoNewPrivs(t *testing.T) {
	report, err := Compile(Policy{Userns: UsernsOff, Seccomp: SeccompStrict},
		Context{}, Host{Root: true, UsernsSupported: true})
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	if !report.SeccompApplied || report.SeccompProfile != SeccompStrict {
		t.Fatalf("strict profile not applied: %+v", report)
	}
	if !report.NoNewPrivsApplied {
		t.Fatal("a seccomp filter must imply no_new_privs")
	}
}

func TestReadOnlyMapped(t *testing.T) {
	report, err := Compile(Policy{Userns: UsernsOff, Seccomp: SeccompNone, ReadOnly: true},
		Context{}, Host{Root: true, UsernsSupported: true})
	if err != nil {
		t.Fatalf("read-only compile: %v", err)
	}
	if !report.ReadOnlyApplied {
		t.Fatal("read-only request must be reported applied")
	}
}
