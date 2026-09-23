package warden

import (
	"testing"

	"jailor/internal/jail"
	"jailor/internal/security"
)

func TestCompileSecurityNilPolicy(t *testing.T) {
	w := New(Options{})
	init := &jail.InitConfig{MountProc: true, SeccompProfile: security.SeccompNone}
	report, err := w.compileSecurity(init)
	if err != nil {
		t.Fatalf("nil policy must not error, got %v", err)
	}
	if report != nil {
		t.Fatalf("nil policy must not produce a report, got %+v", report)
	}
	if init.SeccompProfile != security.SeccompNone {
		t.Fatalf("nil policy must not mutate InitConfig, got seccomp=%q", init.SeccompProfile)
	}
}

func TestCompileSecurityStrictProfile(t *testing.T) {
	host := security.Host{
		Root:                    true,
		UsernsSupported:         true,
		MountNamespaceSupported: true,
	}
	report, err := security.Compile(security.Policy{
		Seccomp: security.SeccompStrict,
	}, security.Context{RequireMounts: true}, host)
	if err != nil {
		t.Fatalf("strict policy must compile on rootful host: %v", err)
	}
	if !report.SeccompApplied || report.SeccompProfile != security.SeccompStrict {
		t.Fatalf("strict profile not applied: applied=%v profile=%q",
			report.SeccompApplied, report.SeccompProfile)
	}
	if !report.NoNewPrivsApplied {
		t.Fatalf("seccomp filter must imply no_new_privs")
	}
}

func TestCompileSecurityCustomRejected(t *testing.T) {
	host := security.Host{Root: true, UsernsSupported: true}
	report, err := security.Compile(security.Policy{
		Seccomp: security.SeccompCustom,
	}, security.Context{}, host)
	if err == nil {
		t.Fatalf("custom profile must be rejected")
	}
	if !security.IsUnavailable(err) {
		t.Fatalf("want typed *security.Unavailable, got %v", err)
	}
	if report == nil || report.Unavailable == nil {
		t.Fatalf("report must carry the unavailable feature")
	}
}
