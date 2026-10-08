//go:build linux

package jail

import (
	"reflect"
	"sort"
	"syscall"
	"testing"
)

const seccompRetActionMask = 0xffff0000

type bpfOutcome uint32

func runBPF(prog []sockFilter, nr uint32, arch uint32, args [6]uint32) uint32 {
	var (
		a    uint32
		regs [6]uint32
	)
	_ = regs
	_ = a
	for pc := 0; pc < len(prog); pc++ {
		f := prog[pc]
		switch f.Code {
		case uint16(bpfClassLD | bpfLDW | bpfABS):
			switch f.K {
			case seccompDataNR:
				a = nr
			case seccompDataArch:
				a = arch
			case seccompDataArgs, seccompDataArgs + 8, seccompDataArgs + 16,
				seccompDataArgs + 24, seccompDataArgs + 32, seccompDataArgs + 40:
				a = args[(f.K-seccompDataArgs)/8]
			default:
				return seccompRetErrno | uint32(syscall.EFAULT)
			}
		case uint16(bpfClassJMP | bpfJEQ | bpfK):
			if a == f.K {
				pc += int(f.Jt)
			} else {
				pc += int(f.Jf)
			}
		case uint16(bpfClassJMP | bpfJSET | bpfK):
			if a&f.K != 0 {
				pc += int(f.Jt)
			} else {
				pc += int(f.Jf)
			}
		case uint16(bpfClassRET | bpfRETK):
			return f.K
		default:
			return seccompRetErrno | uint32(syscall.EFAULT)
		}
	}
	return seccompRetErrno | uint32(syscall.EFAULT)
}

func noArgs() [6]uint32 {
	return [6]uint32{}
}

func checkJumpsInRange(t *testing.T, prog []sockFilter) {
	t.Helper()
	for i, f := range prog {
		switch f.Code {
		case uint16(bpfClassJMP | bpfJEQ | bpfK), uint16(bpfClassJMP | bpfJSET | bpfK):
			if i+1+int(f.Jt) >= len(prog) {
				t.Errorf("instruction %d: jt=%d lands at %d, past end %d", i, f.Jt, i+1+int(f.Jt), len(prog))
			}
			if i+1+int(f.Jf) >= len(prog) {
				t.Errorf("instruction %d: jf=%d lands at %d, past end %d", i, f.Jf, i+1+int(f.Jf), len(prog))
			}
		}
	}
}

func TestDenyFilterShape(t *testing.T) {
	prog := buildDenyFilter(defaultDeniedSyscalls())
	if len(prog) < 3 {
		t.Fatalf("filter too short: %d", len(prog))
	}

	ld := prog[0]
	if ld.K != seccompDataNR {
		t.Fatalf("first instruction must load seccomp data nr, got K=%d", ld.K)
	}

	var jeq []uint32
	for _, f := range prog[1 : len(prog)-2] {
		if f.Code != bpfClassJMP|bpfJEQ|bpfK {
			t.Fatalf("expected JEQ instruction, got code %d", f.Code)
		}
		jeq = append(jeq, f.K)
	}
	sort.Slice(jeq, func(i, j int) bool { return jeq[i] < jeq[j] })

	var want []uint32
	for _, n := range defaultDeniedSyscalls() {
		want = append(want, uint32(n))
	}
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if !reflect.DeepEqual(jeq, want) {
		t.Errorf("JEQ set mismatch:\n got %v\nwant %v", jeq, want)
	}

	allow := prog[len(prog)-2]
	errno := prog[len(prog)-1]
	if allow.Code != bpfClassRET|bpfRETK || allow.K != seccompRetAllow {
		t.Errorf("expected RET ALLOW as penultimate instruction, got code=%d K=%d", allow.Code, allow.K)
	}
	if errno.Code != bpfClassRET|bpfRETK || errno.K&seccompRetActionMask != seccompRetErrno {
		t.Errorf("expected RET ERRNO as final instruction, got code=%d K=%d", errno.Code, errno.K)
	}

	for i, f := range prog[1 : len(prog)-2] {
		k := i + 1
		if int(f.Jt)+k+1 != len(prog)-1 {
			t.Errorf("JEQ at %d jumps to %d, want %d", k, int(f.Jt)+k+1, len(prog)-1)
		}
	}
}

func TestDefaultProfileDeniesForbiddenSyscalls(t *testing.T) {
	prog := buildDefaultFilter()
	checkJumpsInRange(t, prog)

	for _, nr := range []uint32{
		101,
		155,
		163,
		165,
		166,
		246,
		272,
		298,
		320,
		428,
		429,
		430,
		431,
		432,
		433,
		442,
	} {
		got := runBPF(prog, nr, auditArchC000003E, noArgs())
		if got != seccompRetEPERM {
			t.Errorf("default profile: syscall %d returned %#x, want EPERM", nr, got)
		}
	}
}

func TestDefaultProfileAllowsOrdinarySyscalls(t *testing.T) {
	prog := buildDefaultFilter()
	for _, nr := range []uint32{0, 1, 2, 39, 60, 61, 62, 231, 318, 334} {
		got := runBPF(prog, nr, auditArchC000003E, noArgs())
		if got != seccompRetAllow {
			t.Errorf("default profile: syscall %d returned %#x, want ALLOW", nr, got)
		}
	}
}

func TestDefaultProfileAllowsThreadCreation(t *testing.T) {
	prog := buildDefaultFilter()

	threadFlags := uint32(syscall.CLONE_VM | syscall.CLONE_FS | syscall.CLONE_FILES |
		syscall.CLONE_SIGHAND | syscall.CLONE_THREAD | syscall.CLONE_SYSVSEM)
	args := [6]uint32{threadFlags}
	if got := runBPF(prog, sysClone, auditArchC000003E, args); got != seccompRetAllow {
		t.Errorf("clone for a new thread returned %#x, want ALLOW", got)
	}

	if got := runBPF(prog, sysClone3, auditArchC000003E, [6]uint32{threadFlags}); got != seccompRetENOSYS {
		t.Errorf("clone3 for a new thread returned %#x, want ENOSYS", got)
	}
}

func TestDefaultProfileDeniesNamespaceCreation(t *testing.T) {
	prog := buildDefaultFilter()
	for _, flag := range []uint32{
		syscall.CLONE_NEWNS,
		syscall.CLONE_NEWUSER,
		syscall.CLONE_NEWPID,
		syscall.CLONE_NEWNET,
		syscall.CLONE_NEWIPC,
		syscall.CLONE_NEWUTS,
		syscall.CLONE_NEWCGROUP,
	} {
		args := [6]uint32{flag}
		if got := runBPF(prog, sysClone, auditArchC000003E, args); got != seccompRetEPERM {
			t.Errorf("clone with %#x returned %#x, want EPERM", flag, got)
		}
	}
}

func TestProfileRejectsForeignArchitecture(t *testing.T) {
	for name, prog := range map[string][]sockFilter{
		"default": buildDefaultFilter(),
		"strict":  buildStrictFilter(),
	} {
		got := runBPF(prog, 0, 0xdeadbeef, noArgs())
		if got != seccompRetEPERM {
			t.Errorf("%s profile on foreign arch returned %#x, want EPERM", name, got)
		}
	}
}

func TestStrictProfileAllowsOnlyListedSyscalls(t *testing.T) {
	prog := buildStrictFilter()
	checkJumpsInRange(t, prog)

	for _, nr := range []uint32{0, 1, 2, 39, 60, 61} {
		if got := runBPF(prog, nr, auditArchC000003E, noArgs()); got != seccompRetAllow {
			t.Errorf("strict profile: syscall %d returned %#x, want ALLOW", nr, got)
		}
	}
	for _, nr := range []uint32{101, 165, 246, 272, 298} {
		if got := runBPF(prog, nr, auditArchC000003E, noArgs()); got != seccompRetEPERM {
			t.Errorf("strict profile: syscall %d returned %#x, want EPERM", nr, got)
		}
	}
}

func TestBuildSeccompFilterProfiles(t *testing.T) {
	if got, err := buildSeccompFilter(&InitConfig{}); err != nil || got != nil {
		t.Errorf("empty config: got %v, %v, want nil, nil", got, err)
	}
	if got, err := buildSeccompFilter(&InitConfig{SeccompProfile: SeccompNone}); err != nil || got != nil {
		t.Errorf("none profile: got %v, %v, want nil, nil", got, err)
	}
	if got, err := buildSeccompFilter(&InitConfig{Seccomp: true}); err != nil || len(got) == 0 {
		t.Errorf("Seccomp=true: got %d words, %v, want a non-empty filter", len(got), err)
	}
	if got, err := buildSeccompFilter(&InitConfig{SeccompProfile: SeccompDefault}); err != nil || len(got) == 0 {
		t.Errorf("default profile: got %d words, %v, want a non-empty filter", len(got), err)
	}
	if got, err := buildSeccompFilter(&InitConfig{SeccompProfile: SeccompStrict}); err != nil || len(got) == 0 {
		t.Errorf("strict profile: got %d words, %v, want a non-empty filter", len(got), err)
	}
	if _, err := buildSeccompFilter(&InitConfig{SeccompProfile: "profane"}); err == nil {
		t.Error("unknown profile must fail closed")
	}
}

func TestSeccompProfileNameResolution(t *testing.T) {
	cases := []struct {
		cfg  InitConfig
		want string
	}{
		{InitConfig{}, SeccompNone},
		{InitConfig{Seccomp: true}, SeccompDefault},
		{InitConfig{SeccompProfile: SeccompNone}, SeccompNone},
		{InitConfig{SeccompProfile: SeccompStrict}, SeccompStrict},
		{InitConfig{Seccomp: true, SeccompProfile: SeccompStrict}, SeccompStrict},
	}
	for _, c := range cases {
		if got := seccompProfileName(&c.cfg); got != c.want {
			t.Errorf("seccompProfileName(%+v) = %q, want %q", c.cfg, got, c.want)
		}
	}
}

func TestSeccompRequested(t *testing.T) {
	if seccompRequested(&InitConfig{}) {
		t.Error("seccomp must not be requested when neither flag nor profile is set")
	}
	if seccompRequested(&InitConfig{SeccompProfile: SeccompNone}) {
		t.Error("profile none must not request seccomp")
	}
	if !seccompRequested(&InitConfig{Seccomp: true}) {
		t.Error("Seccomp=true must request seccomp")
	}
	if !seccompRequested(&InitConfig{SeccompProfile: SeccompDefault}) {
		t.Error("an explicit profile must request seccomp")
	}
}
