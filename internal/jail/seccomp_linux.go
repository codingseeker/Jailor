//go:build linux

package jail

import (
	"fmt"
	"os"
	"sort"
	"syscall"
	"unsafe"
)

const (
	bpfClassLD  = 0x00
	bpfClassJMP = 0x05
	bpfClassRET = 0x06

	bpfLDW = 0x00
	bpfABS = 0x20

	bpfJEQ  = 0x10
	bpfJSET = 0x40
	bpfK    = 0x00

	bpfRETK = 0x00
)

const (
	seccompSetModeFilter = 0x1
	seccompDataNR        = 0x0
	seccompDataArch      = 0x4
	seccompDataArgs      = 0x10
)

const (
	seccompRetAllow = 0x7fff0000

	seccompRetErrno    = 0x00050000
	seccompRetEPERM    = seccompRetErrno | uint32(syscall.EPERM)
	seccompRetENOSYS   = seccompRetErrno | uint32(syscall.ENOSYS)
	auditArchC000003E  = 0xc000003e
	cloneFirstArgIndex = 0
)

const (
	sysClone  = 56
	sysClone3 = 435
)

type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

type sockFprog struct {
	Len    uint16
	Filter *sockFilter
}

func buildDenyFilter(nrs []uint32) []sockFilter {
	return buildFilter(nrs, seccompRetAllow, seccompRetEPERM)
}

func buildAllowFilter(nrs []uint32) []sockFilter {
	return buildFilter(nrs, seccompRetEPERM, seccompRetAllow)
}

func seccompLoad(filter []sockFilter) error {
	if len(filter) == 0 {
		return nil
	}
	prog := &sockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	_, _, errno := syscall.Syscall(
		syscallSYS_SECCOMP,
		seccompSetModeFilter,
		0,
		uintptr(unsafe.Pointer(prog)),
	)
	if errno != 0 {
		return fmt.Errorf("jail: install seccomp filter: %w", errno)
	}
	return nil
}

func buildFilter(nrs []uint32, fallback, target uint32) []sockFilter {
	nrs = append([]uint32(nil), nrs...)
	sort.Slice(nrs, func(i, j int) bool { return nrs[i] < nrs[j] })
	n := len(nrs)

	targetIdx := n + 2

	prog := make([]sockFilter, 0, n+3)
	prog = append(prog, sockFilter{
		Code: uint16(bpfClassLD | bpfLDW | bpfABS),
		K:    seccompDataNR,
	})
	for i, nr := range nrs {
		k := i + 1
		prog = append(prog, sockFilter{
			Code: uint16(bpfClassJMP | bpfJEQ | bpfK),
			K:    nr,
			Jt:   uint8(targetIdx - k - 1),
			Jf:   0,
		})
	}
	prog = append(prog, sockFilter{
		Code: uint16(bpfClassRET | bpfRETK),
		K:    fallback,
	})
	prog = append(prog, sockFilter{
		Code: uint16(bpfClassRET | bpfRETK),
		K:    target,
	})
	return prog
}

func filterToRawWords(filter []sockFilter) []uintptr {
	words := make([]uintptr, len(filter))
	for i, insn := range filter {
		words[i] = uintptr(uint64(uint32(insn.Code)) |
			uint64(uint32(insn.Jt))<<16 |
			uint64(uint32(insn.Jf))<<24 |
			uint64(insn.K)<<32)
	}
	return words
}

const (
	SeccompNone    = "none"
	SeccompDefault = "default"
	SeccompStrict  = "strict"
)

func seccompRequested(cfg *InitConfig) bool {
	return cfg.Seccomp || (cfg.SeccompProfile != "" && cfg.SeccompProfile != SeccompNone)
}

func seccompProfileName(cfg *InitConfig) string {
	if cfg.SeccompProfile != "" {
		return cfg.SeccompProfile
	}
	if cfg.Seccomp {
		return SeccompDefault
	}
	return SeccompNone
}

const cloneNamespaceMask = uint32(
	syscall.CLONE_NEWNS |
		syscall.CLONE_NEWCGROUP |
		syscall.CLONE_NEWUTS |
		syscall.CLONE_NEWIPC |
		syscall.CLONE_NEWUSER |
		syscall.CLONE_NEWPID |
		syscall.CLONE_NEWNET,
)

func buildProfileFilter(nrs []uint32, fallback, target uint32) []sockFilter {
	nrs = append([]uint32(nil), nrs...)
	sort.Slice(nrs, func(i, j int) bool { return nrs[i] < nrs[j] })

	denied := make([]uint32, 0, len(nrs))
	for _, nr := range nrs {
		if nr != sysClone && nr != sysClone3 {
			denied = append(denied, nr)
		}
	}

	loadNR := func() sockFilter {
		return sockFilter{Code: uint16(bpfClassLD | bpfLDW | bpfABS), K: seccompDataNR}
	}
	ret := func(action uint32) sockFilter {
		return sockFilter{Code: uint16(bpfClassRET | bpfRETK), K: action}
	}

	prog := make([]sockFilter, 0, len(denied)+16)
	add := func(f ...sockFilter) []int {
		base := len(prog)
		prog = append(prog, f...)
		idx := make([]int, len(f))
		for i := range idx {
			idx[i] = base + i
		}
		return idx
	}
	patch := func(at int, jt, jf int) {
		prog[at].Jt = uint8(jt)
		prog[at].Jf = uint8(jf)
	}
	to := func(from int, target int) int {
		return target - from - 1
	}

	arch := add(loadNR(), sockFilter{Code: uint16(bpfClassLD | bpfLDW | bpfABS), K: seccompDataArch},
		sockFilter{Code: uint16(bpfClassJMP | bpfJEQ | bpfK), K: auditArchC000003E}, ret(seccompRetEPERM))
	patch(arch[2], 1, 0)

	clone3 := add(loadNR(), sockFilter{Code: uint16(bpfClassJMP | bpfJEQ | bpfK), K: sysClone3},
		ret(seccompRetENOSYS))
	patch(clone3[1], 0, 1)

	clone := add(loadNR(), sockFilter{Code: uint16(bpfClassJMP | bpfJEQ | bpfK), K: sysClone},
		ret(fallback),
		sockFilter{Code: uint16(bpfClassLD | bpfLDW | bpfABS), K: seccompDataArgs + 8*cloneFirstArgIndex},
		sockFilter{Code: uint16(bpfClassJMP | bpfJSET | bpfK), K: cloneNamespaceMask},
		ret(seccompRetEPERM),
		ret(fallback))
	patch(clone[4], 1, 0)

	listed := add(loadNR())
	base := listed[0]
	for _, nr := range denied {
		add(sockFilter{Code: uint16(bpfClassJMP | bpfJEQ | bpfK), K: nr})
	}
	fallbackIdx := len(prog)
	add(ret(fallback))
	targetIdx := len(prog)
	add(ret(target))

	patch(clone[1], to(clone[1], clone[3]), to(clone[1], base))
	patch(clone[4], to(clone[4], clone[5]), to(clone[4], clone[6]))
	for i, nr := range denied {
		at := base + 1 + i
		patch(at, to(at, targetIdx), 0)
		_ = nr
	}
	_ = fallbackIdx
	return prog
}

func buildDefaultFilter() []sockFilter {
	return buildProfileFilter(defaultDeniedSyscalls(), seccompRetAllow, seccompRetEPERM)
}

func buildStrictFilter() []sockFilter {
	return buildProfileFilter(strictAllowedSyscalls(), seccompRetEPERM, seccompRetAllow)
}

func buildSeccompFilter(cfg *InitConfig) ([]uintptr, error) {
	switch seccompProfileName(cfg) {
	case "", SeccompNone:
		return nil, nil
	case SeccompDefault:
		return filterToRawWords(buildDefaultFilter()), nil
	case SeccompStrict:
		return filterToRawWords(buildStrictFilter()), nil
	default:
		return nil, fmt.Errorf("jail: unknown seccomp profile %q", cfg.SeccompProfile)
	}
}

func applySeccompProfile(profile string) error {
	switch profile {
	case "", SeccompNone:
		return nil
	case SeccompDefault:
		return seccompLoad(buildDefaultFilter())
	case SeccompStrict:
		return seccompLoad(buildStrictFilter())
	default:
		return fmt.Errorf("jail: unknown seccomp profile %q", profile)
	}
}

func ensureNewPrivs() error {
	const prSetNoNewPrivs = 38
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("jail: set no_new_privs: %w", errno)
	}
	return nil
}

const attrExec = "/proc/self/attr/exec"

func applyLSM(spec string) error {
	if spec == "" {
		return nil
	}
	if err := os.WriteFile(attrExec, []byte(spec), 0); err != nil {
		return fmt.Errorf("jail: apply LSM profile %q: %w", spec, err)
	}
	return nil
}
