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

	bpfJEQ = 0x10
	bpfK   = 0x00

	bpfRETK = 0x00
)

const (
	seccompModeFilter    = 0x2
	seccompSetModeFilter = 0x1
	seccompDataNR        = 0x0
)

const (
	seccompRetErrno = 0x00050000
	seccompRetAllow = 0x7fff0000
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
	return buildFilter(nrs, seccompRetAllow, seccompRetErrno|uint32(syscall.EPERM))
}

func buildAllowFilter(nrs []uint32) []sockFilter {
	return buildFilter(nrs, seccompRetErrno|uint32(syscall.EPERM), seccompRetAllow)
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
		return fmt.Errorf("jail: install seccomp filter: %v", errno)
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

const (
	SeccompNone    = "none"
	SeccompDefault = "default"
	SeccompStrict  = "strict"
)

func applySeccompProfile(profile string) error {
	switch profile {
	case "", SeccompNone:
		return nil
	case SeccompDefault:
		return seccompLoad(buildDenyFilter(defaultDeniedSyscalls()))
	case SeccompStrict:
		return seccompLoad(buildAllowFilter(strictAllowedSyscalls()))
	default:
		return fmt.Errorf("jail: unknown seccomp profile %q", profile)
	}
}

func ensureNewPrivs() error {
	const prSetNoNewPrivs = 38
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("jail: set no_new_privs: %v", errno)
	}
	return nil
}

const attrExec = "/proc/self/attr/exec"

func applyLSM(spec string) error {
	if spec == "" {
		return nil
	}
	return os.WriteFile(attrExec, []byte(spec), 0)
}
