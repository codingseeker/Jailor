//go:build linux

package jail

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	prCapBSetDrop = 24
)

const linuxCapabilityVersion3 = 0x20080522

type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

var capNames = map[string]int{
	"CAP_CHOWN":              0,
	"CAP_DAC_OVERRIDE":       1,
	"CAP_DAC_READ_SEARCH":    2,
	"CAP_FOWNER":             3,
	"CAP_FSETID":             4,
	"CAP_KILL":               5,
	"CAP_SETGID":             6,
	"CAP_SETUID":             7,
	"CAP_SETPCAP":            8,
	"CAP_LINUX_IMMUTABLE":    9,
	"CAP_NET_BIND_SERVICE":   10,
	"CAP_NET_BROADCAST":      11,
	"CAP_NET_ADMIN":          12,
	"CAP_NET_RAW":            13,
	"CAP_IPC_LOCK":           14,
	"CAP_IPC_OWNER":          15,
	"CAP_SYS_MODULE":         16,
	"CAP_SYS_RAWIO":          17,
	"CAP_SYS_CHROOT":         18,
	"CAP_SYS_PTRACE":         19,
	"CAP_SYS_PACCT":          20,
	"CAP_SYS_ADMIN":          21,
	"CAP_SYS_BOOT":           22,
	"CAP_SYS_NICE":           23,
	"CAP_SYS_RESOURCE":       24,
	"CAP_SYS_TIME":           25,
	"CAP_SYS_TTY_CONFIG":     26,
	"CAP_MKNOD":              27,
	"CAP_LEASE":              28,
	"CAP_AUDIT_WRITE":        29,
	"CAP_AUDIT_CONTROL":      30,
	"CAP_SETFCAP":            31,
	"CAP_MAC_OVERRIDE":       32,
	"CAP_MAC_ADMIN":          33,
	"CAP_SYSLOG":             34,
	"CAP_WAKE_ALARM":         35,
	"CAP_BLOCK_SUSPEND":      36,
	"CAP_AUDIT_READ":         37,
	"CAP_PERFMON":            38,
	"CAP_BPF":                39,
	"CAP_CHECKPOINT_RESTORE": 40,
}

func capNumber(name string) (int, bool) {
	n, ok := capNames[name]
	return n, ok
}

func dropBoundingCaps(keep []string) error {
	keepSet := make(map[string]bool, len(keep))
	for _, c := range keep {
		keepSet[c] = true
	}
	for name, num := range capNames {
		if keepSet[name] {
			continue
		}
		if _, _, errno := syscall.Syscall6(
			syscall.SYS_PRCTL, prCapBSetDrop, uintptr(num), 0, 0, 0, 0,
		); errno != 0 {

			if os.Geteuid() == 0 {
				return fmt.Errorf("drop cap %s: %w", name, errno)
			}
		}
	}
	return nil
}

func dropEffectiveCaps(keep []string) error {
	keepSet := make(map[string]bool, len(keep))
	for _, c := range keep {
		keepSet[c] = true
	}
	if keepSet["all"] {
		return nil
	}

	if len(capNames) == 0 {
		return nil
	}

	var data [2]capData
	_, _, errno := syscall.Syscall6(syscall.SYS_CAPGET,
		uintptr(unsafe.Pointer(&capHeader{version: linuxCapabilityVersion3})),
		uintptr(unsafe.Pointer(&data[0])),
		0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("jail: capget: %v", errno)
	}
	lo := data[0]
	hi := data[1]

	var keepMask uint64
	for _, c := range keep {
		if n, ok := capNames[c]; ok {
			keepMask |= 1 << uint(n)
		}
	}
	keptLo := uint32(keepMask & 0xffffffff)
	keptHi := uint32(keepMask >> 32)

	newLo := capData{
		effective:   lo.effective & keptLo,
		permitted:   lo.permitted & keptLo,
		inheritable: lo.inheritable & keptLo,
	}
	newHi := capData{
		effective:   hi.effective & keptHi,
		permitted:   hi.permitted & keptHi,
		inheritable: hi.inheritable & keptHi,
	}

	hdr := capHeader{version: linuxCapabilityVersion3}

	words := [2]capData{newLo, newHi}
	_, _, errno = syscall.Syscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&words[0])), 0)
	if errno != 0 {
		return fmt.Errorf("jail: capset: %v", errno)
	}
	return nil
}
