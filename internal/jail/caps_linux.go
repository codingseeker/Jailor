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
	prCapBSetDrop = 24
)

const (
	capVersion3 = 0x20080522
	capCount    = 41
)

type rawCapHeader struct {
	version uint32
	pid     int32
}

type rawCapData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

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
	"CAP_BOOT":               22,
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

func knownCapabilityNames() []string {
	names := make([]string, 0, len(capNames))
	for name := range capNames {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func capMaskFor(keep []string) (uint64, error) {
	if len(keep) == 0 {
		return 0, nil
	}
	var mask uint64
	for _, name := range keep {
		num, ok := capNames[name]
		if !ok {
			return 0, fmt.Errorf("jail: unknown capability %q", name)
		}
		if num >= 64 {
			return 0, fmt.Errorf("jail: capability %q is out of range", name)
		}
		mask |= 1 << uint(num)
	}
	return mask, nil
}

func applyCapabilityPolicy(keep []string) error {
	mask, err := capMaskFor(keep)
	if err != nil {
		return err
	}
	if err := dropBoundingCaps(mask); err != nil {
		return err
	}
	return dropEffectiveCaps(mask)
}

func dropBoundingCaps(mask uint64) error {
	names := make([]int, 0, len(capNames))
	for _, num := range capNames {
		if mask&(1<<uint(num)) != 0 {
			continue
		}
		names = append(names, num)
	}
	sort.Ints(names)
	for _, num := range names {
		if _, _, errno := syscall.Syscall6(
			syscall.SYS_PRCTL, prCapBSetDrop, uintptr(num), 0, 0, 0, 0,
		); errno != 0 {
			if os.Geteuid() == 0 {
				return fmt.Errorf("jail: drop capability %s from bounding set: %w", capNameOf(num), errno)
			}
		}
	}
	return nil
}

func dropEffectiveCaps(mask uint64) error {
	var data [2]capData
	hdr := capHeader{version: capVersion3}
	_, _, errno := syscall.Syscall(syscall.SYS_CAPGET,
		uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0)
	if errno != 0 {
		return fmt.Errorf("jail: capget: %w", errno)
	}
	lo := data[0]
	hi := data[1]

	words := [2]capData{
		{
			effective:   lo.effective & uint32(mask),
			permitted:   lo.permitted & uint32(mask),
			inheritable: lo.inheritable & uint32(mask),
		},
		{
			effective:   hi.effective & uint32(mask>>32),
			permitted:   hi.permitted & uint32(mask>>32),
			inheritable: hi.inheritable & uint32(mask>>32),
		},
	}

	set := capHeader{version: capVersion3}
	_, _, errno = syscall.Syscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&set)), uintptr(unsafe.Pointer(&words[0])), 0)
	if errno != 0 {
		return fmt.Errorf("jail: capset: %w", errno)
	}
	return nil
}

func capNameOf(num int) string {
	for name, n := range capNames {
		if n == num {
			return name
		}
	}
	return fmt.Sprintf("#%d", num)
}
