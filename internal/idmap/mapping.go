package idmap

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

type MapLine struct {
	ContainerID uint32
	HostID      uint32
	Size        uint32
}

func (m MapLine) String() string {
	return fmt.Sprintf("%d->%d,%d", m.ContainerID, m.HostID, m.Size)
}
func BuildMappings(euid, egid uint32, uidRanges, gidRanges []Range) (uid, gid []MapLine, err error) {
	uid, err = build(euid, uidRanges)
	if err != nil {
		return nil, nil, err
	}
	gid, err = build(egid, gidRanges)
	if err != nil {
		return nil, nil, err
	}
	return uid, gid, nil
}

func build(hostSelf uint32, ranges []Range) ([]MapLine, error) {
	var out []MapLine
	out = append(out, MapLine{ContainerID: 0, HostID: hostSelf, Size: 1})

	cont := uint32(1)
	for _, r := range ranges {
		if r.Size == 0 {
			continue
		}
		delta := uint64(cont) + uint64(r.Size)
		if cont >= 0x80000000 || delta > uint64(^uint32(0))+1 {
			out = append(out, MapLine{ContainerID: cont, HostID: r.Start,
				Size: uint32(uint64(^uint32(0)) - uint64(cont) + 1)})
			return out, nil
		}
		out = append(out, MapLine{ContainerID: cont, HostID: r.Start, Size: r.Size})
		cont += r.Size
	}
	return out, nil
}
func ToProcLines(lines []MapLine) []syscall.SysProcIDMap {
	if len(lines) == 0 {
		return nil
	}
	out := make([]syscall.SysProcIDMap, 0, len(lines))
	for _, l := range lines {
		out = append(out, syscall.SysProcIDMap{ContainerID: int(l.ContainerID), HostID: int(l.HostID), Size: int(l.Size)})
	}
	return out
}
func WriteMaps(pid int, uid, gid []MapLine) error {
	if len(uid) == 0 || len(gid) == 0 {
		return &Unavailable{File: SubUID, User: strconv.Itoa(pid),
			Why: "refusing to install an empty id map"}
	}
	if err := execHelper("newuidmap", pid, uid); err != nil {
		return err
	}
	if err := execHelper("newgidmap", pid, gid); err != nil {
		return err
	}
	return nil
}

func execHelper(name string, pid int, lines []MapLine) error {
	bin, err := exec.LookPath(name)
	if err != nil {
		return &Unavailable{File: File("/usr/bin/" + name), User: strconv.Itoa(pid),
			Why: "setuid helper " + name + " not found on PATH; cannot install subordinate id maps"}
	}
	args := []string{strconv.Itoa(pid)}
	for _, l := range lines {
		args = append(args, strconv.FormatUint(uint64(l.ContainerID), 10),
			strconv.FormatUint(uint64(l.HostID), 10),
			strconv.FormatUint(uint64(l.Size), 10))
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("idmap: %s: %w", name, fmt.Errorf("%s", msg))
	}
	return nil
}
func MapsToString(lines []MapLine) []string {
	if len(lines) == 0 {
		return nil
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, l.String())
	}
	return out
}
