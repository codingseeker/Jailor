//go:build linux

package runtimecore

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func ExitCode(ws syscall.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

func Alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

func IsZombie(pid int) bool {
	if pid <= 0 {
		return false
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	close := strings.LastIndex(string(data), ")")
	if close < 0 {
		return false
	}
	rest := strings.Fields(string(data)[close+1:])
	if len(rest) < 1 {
		return false
	}
	return rest[0] == "Z"
}

func NSPids(pid int) []int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		var ids []int
		for _, f := range strings.Fields(strings.TrimPrefix(line, "NSpid:")) {
			if n, err := strconv.Atoi(f); err == nil {
				ids = append(ids, n)
			}
		}
		return ids
	}
	return nil
}

func InnermostPID(pid int) int {
	ids := NSPids(pid)
	if len(ids) == 0 {
		return 0
	}
	return ids[len(ids)-1]
}

func ChildHostPID(initPID int) int {
	if initPID <= 0 {
		return 0
	}
	matches, _ := filepath.Glob("/proc/[0-9]*/stat")
	for _, statFile := range matches {
		pid := statPID(statFile)
		if pid == initPID || pid <= 0 {
			continue
		}
		if statPPID(statFile) == initPID {
			return pid
		}
	}
	return 0
}

func statPID(statFile string) int {
	base := strings.TrimSuffix(statFile, "/stat")
	pid, err := strconv.Atoi(strings.TrimPrefix(base, "/proc/"))
	if err != nil {
		return 0
	}
	return pid
}

func statPPID(statFile string) int {
	data, err := os.ReadFile(statFile)
	if err != nil {
		return 0
	}
	close := strings.LastIndex(string(data), ")")
	if close < 0 {
		return 0
	}
	rest := strings.Fields(string(data)[close+1:])
	if len(rest) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(rest[1])
	if err != nil {
		return 0
	}
	return ppid
}
