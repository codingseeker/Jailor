//go:build linux

package jail

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
)

func IsNSEnter() bool {
	return len(os.Args) > 0 && os.Args[1] == "__nsenter"
}

func RunNSEnter() int {
	return runNSEnter()
}

func runNSEnter() int {

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pidStr := os.Getenv(envVisitorTarget)
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		fmt.Fprintf(os.Stderr, "nsenter: bad target pid %q\n", pidStr)
		return 1
	}
	cfgFD, err := mustGetFD(envVisitorCFG)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if err := enterTargetNamespaces(pid); err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: %v\n", err)
		return 1
	}

	argv := append([]string{"jailor", "__visitor"}, os.Args[2:]...)
	child, err := syscall.ForkExec(os.Args[0], argv, &syscall.ProcAttr{
		Dir:   "/",
		Env:   os.Environ(),
		Files: []uintptr{0, 1, 2, uintptr(cfgFD)},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: fork visitor: %v\n", err)
		return 1
	}
	var ws syscall.WaitStatus
	_, _ = syscall.Wait4(child, &ws, 0, nil)
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

func enterTargetNamespaces(pid int) error {
	ordered := []struct {
		name string
		flag uintptr
	}{
		{"user", syscall.CLONE_NEWUSER},
		{"mnt", syscall.CLONE_NEWNS},
		{"uts", syscall.CLONE_NEWUTS},
		{"ipc", syscall.CLONE_NEWIPC},
		{"pid", syscall.CLONE_NEWPID},
		{"net", syscall.CLONE_NEWNET},
		{"cgroup", syscall.CLONE_NEWCGROUP},
	}
	for _, ns := range ordered {
		path := fmt.Sprintf("/proc/%d/ns/%s", pid, ns.name)
		f, err := os.Open(path)
		if err != nil {

			if ns.name == "cgroup" {
				continue
			}
			return fmt.Errorf("open %s: %w", path, err)
		}
		if _, _, errno := syscall.Syscall(syscallSYS_SETNS, f.Fd(), ns.flag, 0); errno != 0 {
			f.Close()
			return fmt.Errorf("setns into %s: %v", path, errno)
		}
		f.Close()
	}
	return nil
}
