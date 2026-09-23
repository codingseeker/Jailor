package gate

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
)

func netnsFile(pid int) (*os.File, error) {
	path := "/proc/self/ns/net"
	target := "self"
	if pid > 0 {
		path = fmt.Sprintf("/proc/%d/ns/net", pid)
		target = fmt.Sprintf("%d", pid)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("gate: open network namespace of %s: %w", target, err)
	}
	return f, nil
}

var netnsMu sync.Mutex

func setnsByFd(fd uintptr) error {
	if _, _, errno := syscall.Syscall(syscallSYS_SETNS, fd, syscall.CLONE_NEWNET, 0); errno != 0 {
		return fmt.Errorf("gate: setns into network namespace: %v", errno)
	}
	return nil
}

func withNetns(pid int, fn func() error) error {
	orig, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("gate: open own netns: %w", err)
	}
	defer orig.Close()

	target, err := netnsFile(pid)
	if err != nil {
		return err
	}
	defer target.Close()

	netnsMu.Lock()
	defer netnsMu.Unlock()

	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := setnsByFd(target.Fd()); err != nil {
			result <- err
			return
		}
		fnErr := fn()
		if restoreErr := setnsByFd(orig.Fd()); restoreErr != nil && fnErr == nil {
			fnErr = restoreErr
		}
		result <- fnErr
	}()
	return <-result
}
