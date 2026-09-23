//go:build linux

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func supportsOverlay() bool {
	data, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "overlay") {
			return true
		}
	}
	return false
}

func mountOverlay(lower []string, upper, work, dest string) error {
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s",
		strings.Join(lower, ":"), upper, work)
	if err := syscall.Mount("overlay", dest, "overlay", 0, opts); err != nil {
		return fmt.Errorf("store: overlay mount: %w", err)
	}
	return nil
}

func mountOverlayRO(lower []string, dest string) error {
	opts := fmt.Sprintf("lowerdir=%s,ro", strings.Join(lower, ":"))
	if err := syscall.Mount("overlay", dest, "overlay", syscall.MS_RDONLY, opts); err != nil {
		return fmt.Errorf("store: overlay ro mount: %w", err)
	}
	return nil
}

func (s *Store) unmount(path string) error {
	if !isMounted(path) {
		return nil
	}
	err := syscall.Unmount(path, 0)
	if err == nil || err == syscall.EINVAL || err == syscall.ENOENT {
		return nil
	}
	return fmt.Errorf("store: unmount %s: %w", path, err)
}

func isMounted(path string) bool {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	clean, rerr := filepath.Abs(filepath.Clean(path))
	if rerr != nil {
		clean = filepath.Clean(path)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, " ")

		if len(fields) > 4 && fields[4] == clean {
			return true
		}
	}
	return false
}
