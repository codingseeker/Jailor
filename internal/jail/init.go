//go:build linux

package jail

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func IsInit() bool {
	return len(os.Args) > 0 && os.Args[1] == "__init"
}

func RunInit() int {
	cfgFD, err := mustGetFD(envConfigFD)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	syncInFD, err := mustGetFD(envSyncInFD)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	syncOutFD, err := mustGetFD(envSyncOutFD)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	cfg, err := readConfig(cfgFD)
	if err != nil {
		fail(syncOutFD, err)
		return 1
	}

	if err := waitRelease(syncInFD); err != nil {
		fail(syncOutFD, err)
		return 1
	}

	if err := prepareJail(&cfg); err != nil {
		teardownMounts()
		fail(syncOutFD, err)
		return 1
	}

	return servePrisoner(&cfg, syncOutFD)
}

func readConfig(fd int) (InitConfig, error) {
	f := os.NewFile(uintptr(fd), "config")
	defer f.Close()
	data, err := readAll(f)
	if err != nil {
		return InitConfig{}, fmt.Errorf("jail: read config: %w", err)
	}
	var cfg InitConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return InitConfig{}, fmt.Errorf("jail: parse config: %w", err)
	}
	if len(cfg.Args) == 0 {
		return InitConfig{}, errors.New("jail: config has no prisoner command")
	}
	return cfg, nil
}

func readAll(f *os.File) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := f.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return nil, err
		}
	}
}

func waitRelease(fd int) error {
	f := os.NewFile(uintptr(fd), "sync-in")
	defer f.Close()
	buf := make([]byte, 1)
	if _, err := f.Read(buf); err != nil {
		return fmt.Errorf("jail: sync: %w", err)
	}
	if buf[0] != syncReady {
		return errors.New("jail: unexpected sync marker")
	}
	return nil
}

func fail(fd int, err error) {
	fmt.Fprintf(os.Stderr, "jail init: %v\n", err)
	f := os.NewFile(uintptr(fd), "sync-out")
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%c\n", syncFail)
}

func prepareJail(cfg *InitConfig) error {
	if cfg.Hostname != "" {
		if err := syscall.Sethostname([]byte(cfg.Hostname)); err != nil {
			return fmt.Errorf("jail: set hostname %q: %w", cfg.Hostname, err)
		}
	}

	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("jail: make mount tree private: %w", err)
	}

	if cfg.Rootfs != "" {
		if err := enterCell(cfg); err != nil {
			return err
		}
	}

	if cfg.MountProc {
		if err := ensureDir("/proc"); err != nil {
			return fmt.Errorf("jail: create /proc: %w", err)
		}
		if err := syscall.Mount("proc", "/proc", "proc",
			syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
			return fmt.Errorf("jail: mount /proc: %w", err)
		}
	}
	if cfg.MountTmp {
		if err := ensureDir("/tmp"); err != nil {
			return fmt.Errorf("jail: create /tmp: %w", err)
		}
		if err := syscall.Mount("tmpfs", "/tmp", "tmpfs",
			syscall.MS_NOSUID|syscall.MS_NODEV, "mode=1777"); err != nil {
			return fmt.Errorf("jail: mount /tmp: %w", err)
		}
	}
	if cfg.MountDev {
		if err := setupDev(); err != nil {
			return fmt.Errorf("jail: mount /dev: %w", err)
		}
	}

	if cfg.ReadOnly {
		if cfg.Rootfs == "" {
			return errors.New("jail: read-only Cell requires a rootfs")
		}
		if err := makeCellReadOnly(); err != nil {
			return err
		}
	}

	if err := applyRestrictions(cfg); err != nil {
		return err
	}
	return nil
}

func makeCellReadOnly() error {
	return syscall.Mount("", "/", "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, "")
}

func enterCell(cfg *InitConfig) error {
	root := cfg.Rootfs
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}

	if err := syscall.Mount(absRoot, absRoot, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("jail: bind-mount cell %s: %w", absRoot, err)
	}

	putOld := filepath.Join(absRoot, ".oldroot")
	if err := os.MkdirAll(putOld, 0o700); err != nil {
		return fmt.Errorf("jail: create .oldroot: %w", err)
	}

	if err := syscall.PivotRoot(absRoot, putOld); err == nil {
		if err := syscall.Chdir("/"); err != nil {
			return err
		}
		if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_SLAVE, ""); err != nil {
			return fmt.Errorf("jail: make root slave: %w", err)
		}
		if err := syscall.Mount("/", "/", "", syscall.MS_REC|syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("jail: rebind cell root: %w", err)
		}
		if cfg.WorkDir != "" {
			if err := syscall.Chdir(cfg.WorkDir); err != nil {
				return fmt.Errorf("jail: chdir %s: %w", cfg.WorkDir, err)
			}
		}
		if err := syscall.Unmount("/.oldroot", syscall.MNT_DETACH); err != nil {
			return fmt.Errorf("jail: unmount .oldroot: %w", err)
		}
		_ = os.Remove("/.oldroot")
		return nil
	} else {

		if err := os.RemoveAll(putOld); err != nil {
			_ = err
		}
		if err := syscall.Chroot(absRoot); err != nil {
			return fmt.Errorf("jail: pivot_root and chroot both failed: %w", err)
		}
		if cfg.WorkDir != "" {
			if err := syscall.Chdir(cfg.WorkDir); err != nil {
				return fmt.Errorf("jail: chdir %s: %w", cfg.WorkDir, err)
			}
		} else {
			if err := syscall.Chdir("/"); err != nil {
				return err
			}
		}
		return nil
	}
}

func ensureMountProc(_ *InitConfig) {}

func ensureDir(name string) error {
	return os.MkdirAll(name, 0o755)
}

func teardownMounts() {
	for _, p := range []string{"/proc", "/dev", "/tmp"} {
		_ = syscall.Unmount(p, syscall.MNT_DETACH)
	}
	_ = syscall.Unmount("/.oldroot", syscall.MNT_DETACH)
}

func setupDev() error {
	devDir := "/dev"
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		return err
	}
	if err := syscall.Mount("tmpfs", devDir, "tmpfs", syscall.MS_NOSUID, "mode=0755"); err != nil {
		return fmt.Errorf("mount /dev: %w", err)
	}
	devices := []struct {
		name         string
		major, minor uint32
	}{
		{"null", 1, 3},
		{"zero", 1, 5},
		{"full", 1, 7},
		{"random", 1, 8},
		{"urandom", 1, 9},
		{"tty", 5, 0},
	}
	for _, d := range devices {
		path := filepath.Join("/dev", d.name)
		dev := int(d.major<<8 | d.minor)
		err := syscall.Mknod(path, syscall.S_IFCHR|0o666, dev)
		if err != nil {
			_ = err
		}
	}
	if err := os.MkdirAll(filepath.Join(devDir, "pts"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(devDir, "shm"), 0o1777); err != nil {
		return err
	}
	if err := os.Symlink("/proc/self/fd", filepath.Join(devDir, "fd")); err != nil {
		_ = err
	}
	if err := os.Symlink("/proc/self/fd/0", filepath.Join(devDir, "stdin")); err != nil {
		_ = err
	}
	if err := os.Symlink("/proc/self/fd/1", filepath.Join(devDir, "stdout")); err != nil {
		_ = err
	}
	if err := os.Symlink("/proc/self/fd/2", filepath.Join(devDir, "stderr")); err != nil {
		_ = err
	}
	return nil
}

func applyRestrictions(cfg *InitConfig) error {
	seccompOn := cfg.SeccompProfile != "" && cfg.SeccompProfile != SeccompNone
	if cfg.Seccomp && !seccompOn {

		cfg.SeccompProfile = SeccompDefault
		seccompOn = true
	}
	if cfg.NoNewPrivs || seccompOn {

		if err := ensureNewPrivs(); err != nil {
			return err
		}
	}
	if seccompOn {
		if err := applySeccompProfile(cfg.SeccompProfile); err != nil {
			return err
		}
	}

	if cfg.LSM != "" {
		if err := applyLSM(cfg.LSM); err != nil {
			return err
		}
	}

	if err := dropBoundingCaps(cfg.Capabilities); err != nil {
		return err
	}
	return dropEffectiveCaps(cfg.Capabilities)
}

func resolveCommand(cfg *InitConfig) (argv []string, env []string, err error) {
	argv = append([]string(nil), cfg.Args...)
	env = cfg.Env
	userEnv := cfg.Env != nil
	if env == nil {
		env = os.Environ()
	}

	const jailPath = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if cfg.Rootfs != "" && !userEnv {
		filtered := env[:0]
		for _, e := range env {
			if len(e) >= 5 && e[:5] == "PATH=" {
				continue
			}
			filtered = append(filtered, e)
		}
		env = append(filtered, jailPath)
	} else {
		pathSet := false
		for _, e := range env {
			if len(e) >= 5 && e[:5] == "PATH=" {
				pathSet = true
				break
			}
		}
		if !pathSet {
			env = append(env, jailPath)
		}
	}

	argv0 := argv[0]
	if !containsSlash(argv0) {

		oldPath := os.Getenv("PATH")
		for _, e := range env {
			if len(e) >= 5 && e[:5] == "PATH=" {
				_ = os.Setenv("PATH", e[5:])
				break
			}
		}
		if p, lerr := exec.LookPath(argv0); lerr == nil {
			argv[0] = p
		} else {
			err = lerr
		}
		_ = os.Setenv("PATH", oldPath)
	}
	return argv, env, err
}

func execPrisoner(cfg *InitConfig) error {
	argv, env, err := resolveCommand(cfg)
	if err != nil {
		return err
	}
	return syscall.Exec(argv[0], argv, env)
}

func containsSlash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}
