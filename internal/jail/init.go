//go:build linux

package jail

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const jailPathEnv = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

func IsInit() bool {
	return len(os.Args) > 1 && os.Args[1] == InitArg
}

func IsStager() bool {
	return len(os.Args) > 1 && os.Args[1] == StagerArg
}

func RunStager() int {
	cfgFD, err := mustGetFD(envConfigFD)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	releaseFD, err := mustGetFD(envReleaseFD)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	readyFD, err := mustGetFD(envReadyFD)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	prisonerReadFD, err := mustGetFD(envPrisonerReadFD)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	prisonerWriteFD, err := mustGetFD(envPrisonerWriteFD)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	initPIDFD, err := mustGetFD(envInitPIDFD)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	cfg, err := readConfig(cfgFD)
	if err != nil {
		reportInitFailure(readyFD, err)
		return 1
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	initPID, goFD, err := stagerLaunch(&cfg, readyFD, initPIDFD, prisonerWriteFD, prisonerReadFD, newPIDNamespaceRequested())
	if err != nil {
		if teardownErr := teardownMounts(); teardownErr != nil {
			fmt.Fprintf(os.Stderr, "jail stager: %v (teardown: %v)\n", err, teardownErr)
		}
		reportInitFailure(readyFD, err)
		return 127
	}
	_ = closeFD(prisonerWriteFD)
	_ = closeFD(readyFD)
	_ = closeFD(initPIDFD)

	if err := waitRelease(releaseFD); err != nil {
		if killErr := syscall.Kill(initPID, syscall.SIGKILL); killErr != nil {
			fmt.Fprintf(os.Stderr, "jail stager: %v (kill jail init: %v)\n", err, killErr)
		}
		_, _ = syscall.Wait4(initPID, nil, 0, nil)
		return 1
	}
	if err := releaseInit(goFD); err != nil {
		if killErr := syscall.Kill(initPID, syscall.SIGKILL); killErr != nil {
			fmt.Fprintf(os.Stderr, "jail stager: %v (kill jail init: %v)\n", err, killErr)
		}
		_, _ = syscall.Wait4(initPID, nil, 0, nil)
		return 1
	}
	return waitForInit(initPID)
}

func newPIDNamespaceRequested() bool {
	return os.Getenv(envNewPIDNS) == "1"
}

func stagerLaunch(cfg *InitConfig, readyFD, initPIDFD, prisonerFD, prisonerReadFD int, newPIDNS bool) (int, int, error) {
	if err := setHostname(cfg.Hostname); err != nil {
		return 0, 0, err
	}
	if err := makeMountsPrivate(); err != nil {
		return 0, 0, err
	}

	devRoot, tmpRoot, err := cellMountPoints(cfg.Rootfs)
	if err != nil {
		return 0, 0, err
	}
	if cfg.MountTmp {
		if err := mountTmp(tmpRoot); err != nil {
			return 0, 0, err
		}
	}
	if cfg.MountDev {
		if err := setupDev(devRoot); err != nil {
			return 0, 0, err
		}
	}

	if cfg.Rootfs != "" {
		if err := enterCell(cfg); err != nil {
			return 0, 0, err
		}
	}
	if cfg.ReadOnly {
		if cfg.Rootfs == "" {
			return 0, 0, errors.New("jail: read-only Cell requires a rootfs")
		}
		if err := makeCellReadOnly(); err != nil {
			return 0, 0, err
		}
	}
	if cfg.LSM != "" {
		if err := applyLSM(cfg.LSM); err != nil {
			return 0, 0, err
		}
	}

	argv, err := resolvePrisonerCommand(cfg)
	if err != nil {
		return 0, 0, err
	}
	env, err := prisonerEnvironment(cfg)
	if err != nil {
		return 0, 0, err
	}

	seccompProg, err := buildSeccompFilter(cfg)
	if err != nil {
		return 0, 0, err
	}
	capMask, err := capMaskFor(cfg.Capabilities)
	if err != nil {
		return 0, 0, err
	}

	if newPIDNS {
		if err := syscall.Unshare(syscall.CLONE_NEWPID); err != nil {
			return 0, 0, fmt.Errorf("jail: create pid namespace: %w", err)
		}
	}

	prisoner, err := newRawExec(argv, env)
	if err != nil {
		return 0, 0, fmt.Errorf("jail: encode prisoner command: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return 0, 0, fmt.Errorf("jail: locate self: %w", err)
	}
	initSpec, err := newRawExec([]string{self, InitArg}, jailInitEnvironment(env))
	if err != nil {
		return 0, 0, fmt.Errorf("jail: encode jail init command: %w", err)
	}

	goR, goW, err := os.Pipe()
	if err != nil {
		return 0, 0, fmt.Errorf("jail: create jail init release pipe: %w", err)
	}

	initPlan = rawInitPlan{
		launch:       true,
		inheritedFD:  runtimeOpenDescriptors(),
		mountProc:    cfg.MountProc,
		noNewPrivs:   cfg.NoNewPrivs || seccompRequested(cfg),
		seccompProg:  seccompProg,
		capMask:      capMask,
		readyFD:      readyFD,
		prisonerFD:   prisonerFD,
		prisonerRead: prisonerReadFD,
		goFD:         int(goR.Fd()),
		prisoner:     prisoner,
		init:         initSpec,
	}
	if err := clearCloseOnExec(int(goR.Fd())); err != nil {
		goR.Close()
		goW.Close()
		return 0, 0, fmt.Errorf("jail: keep jail init release descriptor: %w", err)
	}
	runtime.KeepAlive(goR)

	pid := spawnRawInit()
	goR.Close()
	if pid < 0 {
		goW.Close()
		initPlan.launch = false
		return 0, 0, fmt.Errorf("jail: fork jail init: %w", syscall.Errno(-pid))
	}
	if err := writeInitPID(initPIDFD, pid); err != nil {
		if killErr := syscall.Kill(pid, syscall.SIGKILL); killErr != nil {
			goW.Close()
			return 0, 0, fmt.Errorf("jail: report jail init pid: %w (kill: %v)", err, killErr)
		}
		if _, waitErr := syscall.Wait4(pid, nil, 0, nil); waitErr != nil {
			goW.Close()
			return 0, 0, fmt.Errorf("jail: report jail init pid: %w (reap: %v)", err, waitErr)
		}
		goW.Close()
		initPlan.launch = false
		return 0, 0, err
	}
	return pid, int(goW.Fd()), nil
}

func cellMountPoints(rootfs string) (devRoot, tmpRoot string, err error) {
	devRoot, tmpRoot = "/dev", "/tmp"
	if rootfs == "" {
		return devRoot, tmpRoot, nil
	}
	absRoot, err := filepath.Abs(rootfs)
	if err != nil {
		return "", "", err
	}
	for _, dir := range []string{"dev", "tmp"} {
		if err := os.MkdirAll(filepath.Join(absRoot, dir), 0o755); err != nil {
			return "", "", fmt.Errorf("jail: create %s in cell: %w", dir, err)
		}
	}
	return filepath.Join(absRoot, "dev"), filepath.Join(absRoot, "tmp"), nil
}

func writeInitPID(fd, pid int) error {
	if _, err := fmt.Fprintf(os.NewFile(uintptr(fd), "init-pid"), "%c%d\n", syncInit, pid); err != nil {
		return fmt.Errorf("jail: report jail init pid: %w", err)
	}
	return nil
}

func waitForInit(initPID int) int {
	var ws syscall.WaitStatus
	for {
		pid, err := syscall.Wait4(initPID, &ws, 0, nil)
		if err == nil && pid == initPID {
			return exitStatusCode(ws)
		}
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "jail: wait jail init: %v\n", err)
			return 1
		}
	}
}

func closeFD(fd int) error {
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("jail: close descriptor %d: %w", fd, err)
	}
	return nil
}

func waitRelease(fd int) error {
	f := os.NewFile(uintptr(fd), "release")
	if f == nil {
		return errors.New("jail: release descriptor is not open")
	}
	defer f.Close()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(f, buf); err != nil {
		return fmt.Errorf("jail: release: %w", err)
	}
	if buf[0] != syncReady {
		return errors.New("jail: unexpected release marker")
	}
	return nil
}

func releaseInit(fd int) error {
	if _, err := syscall.Write(fd, []byte{syncReady}); err != nil {
		return fmt.Errorf("jail: release jail init: %w", err)
	}
	return nil
}

func reportInitFailure(fd int, err error) {
	fmt.Fprintf(os.Stderr, "jail stager: %v\n", err)
	f := os.NewFile(uintptr(fd), "sync-out")
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%c%v\n", syncFail, err)
}

func setHostname(hostname string) error {
	if hostname == "" {
		return nil
	}
	if len(hostname) > 64 {
		return fmt.Errorf("jail: hostname %q is too long", hostname)
	}
	if err := syscall.Sethostname([]byte(hostname)); err != nil {
		return fmt.Errorf("jail: set hostname %q: %w", hostname, err)
	}
	return nil
}

func makeMountsPrivate() error {
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("jail: make mount tree private: %w", err)
	}
	return nil
}

func mountTmp(root string) error {
	if err := ensureDir(root); err != nil {
		return fmt.Errorf("jail: create %s: %w", root, err)
	}
	if err := syscall.Mount("tmpfs", root, "tmpfs",
		syscall.MS_NOSUID|syscall.MS_NODEV, "mode=1777"); err != nil {
		return fmt.Errorf("jail: mount %s: %w", root, err)
	}
	return nil
}

func makeCellReadOnly() error {
	if err := syscall.Mount("", "/", "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("jail: make cell root read-only: %w", err)
	}
	return nil
}

func enterCell(cfg *InitConfig) error {
	absRoot, err := filepath.Abs(cfg.Rootfs)
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
	mountInfo, mountInfoErr := hostMountInfo()

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
		if err := chdirWorkDir(cfg.WorkDir); err != nil {
			return err
		}
		if err := syscall.Unmount("/.oldroot", syscall.MNT_DETACH); err != nil {
			return fmt.Errorf("jail: unmount .oldroot: %w", err)
		}
		if err := removeOldRoot(mountInfo, mountInfoErr); err != nil {
			return err
		}
		return nil
	}

	if err := os.RemoveAll(putOld); err != nil {
		return fmt.Errorf("jail: remove .oldroot: %w", err)
	}
	if err := syscall.Chroot(absRoot); err != nil {
		return fmt.Errorf("jail: pivot_root and chroot both failed: %w", err)
	}
	return chdirWorkDir(cfg.WorkDir)
}

func hostMountInfo() ([]byte, error) {
	return os.ReadFile("/proc/self/mountinfo")
}

func removeOldRoot(mountInfo []byte, mountInfoErr error) error {
	err := os.Remove("/.oldroot")
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	if !errors.Is(err, syscall.EBUSY) && !errors.Is(err, syscall.ENOTEMPTY) {
		return fmt.Errorf("jail: remove .oldroot: %w", err)
	}
	return verifyOldRootDetached(mountInfo, mountInfoErr)
}

func verifyOldRootDetached(mountInfo []byte, mountInfoErr error) error {
	if mountInfoErr != nil {
		return fmt.Errorf("jail: verify old root is detached: %w", mountInfoErr)
	}
	for _, line := range strings.Split(string(mountInfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if fields[4] == "/.oldroot" {
			return errors.New("jail: old root is still mounted at /.oldroot")
		}
	}
	entries, err := os.ReadDir("/.oldroot")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("jail: verify old root is detached: %w", err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("jail: old root is still reachable through /.oldroot: %d entries", len(entries))
	}
	return nil
}

func chdirWorkDir(workDir string) error {
	if workDir == "" {
		workDir = "/"
	}
	if err := syscall.Chdir(workDir); err != nil {
		return fmt.Errorf("jail: chdir %s: %w", workDir, err)
	}
	return nil
}

func ensureDir(name string) error {
	return os.MkdirAll(name, 0o755)
}

func teardownMounts() error {
	var failures []error
	for _, p := range []string{"/proc", "/dev", "/tmp", "/.oldroot"} {
		if err := syscall.Unmount(p, syscall.MNT_DETACH); err != nil && err != syscall.EINVAL && err != syscall.ENOENT {
			failures = append(failures, fmt.Errorf("unmount %s: %w", p, err))
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	return nil
}

type jailDevice struct {
	name         string
	major, minor uint32
}

var jailDevices = []jailDevice{
	{"null", 1, 3},
	{"zero", 1, 5},
	{"full", 1, 7},
	{"random", 1, 8},
	{"urandom", 1, 9},
	{"tty", 5, 0},
}

var jailDeviceDirs = []struct {
	name string
	mode os.FileMode
}{
	{"pts", 0o755},
	{"shm", 0o1777},
}

var jailDeviceLinks = []struct {
	name   string
	target string
}{
	{"fd", "/proc/self/fd"},
	{"stdin", "/proc/self/fd/0"},
	{"stdout", "/proc/self/fd/1"},
	{"stderr", "/proc/self/fd/2"},
}

var jailMaskedDevices = []string{"mem", "kmem", "port", "kmsg", "mqueue", "full", "random"}

func setupDev(root string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("jail: create %s: %w", root, err)
	}
	if err := syscall.Mount("tmpfs", root, "tmpfs", syscall.MS_NOSUID, "mode=0755"); err != nil {
		return fmt.Errorf("jail: mount %s: %w", root, err)
	}
	for _, d := range jailDevices {
		if err := provideDevice(root, d); err != nil {
			return err
		}
	}
	for _, d := range jailDeviceDirs {
		path := filepath.Join(root, d.name)
		if err := os.MkdirAll(path, d.mode); err != nil {
			return fmt.Errorf("jail: create %s: %w", path, err)
		}
		if err := os.Chmod(path, d.mode); err != nil {
			return fmt.Errorf("jail: chmod %s: %w", path, err)
		}
	}
	for _, l := range jailDeviceLinks {
		path := filepath.Join(root, l.name)
		if err := os.Symlink(l.target, path); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("jail: create %s -> %s: %w", path, l.target, err)
			}
		}
	}
	if err := maskHostDevices(root); err != nil {
		return err
	}
	return verifyDevNull(root)
}

func provideDevice(root string, d jailDevice) error {
	target := filepath.Join(root, d.name)
	if err := createDevicePlaceholder(target, d); err != nil {
		return err
	}
	source := filepath.Join("/dev", d.name)
	if _, err := os.Stat(source); err != nil {
		return fmt.Errorf("jail: device %s is unavailable on the host: %w", source, err)
	}
	if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("jail: bind %s into the jail: %w", source, err)
	}
	return nil
}

func createDevicePlaceholder(path string, d jailDevice) error {
	dev := int(mkdev(d.major, d.minor))
	if err := syscall.Mknod(path, syscall.S_IFCHR|0o666, dev); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("jail: create %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o666)
	if err != nil {
		return fmt.Errorf("jail: create %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("jail: close %s: %w", path, err)
	}
	return nil
}

func maskHostDevices(root string) error {
	for _, name := range jailMaskedDevices {
		if name == "full" || name == "random" {
			continue
		}
		target := filepath.Join(root, name)
		if _, err := os.Lstat(target); err != nil {
			continue
		}
		nullPath := filepath.Join(root, "null")
		if err := syscall.Mount(nullPath, target, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("jail: mask %s: %w", target, err)
		}
	}
	return nil
}

func mkdev(major, minor uint32) uint64 {
	return (uint64(major) << 8) | uint64(minor)
}

func verifyDevNull(root string) error {
	f, err := os.OpenFile(filepath.Join(root, "null"), os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("jail: verify /dev/null: %w", err)
	}
	defer f.Close()
	if _, err := f.Write([]byte{0}); err != nil {
		return fmt.Errorf("jail: verify /dev/null is writable: %w", err)
	}
	return nil
}

func applyNoNewPrivsPolicy(cfg *InitConfig) error {
	if !cfg.NoNewPrivs && !seccompRequested(cfg) {
		return nil
	}
	if err := ensureNewPrivs(); err != nil {
		return err
	}
	return nil
}

func resolvePrisonerCommand(cfg *InitConfig) ([]string, error) {
	argv := append([]string(nil), cfg.Args...)
	name := argv[0]
	if strings.ContainsRune(name, '/') {
		abs, err := filepath.Abs(name)
		if err != nil {
			return nil, fmt.Errorf("jail: resolve prisoner command %q: %w", name, err)
		}
		if err := verifyExecutable(abs); err != nil {
			return nil, err
		}
		argv[0] = abs
		return argv, nil
	}
	resolved, err := lookPathInJail(name, prisonerPath(cfg))
	if err != nil {
		return nil, err
	}
	argv[0] = resolved
	return argv, nil
}

func prisonerPath(cfg *InitConfig) string {
	if cfg.Env != nil {
		for _, e := range cfg.Env {
			if strings.HasPrefix(e, "PATH=") {
				return e[len("PATH="):]
			}
		}
	}
	return strings.TrimPrefix(jailPathEnv, "PATH=")
}

func verifyExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("jail: prisoner command %q: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("jail: prisoner command %q is a directory", path)
	}
	if info.Mode().IsRegular() && info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("jail: prisoner command %q is not executable (mode %s)", path, info.Mode().Perm())
	}
	if interp, ok := elfInterpreter(path); ok && interp != "" {
		if _, err := os.Stat(interp); err != nil {
			return fmt.Errorf("jail: prisoner command %q needs ELF interpreter %q: %w", path, interp, err)
		}
	}
	return nil
}

func elfInterpreter(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	header := make([]byte, 64)
	if _, err := io.ReadFull(f, header); err != nil {
		return "", false
	}
	if !isELF(header) {
		return "", false
	}
	phoff := binary.LittleEndian.Uint64(header[32:40])
	phentsize := binary.LittleEndian.Uint16(header[54:56])
	phnum := binary.LittleEndian.Uint16(header[56:58])
	if phnum == 0 || phentsize < 56 {
		return "", false
	}
	if _, err := f.Seek(int64(phoff), io.SeekStart); err != nil {
		return "", false
	}
	entry := make([]byte, int(phentsize)*int(phnum))
	if _, err := io.ReadFull(f, entry); err != nil {
		return "", false
	}
	for i := 0; i < int(phnum); i++ {
		rec := entry[i*int(phentsize):]
		if binary.LittleEndian.Uint32(rec[0:4]) != elfPTInterp {
			continue
		}
		offset := binary.LittleEndian.Uint64(rec[8:16])
		size := binary.LittleEndian.Uint64(rec[32:40])
		if size == 0 || size > 4096 {
			return "", false
		}
		buf := make([]byte, size)
		if _, err := f.ReadAt(buf, int64(offset)); err != nil {
			return "", false
		}
		return strings.TrimRight(string(buf), "\x00"), true
	}
	return "", false
}

const elfPTInterp = 3

func isELF(header []byte) bool {
	return len(header) >= 20 && header[0] == 0x7f && header[1] == 'E' &&
		header[2] == 'L' && header[3] == 'F'
}

func marshalConfig(cfg *InitConfig) ([]byte, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("jail: encode init config: %w", err)
	}
	return data, nil
}

func parseInitPID(line string) int {
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		return 0
	}
	return pid
}
