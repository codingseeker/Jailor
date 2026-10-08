//go:build linux && jailor_priv

package jail

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"jailor/internal/bars"
)

var namespaceSupport struct {
	once sync.Once
	ok   bool
}

func canUseNamespaces() bool {
	namespaceSupport.once.Do(func() {
		if os.Geteuid() == 0 {
			namespaceSupport.ok = true
			return
		}
		namespaceSupport.ok = probeUserNamespace()
	})
	return namespaceSupport.ok
}

//go:noinline
func probeUserNamespace() bool {
	const sysClone = 56
	r, _, errno := syscall.RawSyscall(sysClone, uintptr(syscall.CLONE_NEWUSER)|uintptr(syscall.SIGCHLD), 0, 0)
	if errno != 0 {
		return false
	}
	if r == 0 {
		syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 0, 0, 0)
		for {
		}
	}
	var ws syscall.WaitStatus
	for {
		pid, err := syscall.Wait4(int(r), &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return false
		}
		if pid == int(r) {
			return ws.Exited() && ws.ExitStatus() == 0
		}
	}
}

func runJail(t *testing.T, kinds []bars.Kind, userns bool, probeKind string, hostname string) (string, int) {
	t.Helper()
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}

	out := &syncBuf{}

	cfg := &InitConfig{
		Args:      []string{testExe, "__probe", probeKind},
		Hostname:  hostname,
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,
	}
	opts := SpawnOpts{
		Init:       *cfg,
		Namespaces: kinds,
		Userns:     userns,
		Stdout:     out,
		Stderr:     out,
	}
	if userns {
		opts.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}
		opts.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}
	}

	child, err := Spawn(opts, cfg)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	code := child.Wait()
	return out.String(), code
}
func runCell(t *testing.T, userns bool, probeKind string, hostname string) (string, int) {
	t.Helper()
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}

	out := &syncBuf{}

	cfg := &InitConfig{
		Args:      []string{testExe, "__probe", probeKind},
		Hostname:  hostname,
		MountProc: true,
		MountTmp:  false,
		MountDev:  true,
	}
	opts := SpawnOpts{
		Init:       *cfg,
		Namespaces: []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:     userns,
		Stdout:     out,
		Stderr:     out,
	}
	if userns {
		opts.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}
		opts.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}
	}

	child, err := Spawn(opts, cfg)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	code := child.Wait()
	return out.String(), code
}

func TestPIDIsolation(t *testing.T) {
	out, code := runJail(t, []bars.Kind{bars.PID, bars.UTS, bars.Mount}, true, "pid", "isol-pid")
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)

	if m["pid"] != "2" {
		t.Errorf("Prisoner should see itself as PID 2 (init is PID 1), got %q", m["pid"])
	}
	if m["ppid"] != "1" {
		t.Errorf("Prisoner PPID should be 1 (the jail init), got %q", m["ppid"])
	}
}

func TestPIDDiffersFromHost(t *testing.T) {

	hostPID := os.Getpid()
	out, _ := runJail(t, []bars.Kind{bars.PID, bars.UTS, bars.Mount}, true, "pid", "isol-pid2")
	m := parseKV(out)
	if m["pid"] == "1" || m["pid"] == strconv.Itoa(hostPID) {
		t.Errorf("jail pid %s must not match the host pid %d or be 1", m["pid"], hostPID)
	}
	t.Logf("host pid=%d, jail pid=%s (distinct PID namespace)", hostPID, m["pid"])
}

func TestUTSIsolation(t *testing.T) {
	host, _ := os.Hostname()
	inside := "jail-test-host"
	out, code := runJail(t, []bars.Kind{bars.PID, bars.UTS, bars.Mount}, true, "hostname", inside)
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)
	if m["hostname"] != inside {
		t.Errorf("Prisoner should see hostname %q, got %q", inside, m["hostname"])
	}

	if cur, _ := os.Hostname(); cur != host {
		t.Errorf("host hostname changed: was %q now %q", host, cur)
	}
}

func TestNetworkIsolation(t *testing.T) {
	out, code := runJail(t, []bars.Kind{bars.PID, bars.UTS, bars.Mount, bars.Network}, true, "net", "isol-net")
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)

	seen := strings.Split(m["net"], ",")
	if len(seen) == 1 && seen[0] == "lo" {
		return
	}
	t.Errorf("network namespace should expose only lo, got %q", m["net"])
}

func TestUserNamespaceMapping(t *testing.T) {
	out, code := runJail(t, []bars.Kind{bars.PID, bars.UTS, bars.Mount}, true, "hostname", "userns-test")
	if code != 0 {
		t.Fatalf("User-namespaced Jail failed, code=%d out=%s", code, out)
	}
}

func TestProcShowsJailPID1(t *testing.T) {

	out, code := runCell(t, true, "proc1", "proc-test")
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)
	if m["proc1_pid"] != "1" {
		t.Errorf("/proc/1/Pid should be 1, got %q", m["proc1_pid"])
	}
	if m["proc1_ppid"] != "0" {
		t.Errorf("/proc/1/PPid should be 0, got %q", m["proc1_ppid"])
	}
}

func TestInitIsJailPID1(t *testing.T) {

	out, code := runCell(t, true, "init1", "init-test")
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)
	if !strings.Contains(m["init1"], "__init") {
		t.Errorf("/proc/1/cmdline should show the jail init (__init), got %q", m["init1"])
	}
}

func TestExitCodeSignal(t *testing.T) {

	code, err := runCmd(t, []string{testExe, "__probe", "selfterm"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if want := 128 + int(syscall.SIGTERM); code != want {
		t.Errorf("exit code = %d, want %d (SIGTERM)", code, want)
	}
}

func TestOrphanReaping(t *testing.T) {
	out, code := runCell(t, true, "orfarm", "orphan-test")
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)
	if m["orfarm_zombies"] != "0" {
		t.Errorf("orphaned grandchildren left zombies: %q", m["orfarm_zombies"])
	}
}

func TestPrisonerIsChildOfInit(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	out := &syncBuf{}
	cfg := &InitConfig{
		Args:      []string{testExe, "__probe", "sleep"},
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,
	}
	opts := SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      out,
		Stderr:      out,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}
	child, err := Spawn(opts, cfg)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	initHost := child.PID()
	nsPrisoner := child.PrisonerPID()
	hostPrisoner := FindPrisonerHostPID(initHost)
	if nsPrisoner != 2 {
		t.Errorf("prisoner ns pid = %d, want 2 (only the init precedes it)", nsPrisoner)
	}
	if hostPrisoner <= 0 {
		t.Fatalf("could not resolve prisoner host pid under init %d", initHost)
	}
	if hostPrisoner == initHost {
		t.Error("prisoner host pid must differ from the init host pid")
	}
	if err := syscall.Kill(hostPrisoner, 0); err != nil {
		t.Errorf("prisoner host pid %d not alive: %v", hostPrisoner, err)
	}
	if err := child.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill init: %v", err)
	}
	if code := child.Wait(); code != 128+int(syscall.SIGKILL) {
		t.Errorf("init exit code = %d, want %d (SIGKILL tears down the namespace)", code, 128+int(syscall.SIGKILL))
	}
	if err := syscall.Kill(hostPrisoner, 0); err == nil {
		t.Error("prisoner still alive after init was killed")
	}
}

func TestTerminateEscalatesToKill(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	out := &syncBuf{}
	cfg := &InitConfig{
		Args:      []string{testExe, "__probe", "sigignore"},
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,
		Env:       []string{"PATH=/usr/bin:/bin"},
	}
	opts := SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      out,
		Stderr:      out,
		Env:         []string{"JAILOR_ESCALATE_AFTER=500ms", "PATH=/usr/bin:/bin"},
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}
	child, err := Spawn(opts, cfg)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	if err := waitOutput(t, out, "sigignore=ready"); err != nil {
		t.Fatal(err)
	}
	if err := child.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}
	start := time.Now()
	code := child.Wait()
	if want := 128 + int(syscall.SIGKILL); code != want {
		t.Errorf("exit code = %d, want %d (escalated SIGKILL); output: %s", code, want, out.String())
	}
	if got := time.Since(start); got > 8*time.Second {
		t.Errorf("escalation took too long: %v", got)
	}
}

func TestTmpDirCreated(t *testing.T) {

	out, code := runCell(t, true, "tmp", "tmp-test")
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)
	if m["tmp"] != "tmp-ok" {
		t.Errorf("/tmp write/read round-trip failed, got %q", m["tmp"])
	}
}

func TestDevMinimal(t *testing.T) {

	out, code := runCell(t, true, "dev", "dev-test")
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)
	devs := strings.Split(m["dev"], ",")
	has := func(n string) bool {
		for _, d := range devs {
			if d == n {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"fd", "stdin", "stdout", "stderr", "pts", "shm"} {
		if !has(want) {
			t.Errorf("/dev/%s missing (got %q)", want, m["dev"])
		}
	}
}

func TestPsCountsOnlyJailProcesses(t *testing.T) {

	out, code := runCell(t, true, "pscount", "ps-test")
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)
	var count int
	fmt.Sscanf(m["pscount"], "%d", &count)
	if count == 0 {
		t.Error("pscount: expected at least the probe process itself")
	}

	if count > 20 {
		t.Errorf("pscount=%d is too high — jail is leaking host processes", count)
	}
}

func runConfigured(t *testing.T, cfg *InitConfig, userns bool) (string, int) {
	t.Helper()
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	out := &syncBuf{}
	opts := SpawnOpts{
		Init:       *cfg,
		Namespaces: []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:     userns,
		Stdout:     out,
		Stderr:     out,
	}
	if userns {
		opts.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}
		opts.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}
	}
	child, err := Spawn(opts, cfg)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err != nil {
		t.Fatalf("read ready: %v (output: %s)", err, out.String())
	}
	code := child.Wait()
	return out.String(), code
}

func TestCapabilitiesDropped(t *testing.T) {

	out, code := runConfigured(t, &InitConfig{
		Args:         []string{testExe, "__probe", "caps"},
		MountProc:    false,
		MountTmp:     false,
		MountDev:     false,
		Capabilities: []string{"CAP_CHOWN"},
	}, true)
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)

	if m["caps_capeff"] != "0000000000000001" {
		t.Errorf("CapEff should be 1 (only CAP_CHOWN), got %q", m["caps_capeff"])
	}
	if m["caps_capbnd"] != "0000000000000001" {
		t.Errorf("CapBnd should be 1 (only CAP_CHOWN), got %q", m["caps_capbnd"])
	}
}

func TestSeccompDeniesForbiddenSyscall(t *testing.T) {
	out, code := runConfigured(t, &InitConfig{
		Args:      []string{testExe, "__probe", "mount-try"},
		MountProc: true,
		MountTmp:  false,
		MountDev:  false,
		Seccomp:   true,
	}, true)
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)
	if strings.HasPrefix(m["mount_try"], "err:") &&
		(strings.Contains(m["mount_try"], "operation not permitted") ||
			strings.Contains(m["mount_try"], "EPERM")) {
		return
	}
	t.Errorf("mount should be denied by seccomp (EPERM), got %q", m["mount_try"])
}

func TestUnknownSeccompProfileFailsClosed(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	out := &syncBuf{}
	cfg := &InitConfig{
		Args:           []string{testExe, "__probe", "seccomp-try"},
		MountProc:      false,
		MountTmp:       false,
		MountDev:       false,
		SeccompProfile: "profane",
	}
	opts := SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      out,
		Stderr:      out,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}
	child, err := Spawn(opts, cfg)
	if err != nil {
		t.Fatalf("spawn must succeed so the init can fail: %v", err)
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err == nil {
		t.Fatalf("unknown seccomp profile must fail closed, init became ready")
	}
	code := child.Wait()
	if code == 0 {
		t.Fatalf("init must exit non-zero after refusing to apply the profile")
	}
}

func TestUnknownLSMFailsClosed(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	out := &syncBuf{}
	cfg := &InitConfig{
		Args:      []string{testExe, "__probe", "lsm-try"},
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,

		LSM: "apparmor:garbage-profile-that-cannot-exist",
	}
	opts := SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      out,
		Stderr:      out,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}
	child, err := Spawn(opts, cfg)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err == nil {
		t.Fatalf("ungrantable LSM transition must fail closed, init became ready")
	}
	code := child.Wait()
	if code == 0 {
		t.Fatalf("init must exit non-zero after refusing the LSM transition")
	}
}

func TestReadOnlyCellUserNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("a read-only Cell needs host root to remount a superblock, euid is %d", os.Geteuid())
	}
	cell := scratchCell(t)
	out := &syncBuf{}
	cfg := &InitConfig{
		Args:      cellProbeArgs(t, cell, "write-root"),
		Rootfs:    cell,
		MountProc: true,
		MountDev:  true,
		ReadOnly:  true,
	}
	opts := SpawnOpts{
		Init:       *cfg,
		Namespaces: []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Stdout:     out,
		Stderr:     out,
	}
	child, err := Spawn(opts, cfg)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err != nil {
		t.Fatalf("read ready: %v (output: %s)", err, out.String())
	}
	if code := child.Wait(); code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "write_root=err") {
		t.Errorf("write to a read-only Cell root must fail, got %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(cell, "jailor-readonly-test")); err == nil {
		t.Error("read-only Cell accepted a write at the Cell root")
	}
}

func TestReadOnlyCellKeepsCellReadable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("a read-only Cell needs host root to remount a superblock, euid is %d", os.Geteuid())
	}
	cell := scratchCell(t)
	if err := os.WriteFile(filepath.Join(cell, "readable-marker"), []byte("visible"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := &syncBuf{}
	cfg := &InitConfig{
		Args:      cellProbeArgs(t, cell, "read", "/readable-marker"),
		Rootfs:    cell,
		MountProc: true,
		MountDev:  true,
		ReadOnly:  true,
	}
	opts := SpawnOpts{
		Init:       *cfg,
		Namespaces: []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Stdout:     out,
		Stderr:     out,
	}
	child, err := Spawn(opts, cfg)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err != nil {
		t.Fatalf("read ready: %v (output: %s)", err, out.String())
	}
	if code := child.Wait(); code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "readable:visible") {
		t.Errorf("a read-only Cell must stay readable, got %s", out.String())
	}
}

func TestReadOnlyCellRejectsHostRoot(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	out := &syncBuf{}
	cfg := &InitConfig{
		Args:      []string{testExe, "__probe", "write-root"},
		MountProc: true,
		MountDev:  true,
		ReadOnly:  true,
	}
	opts := SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      out,
		Stderr:      out,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}
	child, err := Spawn(opts, cfg)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err == nil {
		t.Fatal("read-only mode without a Cell must fail instead of remounting the host root")
	}
	if code := child.Wait(); code == 0 {
		t.Fatal("the jail must report failure for read-only mode without a Cell")
	}
}

func TestReadOnlyCell(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("pivot_root into the Cell needs host root, euid is %d", os.Geteuid())
	}

	cell := scratchCell(t)
	out := &syncBuf{}
	cfg := &InitConfig{
		Args:      []string{"/bin/sh", "-c", "if touch /ro-marker 2>/dev/null; then echo writable; else echo readonly; fi"},
		Rootfs:    cell,
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,
		ReadOnly:  true,
	}
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	opts := SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      out,
		Stderr:      out,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}
	child, err := Spawn(opts, cfg)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err != nil {
		t.Fatalf("read ready: %v (output: %s)", err, out.String())
	}
	code := child.Wait()
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "readonly") {
		t.Errorf("write to read-only Cell root should fail, got output %q", out.String())
	}
}

func scratchCell(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "..", "rootfs")
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("the privileged tier requires a prepared Cell rootfs at %s: %v", src, err)
	}
	dst := filepath.Join(t.TempDir(), "cell")
	if err := copyTree(src, dst); err != nil {
		t.Fatalf("copy rootfs: %v", err)
	}
	return dst
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}
