//go:build linux && jailor_priv

package jail

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"jailor/internal/bars"
)

func securityProbeArgs(args ...string) []string {
	return append([]string{testExe, "__probe"}, args...)
}

func securityJail(t *testing.T, cfg *InitConfig) string {
	t.Helper()
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	if cfg.Rootfs != "" && len(cfg.Args) > 0 && cfg.Args[0] == testExe {
		cfg.Args = append([]string{copyProbeIntoCell(t, cfg.Rootfs)}, cfg.Args[1:]...)
	}
	out, code := runConfigured(t, cfg, true)
	if code != 0 {
		t.Fatalf("jail exited with %d: %s", code, out)
	}
	return out
}

func TestEscapeOldRootIsInaccessible(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("read-only Cell assertions require host root to remount a superblock, euid is %d", os.Geteuid())
	}
	cell := scratchCell(t)
	if err := os.WriteFile(filepath.Join(cell, "marker"), []byte("cell-only"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("read", "/.oldroot/marker"),
		Rootfs:    cell,
		MountProc: true,
		MountDev:  true,
	})
	if !strings.Contains(out, "err:") {
		t.Errorf("the old root must not be reachable through the jail: %s", out)
	}
}

func TestEscapeOldRootMountPointRemoved(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("read-only Cell assertions require host root to remount a superblock, euid is %d", os.Geteuid())
	}
	cell := scratchCell(t)
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("stat", "/.oldroot"),
		Rootfs:    cell,
		MountProc: true,
		MountDev:  true,
	})
	if !strings.Contains(out, "err:") {
		t.Errorf("/.oldroot must not exist inside the jail: %s", out)
	}
}

func TestEscapeHostRootNotVisibleInCell(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("Cell assertions require host root, euid is %d", os.Geteuid())
	}
	cell := scratchCell(t)
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("stat", "/home"),
		Rootfs:    cell,
		MountProc: true,
		MountDev:  true,
	})
	if strings.Contains(out, "mode:") {
		t.Errorf("host directories must not be visible inside the Cell: %s", out)
	}
}

func TestEscapeParentTraversalIsContained(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("Cell assertions require host root, euid is %d", os.Geteuid())
	}
	cell := scratchCell(t)
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("traverse", "/../../../../etc/passwd"),
		Rootfs:    cell,
		MountProc: true,
		MountDev:  true,
	})
	if strings.Contains(out, "readable:") {
		t.Errorf("parent traversal escaped the Cell: %s", out)
	}
}

func TestEscapeSymlinkTraversalIsContained(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("Cell assertions require host root, euid is %d", os.Geteuid())
	}
	cell := scratchCell(t)
	link := filepath.Join(cell, "escape")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatal(err)
	}
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("read", "/escape"),
		Rootfs:    cell,
		MountProc: true,
		MountDev:  true,
	})
	if strings.Contains(out, "readable:") {
		t.Errorf("a Cell symlink must not expose host files: %s", out)
	}
}

func TestCellRootFilesAreReachable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("Cell assertions require host root, euid is %d", os.Geteuid())
	}
	cell := scratchCell(t)
	if err := os.WriteFile(filepath.Join(cell, "marker"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("read", "/marker"),
		Rootfs:    cell,
		MountProc: true,
		MountDev:  true,
	})
	if !strings.Contains(out, "readable:inside") {
		t.Errorf("Cell files must be readable inside the jail: %s", out)
	}
}

func TestEscapeUnauthorizedMountIsDenied(t *testing.T) {
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("mount-try"),
		MountProc: false,
		MountDev:  false,
		Capabilities: []string{
			"CAP_CHOWN",
		},
	})
	if strings.Contains(out, "mount_try=ok") {
		t.Errorf("mount must be denied without CAP_SYS_ADMIN: %s", out)
	}
}

func TestEscapeUnshareIsDeniedWithoutSysAdmin(t *testing.T) {
	out := securityJail(t, &InitConfig{
		Args:         securityProbeArgs("unshare-try", "user"),
		MountProc:    false,
		MountDev:     false,
		Capabilities: []string{"CAP_CHOWN"},
	})
	if strings.Contains(out, "unshare=ok") {
		t.Errorf("unshare must be denied without CAP_SYS_ADMIN: %s", out)
	}
}

func TestEscapeNamespaceCloneIsDeniedWithoutSysAdmin(t *testing.T) {
	out := securityJail(t, &InitConfig{
		Args:         securityProbeArgs("clone-try", "mount"),
		MountProc:    false,
		MountDev:     false,
		Capabilities: []string{"CAP_CHOWN"},
	})
	if strings.Contains(out, "clone=ok") {
		t.Errorf("clone with a namespace flag must be denied without CAP_SYS_ADMIN: %s", out)
	}
}

func TestEscapeSeccompDeniesUnshare(t *testing.T) {
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("unshare-try", "user"),
		MountProc: false,
		MountDev:  false,
		Seccomp:   true,
	})
	if strings.Contains(out, "unshare=ok") {
		t.Errorf("the default seccomp profile must deny unshare: %s", out)
	}
}

func TestEscapeSeccompDeniesPtrace(t *testing.T) {
	if os.Geteuid() != 0 && !canUseNamespaces() {
		t.Fatalf("the privileged tier cannot create namespaces as euid %d", os.Geteuid())
	}
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("ptrace-try", "1"),
		MountProc: false,
		MountDev:  false,
		Seccomp:   true,
	})
	if strings.Contains(out, "ptrace=ok") {
		t.Errorf("the default seccomp profile must deny ptrace: %s", out)
	}
}

func TestEscapeSeccompAllowsOrdinaryWork(t *testing.T) {
	target := filepath.Join(t.TempDir(), "seccomp-work")
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("write", target),
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,
		Seccomp:   true,
	})
	if !strings.Contains(out, "ok") {
		t.Errorf("seccomp must not break ordinary work: %s", out)
	}
}

func TestEscapeSetuidCannotRaisePrivileges(t *testing.T) {
	out := securityJail(t, &InitConfig{
		Args:         securityProbeArgs("setuid-exec", "/usr/bin/id"),
		MountProc:    false,
		MountDev:     false,
		Capabilities: []string{"CAP_CHOWN"},
	})
	if strings.Contains(out, "setuid_exec=ok") {
		t.Errorf("the prisoner must not be able to regain privileges: %s", out)
	}
}

func TestEscapeDeviceAccessToHostDevicesDenied(t *testing.T) {
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("device-read", "/dev/mem"),
		MountProc: false,
		MountDev:  true,
	})
	if strings.Contains(out, "readable:") {
		t.Errorf("host memory devices must not be readable in the jail: %s", out)
	}
}

func TestEscapeMountPropagationStaysPrivate(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("mount-try"),
		MountProc: false,
		MountDev:  false,
	})
	if strings.Contains(out, "mount_try=ok") {
		t.Errorf("an unprivileged jail must not be able to mount: %s", out)
	}
}

func TestEscapeHostProcIsNotVisibleInCell(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("Cell assertions require host root, euid is %d", os.Geteuid())
	}
	cell := scratchCell(t)
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("hostproc-pid", "1"),
		Rootfs:    cell,
		MountProc: true,
		MountDev:  true,
	})
	if strings.Contains(out, "Uid:") && !strings.Contains(out, "Uid: 0") &&
		!strings.Contains(out, "Uid:\t0") {
		t.Errorf("the jail must not see the host init identity: %s", out)
	}
}

func TestEscapeNetworkNamespaceIsIsolated(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	hostNet := nsInode(mustReadlink(t, "/proc/self/ns/net"))

	out := &syncBuf{}
	cfg := &InitConfig{
		Args:      securityProbeArgs("ns", "net"),
		MountProc: false,
		MountDev:  false,
	}
	child, err := Spawn(SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount, bars.Network},
		Userns:      true,
		Stdout:      out,
		Stderr:      out,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}, cfg)
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
		t.Fatalf("read ready: %v (%s)", err, out.String())
	}
	if code := child.Wait(); code != 0 {
		t.Fatalf("exit code = %d (%s)", code, out.String())
	}
	jailNet := parseKV(out.String())["ns_net"]
	if jailNet == "" {
		t.Fatalf("no network namespace reported: %s", out.String())
	}
	if jailNet == hostNet {
		t.Errorf("prisoner shares the host network namespace %s", jailNet)
	}
}

func mustReadlink(t *testing.T, path string) string {
	t.Helper()
	link, err := os.Readlink(path)
	if err != nil {
		t.Fatalf("readlink %s: %v", path, err)
	}
	return link
}

func TestEscapeFDLeakage(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	secretPath := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(secretPath, []byte("host-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	leaked, err := os.Open(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	defer leaked.Close()
	if err := clearCloseOnExec(int(leaked.Fd())); err != nil {
		t.Fatal(err)
	}

	out, code := runConfigured(t, &InitConfig{
		Args:      securityProbeArgs("fds"),
		MountProc: false,
		MountDev:  false,
	}, true)
	if code != 0 {
		t.Fatalf("exit code = %d: %s", code, out)
	}
	if strings.Contains(out, "credential") || strings.Contains(out, "host-secret") {
		t.Errorf("a host descriptor leaked into the prisoner:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "fd=") {
			continue
		}
		idx := strings.Index(line, "->")
		if idx < 0 {
			continue
		}
		fd := strings.TrimSpace(line[3:idx])
		target := line[idx+2:]
		switch fd {
		case "0", "1", "2":
		default:
			if strings.HasPrefix(target, "anon_inode:") {
				continue
			}
			t.Errorf("unexpected descriptor %s visible inside the jail: %s", fd, line)
		}
	}
}

func TestEscapeSecretFileNotReachableInCell(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("Cell assertions require host root, euid is %d", os.Geteuid())
	}
	cell := scratchCell(t)
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("read", "/root/.ssh/id_ed25519"),
		Rootfs:    cell,
		MountProc: true,
		MountDev:  true,
	})
	if strings.Contains(out, "readable:") {
		t.Errorf("host credentials must not be reachable inside the Cell: %s", out)
	}
}

func TestEscapeSysIsNotVisibleInCell(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("Cell assertions require host root, euid is %d", os.Geteuid())
	}
	cell := scratchCell(t)
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("stat", "/sys"),
		Rootfs:    cell,
		MountProc: true,
		MountDev:  true,
	})
	if strings.Contains(out, "mode:") {
		t.Errorf("host /sys must not be visible inside the Cell: %s", out)
	}
}

func TestCleanupAfterNormalExit(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	target := filepath.Join(t.TempDir(), "cleanup-check")
	out := &syncBuf{}
	cfg := &InitConfig{
		Args:      securityProbeArgs("writecount", target, "16"),
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,
	}
	child, err := Spawn(SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      out,
		Stderr:      out,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}, cfg)
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
		t.Fatalf("read ready: %v (%s)", err, out.String())
	}
	initPID := child.PID()
	if code := child.Wait(); code != 0 {
		t.Fatalf("exit code = %d: %s", code, out.String())
	}
	assertNoJailProcesses(t, initPID)
}

func TestCleanupAfterInitFailure(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	out := &syncBuf{}
	cfg := &InitConfig{
		Args:           securityProbeArgs("caps"),
		SeccompProfile: "profane",
	}
	child, err := Spawn(SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      out,
		Stderr:      out,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}, cfg)
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
		t.Fatal("an unknown seccomp profile must prevent readiness")
	}
	if code := child.Wait(); code == 0 {
		t.Fatal("the jail must report failure with a non-zero status")
	}
	if pid := child.PID(); pid > 0 {
		assertNoJailProcesses(t, pid)
	}
}

func assertNoJailProcesses(t *testing.T, initPID int) {
	t.Helper()
	if initPID <= 0 {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(initPID))); err != nil {
			if child := FindPrisonerHostPID(initPID); child > 0 {
				t.Errorf("prisoner %d survived the jail init", child)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("jail init %d is still present after Wait", initPID)
}

func TestResourceForkBombIsBounded(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("forks", "64"),
		MountProc: false,
		MountDev:  false,
	})
	if !strings.Contains(out, "created:64:ok") && !strings.Contains(out, "err:") {
		t.Errorf("fork probe reported neither success nor a controlled failure: %s", out)
	}
	assertNoJailResidue(t)
}

func TestResourceMemoryExhaustionStaysInsideTheJail(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	target := filepath.Join(t.TempDir(), "memory-exhaustion")
	out, code := runConfigured(t, &InitConfig{
		Args:      securityProbeArgs("writecount", target, "65536"),
		MountProc: false,
		MountDev:  false,
	}, true)
	if code != 0 && !strings.Contains(out, "err:") {
		t.Errorf("a failed jail must report why it failed: %s", out)
	}
	if info, err := os.Stat(target); err == nil && info.Size() > 1<<30 {
		t.Errorf("jail wrote %d bytes into the host filesystem", info.Size())
	}
	assertNoJailResidue(t)
}

func TestResourceCPUThrottleKeepsJailResponsive(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	start := time.Now()
	out := securityJail(t, &InitConfig{
		Args:      securityProbeArgs("burncpu"),
		MountProc: false,
		MountDev:  false,
	})
	if !strings.Contains(out, "burncpu=ok") {
		t.Errorf("the jail must finish its work and report it: %s", out)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("500ms of jail CPU work took %v to complete", elapsed)
	}
}

func TestResourcePIDExhaustionIsBounded(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	out, code := runConfigured(t, &InitConfig{
		Args:      securityProbeArgs("forks", "16"),
		MountProc: false,
		MountDev:  false,
	}, true)
	if code != 0 && !strings.Contains(out, "err:") {
		t.Errorf("a failed jail must report why it failed: %s", out)
	}
	assertNoJailResidue(t)
}

func assertNoJailResidue(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		residue := jailHostProcesses(t)
		if len(residue) == 0 {
			return
		}
		if !time.Now().Before(deadline) {
			t.Errorf("jail processes remain on the host after Wait: %v", residue)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func jailHostProcesses(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("read /proc: %v", err)
	}
	self := os.Getpid()
	var residue []string
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == self {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		if len(args) < 2 {
			continue
		}
		if args[1] == StagerArg || args[1] == InitArg {
			residue = append(residue, entry.Name()+" "+strings.Join(args, " "))
		}
	}
	return residue
}
