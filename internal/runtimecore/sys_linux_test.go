package runtimecore

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func mustSleep(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "3600")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd
}

func TestExitCodeNormal(t *testing.T) {
	if got := ExitCode(syscall.WaitStatus(0x700)); got != 7 {
		t.Fatalf("ExitCode(exit 7) = %d, want 7", got)
	}
}

func TestExitCodeSignal(t *testing.T) {
	if got := ExitCode(syscall.WaitStatus(0x0f)); got != 143 {
		t.Fatalf("ExitCode(SIGTERM) = %d, want 143", got)
	}
}

func TestAlive(t *testing.T) {
	if !Alive(os.Getpid()) {
		t.Fatal("Alive(self) = false")
	}
	if Alive(1 << 20) {
		t.Fatal("Alive(fake pid) = true")
	}
}

func TestStatPPIDAndPID(t *testing.T) {
	self := fmt.Sprintf("/proc/%d/stat", os.Getpid())
	if got := statPPID(self); got != os.Getppid() {
		t.Fatalf("statPPID(%s) = %d, want ppid %d", self, got, os.Getppid())
	}
	if got := statPID(self); got != os.Getpid() {
		t.Fatalf("statPID(%s) = %d, want %d", self, got, os.Getpid())
	}
}

func TestChildHostPID(t *testing.T) {
	if got := ChildHostPID(1 << 20); got != 0 {
		t.Fatalf("ChildHostPID(fake) = %d, want 0", got)
	}
	cmd := mustSleep(t)
	pid := cmd.Process.Pid
	if got := ChildHostPID(os.Getpid()); got != pid {
		t.Fatalf("ChildHostPID(self) = %d, want spawned child %d", got, pid)
	}
}

func TestNSPidsFormat(t *testing.T) {
	ids := NSPids(os.Getpid())
	if len(ids) < 1 {
		t.Fatalf("NSPids(self) is empty")
	}
	if ids[0] != os.Getpid() {
		t.Fatalf("NSPids(self)[0] = %d, want %d", ids[0], os.Getpid())
	}
	if got := InnermostPID(os.Getpid()); got != os.Getpid() {
		t.Fatalf("InnermostPID(self) = %d, want %d", got, os.Getpid())
	}
}

func TestNSPidsMissing(t *testing.T) {
	if ids := NSPids(1 << 20); len(ids) != 0 {
		t.Fatalf("NSPids(fake) is not empty: %q", ids)
	}
}
