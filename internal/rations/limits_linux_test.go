//go:build linux && jailor_priv

package rations

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func limitMount(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatalf("cgroup limits require host root, euid is %d", os.Geteuid())
	}
	mount, err := FindCgroupV2Mount()
	if err != nil {
		t.Fatalf("the privileged tier requires a cgroup v2 hierarchy: %v", err)
	}
	return mount
}

func TestMemoryLimitEnforced(t *testing.T) {
	mount := limitMount(t)

	cg, err := Create(mount, "mem-limit", Rations{MemoryLimitBytes: 32 * 1024 * 1024})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer cg.Remove()

	c, ok := startMemSucker(t)
	if !ok {
		t.Fatal("the privileged tier requires python3 on the runner to exercise the memory limit")
	}
	defer func() {
		_ = c.Process.Kill()
		_, _ = c.Process.Wait()
	}()
	if err := cg.AddPid(c.Process.Pid); err != nil {
		t.Fatalf("AddPid: %v", err)
	}
	if st, err := cg.Stats(); err != nil || st.MemoryMax != 32*1024*1024 {
		t.Errorf("MemoryMax = %d (%v), want %d", st.MemoryMax, err, 32*1024*1024)
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if procAlive(c.Process.Pid) == false {
			break
		}
		if evCount(cg.Path+"/memory.events", "oom_kill") > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if procAlive(c.Process.Pid) {
		t.Error("memory-limited Prisoner was not killed by its Rations")
	}
}

func startMemSucker(t *testing.T) (*exec.Cmd, bool) {
	t.Helper()

	c := exec.Command("python3", "-c",
		"x=bytearray()\nwhile True:\n    x+=b'0'*(16*1024*1024)")
	if err := c.Start(); err != nil {
		return nil, false
	}
	return c, true
}

func procAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil
}

func evCount(path, key string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == key {
			n, _ := strconv.Atoi(fields[1])
			return n
		}
	}
	return 0
}

func TestPIDLimitEnforced(t *testing.T) {
	mount := limitMount(t)

	cg, err := Create(mount, "pid-limit", Rations{PIDsLimit: 4})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer cg.Remove()

	c := exec.Command("sh", "-c", "while :; do (sleep 30 &); sleep 0.1; done")
	if err := c.Start(); err != nil {
		t.Fatalf("start fork burst: %v", err)
	}
	if err := cg.AddPid(c.Process.Pid); err != nil {
		t.Fatalf("AddPid: %v", err)
	}

	time.Sleep(2 * time.Second)
	st, err := cg.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.PIDsCurrent > 4 {
		t.Errorf("PID Ration not enforced: pids.current = %d, limit 4", st.PIDsCurrent)
	}
	_ = c.Process.Kill()
	_, _ = c.Process.Wait()
}

func TestCPULimitRestricts(t *testing.T) {
	mount := limitMount(t)

	cg, err := Create(mount, "cpu-limit", Rations{CPUQuotaMicros: 50000})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer cg.Remove()

	c := exec.Command("sh", "-c", "end=$((SECONDS+2)); while [ $SECONDS -lt $end ]; do :; done")
	if err := c.Start(); err != nil {
		t.Fatalf("start busy loop: %v", err)
	}
	if err := cg.AddPid(c.Process.Pid); err != nil {
		t.Fatalf("AddPid: %v", err)
	}

	if err := c.Wait(); err != nil {
		t.Fatalf("busy loop failed: %v", err)
	}
	st, err := cg.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.CPUUsageUsec <= 0 {
		t.Errorf("expected non-zero CPU usage, got %d", st.CPUUsageUsec)
	}

	if st.CPUUsageUsec > 1300000 {
		t.Errorf("CPU Ration not enforced: usage %d usec > 1.3s for a 0.5 quota over 2s", st.CPUUsageUsec)
	}
}
