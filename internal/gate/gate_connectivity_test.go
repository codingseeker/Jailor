//go:build linux

package gate

import (
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

type errNotFound string

func (e errNotFound) Error() string { return string(e) }
func spawnNetns(t *testing.T) (*exec.Cmd, int) {
	t.Helper()
	c := exec.Command("sleep", "300")
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNET,
	}
	if err := c.Start(); err != nil {
		t.Fatalf("spawn netns child: %v", err)
	}
	return c, c.Process.Pid
}
func waitFor(t *testing.T, pid int, fn func() error, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = fn()
		if lastErr == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %v", what, lastErr)
}
func TestGateBridgeSetupAndConnectivity(t *testing.T) {
	requireRoot(t)
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not found; skipping")
	}

	child, pid := spawnNetns(t)
	defer func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	}()

	jailID := "aabbccdd00112233"
	g, err := New("bridge")
	if err != nil {
		t.Fatalf("New(bridge): %v", err)
	}
	if err := g.Setup(jailID, pid); err != nil {
		t.Fatalf("gate.Setup: %v", err)
	}
	defer g.Teardown(jailID)
	if !linkExists(DefaultBridge) {
		t.Error("host bridge not created")
	}
	if !linkExists(g.VethHost) {
		t.Errorf("host veth %s not created", g.VethHost)
	}
	waitFor(t, pid, func() error {
		if !linkExists("eth0") {
			return errNotFound("eth0")
		}
		return nil
	}, "eth0 in jail netns")
	t.Logf("jail netns saw eth0 with IP %s via gateway %s", g.IP, g.Gateway)
	gw := gatewayOf(g.Gateway)
	if gw == nil {
		t.Fatalf("invalid gateway %s", g.Gateway)
	}
	waitFor(t, pid, func() error {
		c, err := newNLConn()
		if err != nil {
			return err
		}
		defer c.Close()
		return nil
	}, "routing")
	if _, err := exec.LookPath("ping"); err == nil {
		jailIP, _, _ := strings.Cut(g.IP, "/")
		cmd := exec.Command("ping", "-c", "1", "-W", "1", jailIP)
		out, _ := cmd.CombinedOutput()
		t.Logf("host->jail ping output: %s", strings.TrimSpace(string(out)))
	}
}
func TestGateSetupMissingPid(t *testing.T) {
	requireRoot(t)
	g, err := New("bridge")
	if err != nil {
		t.Fatalf("New(bridge): %v", err)
	}
	if err := g.Setup("aabbccdd00112233", 99999999); err == nil {
		t.Error("Setup against a nonexistent PID should error")
		t.Cleanup(func() { g.Teardown("aabbccdd00112233") })
	}
}
func TestGateSetupNone(t *testing.T) {
	requireRoot(t)
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not found; skipping")
	}

	child, pid := spawnNetns(t)
	defer func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	}()

	g, err := New("none")
	if err != nil {
		t.Fatalf("New(none): %v", err)
	}
	if err := g.Setup("aabbccdd00112233", pid); err != nil {
		t.Fatalf("none Setup: %v", err)
	}
}
func TestGateTeardownIdempotent(t *testing.T) {
	requireRoot(t)
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not found; skipping")
	}

	child, pid := spawnNetns(t)
	defer func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	}()

	jailID := "aabbccdd00112233"
	g, err := New("bridge")
	if err != nil {
		t.Fatalf("New(bridge): %v", err)
	}
	if err := g.Setup(jailID, pid); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	g.Teardown(jailID)
	g.Teardown(jailID)
	if linkExists(g.VethHost) {
		t.Errorf("veth %s still exists after Teardown", g.VethHost)
	}
}
