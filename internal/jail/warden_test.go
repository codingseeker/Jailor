//go:build linux

package jail

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"jailor/internal/bars"
)

func runCmd(t *testing.T, argv []string, stdin io.Reader, stdout, stderr io.Writer, env []string) (int, error) {
	t.Helper()
	if !canUseNamespaces() {
		t.Skip("environment cannot create namespaces")
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	cfg := &InitConfig{
		Args:      argv,
		Env:       env,
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,
	}
	opts := SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdin:       stdin,
		Stdout:      stdout,
		Stderr:      stderr,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}

	child, err := Spawn(opts, cfg)
	if err != nil {
		return -1, err
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		return -1, err
	}
	if err := child.Release(); err != nil {
		return -1, err
	}
	if err := child.ReadReady(); err != nil {
		return -1, err
	}
	return child.Wait(), nil
}

func TestStdoutForwarding(t *testing.T) {
	out := &syncBuf{}
	code, err := runCmd(t, []string{"/bin/echo", "hello-out"}, nil, out, nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if strings.TrimSpace(out.String()) != "hello-out" {
		t.Errorf("stdout = %q, want %q", out.String(), "hello-out")
	}
}

func TestStderrForwarding(t *testing.T) {
	out, errOut := &syncBuf{}, &syncBuf{}
	code, err := runCmd(t, []string{"/bin/sh", "-c", `echo err-goes-here 1>&2`}, nil, out, errOut, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if strings.TrimSpace(errOut.String()) != "err-goes-here" {
		t.Errorf("stderr = %q, want %q", errOut.String(), "err-goes-here")
	}
	if strings.Contains(out.String(), "err-goes") {
		t.Errorf("stderr leaked into stdout: %q", out.String())
	}
}

func TestStdinForwarding(t *testing.T) {
	out := &syncBuf{}
	stdin := strings.NewReader("from-stdin\n")
	code, err := runCmd(t, []string{"/bin/cat"}, stdin, out, nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(out.String(), "from-stdin") {
		t.Errorf("stdin data not forwarded: stdout = %q", out.String())
	}
}

func TestEnvironmentPropagation(t *testing.T) {
	out := &syncBuf{}
	env := []string{"JAILOR_TEST_MARK=env-ok", "PATH=/bin:/usr/bin"}
	code, err := runCmd(t, []string{"/usr/bin/env"}, nil, out, nil, env)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(out.String(), "JAILOR_TEST_MARK=env-ok") {
		t.Errorf("prisoner env missing marker:\n%s", out.String())
	}
}

func TestExitCodeZero(t *testing.T) {
	code, err := runCmd(t, []string{"/bin/true"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestNonZeroExitCode(t *testing.T) {
	for _, want := range []int{1, 3, 42} {
		code, err := runCmd(t, []string{"/bin/sh", "-c", "exit " + strconv.Itoa(want)}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if code != want {
			t.Errorf("exit code = %d, want %d", code, want)
		}
	}
}

func TestCommandNotFound(t *testing.T) {
	if !canUseNamespaces() {
		t.Skip("environment cannot create namespaces")
	}
	cfg := &InitConfig{
		Args:      []string{"/nonexistent-binary-xyz"},
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,
	}
	opts := SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      io.Discard,
		Stderr:      io.Discard,
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
		t.Error("ReadReady should fail for a non-existent command")
	}
	if code := child.Wait(); code != 127 {
		t.Errorf("exit code = %d, want 127 (command not found)", code)
	}
}

func TestSigtermHandling(t *testing.T) {
	code, out, err := runSignalProbe(t, syscall.SIGTERM)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	if !strings.Contains(out, "sig=caught") {
		t.Errorf("SIGTERM not caught by Prisoner:\n%s", out)
	}
}

func TestSigintHandling(t *testing.T) {
	code, out, err := runSignalProbe(t, syscall.SIGINT)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	if !strings.Contains(out, "sig=caught") {
		t.Errorf("SIGINT not caught by Prisoner:\n%s", out)
	}
}

func TestKillHandling(t *testing.T) {
	code, _, err := runSignalProbe(t, syscall.SIGKILL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 128+int(syscall.SIGKILL) {
		t.Errorf("exit code = %d, want %d (SIGKILL)", code, 128+int(syscall.SIGKILL))
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitOutput(t *testing.T, buf *syncBuf, marker string) error {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if strings.Contains(buf.String(), marker) {
			return nil
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			return fmt.Errorf("output did not contain %q:\n%s", marker, buf.String())
		}
	}
}

func runSignalProbe(t *testing.T, sig syscall.Signal) (int, string, error) {
	t.Helper()
	if !canUseNamespaces() {
		t.Skip("environment cannot create namespaces")
	}
	out := &syncBuf{}
	cfg := &InitConfig{
		Args:      []string{testExe, "__probe", "sig"},
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
		return -1, "", err
	}
	defer child.Close()
	if err := child.Start(); err != nil {
		return -1, "", err
	}
	if err := child.Release(); err != nil {
		return -1, "", err
	}
	if err := child.ReadReady(); err != nil {
		return -1, "", err
	}
	if err := waitOutput(t, out, "sig=ready"); err != nil {
		return -1, "", err
	}
	if err := child.Signal(sig); err != nil {
		return -1, "", err
	}
	code := child.Wait()
	return code, out.String(), nil
}

func TestChildCleanup(t *testing.T) {
	if !canUseNamespaces() {
		t.Skip("environment cannot create namespaces")
	}
	cfg := &InitConfig{
		Args:      []string{"/bin/true"},
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,
	}
	opts := SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      io.Discard,
		Stderr:      io.Discard,
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
	pid := child.PID()
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	if code := child.Wait(); code != 0 {
		t.Fatalf("exit code = %d", code)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("process %d still present after Wait", pid)
}

func TestSpaceInArgs(t *testing.T) {
	out := &syncBuf{}
	code, err := runCmd(t, []string{"/bin/sh", "-c", `printf 'a b c'`}, nil, out, nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if strings.TrimSpace(out.String()) != "a b c" {
		t.Errorf("spaceful arg corrupted: %q", out.String())
	}
}
