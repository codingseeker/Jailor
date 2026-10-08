//go:build linux

package prisoner

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"jailor/internal/bars"
	"jailor/internal/jail"
)

var self string

func visitorProbe(kind string) int {
	switch kind {
	case "hostname":
		h, err := os.Hostname()
		if err != nil {
			fmt.Printf("hostname=err:%v\n", err)
			return 1
		}
		fmt.Printf("hostname=%s\n", h)
	case "selfns":
		names := []string{"mnt", "uts", "ipc", "pid", "net", "user", "cgroup"}
		for _, n := range names {
			if link, err := os.Readlink("/proc/self/ns/" + n); err == nil {
				fmt.Printf("ns_%s=%s\n", n, link)
			}
		}
	case "sleep":
		fmt.Printf("jail-sleep\n")
		time.Sleep(30 * time.Second)
	}
	return 0
}

func TestMain(m *testing.M) {
	switch {
	case len(os.Args) > 1 && os.Args[1] == jail.InitArg:
		os.Exit(jail.RunInit())
	case len(os.Args) > 1 && os.Args[1] == jail.StagerArg:
		os.Exit(jail.RunStager())
	case len(os.Args) > 1 && os.Args[1] == "__nsenter":
		os.Exit(jail.RunNSEnter())
	case len(os.Args) > 1 && os.Args[1] == "__visitor":
		os.Exit(jail.RunVisitor())
	case len(os.Args) > 1 && os.Args[1] == "__probe":
		if len(os.Args) > 2 {
			os.Exit(visitorProbe(os.Args[2]))
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func init() {
	self, _ = os.Executable()
}

func canNS() bool {
	if os.Geteuid() == 0 {
		return true
	}
	cmd := exec.Command(self, "__probe", "hostname")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
	return cmd.Run() == nil
}

func startJail(t *testing.T, hostname string) int {
	t.Helper()
	if !canNS() {
		t.Skip("cannot create namespaces")
	}

	cfg := &jail.InitConfig{
		Args:      []string{self, "__probe", "sleep"},
		Hostname:  hostname,
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,
	}
	opts := jail.SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount, bars.Network},
		Userns:      true,
		Stdout:      os.Stderr,
		Stderr:      os.Stderr,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}
	child, err := jail.Spawn(opts, cfg)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	if err := child.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := child.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := child.ReadReady(); err != nil {
		child.Kill()
		child.Wait()
		t.Fatalf("read-ready: %v", err)
	}

	pid := child.PID()
	t.Cleanup(func() {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		child.Wait()
	})
	return pid
}

func runInside(t *testing.T, pid int, probe string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cfg := jail.InitConfig{
		Args: []string{self, "__probe", probe},
	}

	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	defer inR.Close()
	defer outW.Close()
	defer errW.Close()
	_ = inW.Close()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, e := outR.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
			}
			if e != nil {
				break
			}
		}
		buf = make([]byte, 4096)
		for {
			n, e := errR.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
			}
			if e != nil {
				break
			}
		}
		close(done)
	}()

	err := Enter(SpawnOptions{
		Pid:    pid,
		Init:   cfg,
		Stdin:  inR,
		Stdout: outW,
		Stderr: errW,
	})
	_ = outR.Close()
	_ = errR.Close()
	<-done
	return out.String(), err
}

func nsInode(link string) string {
	if i := strings.Index(link, "["); i >= 0 {
		link = link[i+1:]
		if j := strings.Index(link, "]"); j >= 0 {
			return link[:j]
		}
	}
	return link
}

func parseKV(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "="); i > 0 {
			m[line[:i]] = line[i+1:]
		}
	}
	return m
}

func TestExecEntersSameUTS(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to setns into another process's namespaces")
	}
	const inside = "visitor-host"
	pid := startJail(t, inside)

	out, err := runInside(t, pid, "hostname")
	if err != nil {
		t.Fatalf("exec inside jail: %v (out=%q)", err, out)
	}
	m := parseKV(out)
	if m["hostname"] != inside {
		t.Errorf("Visitor should see the Jail hostname %q, got %q (out=%q)", inside, m["hostname"], out)
	}
}

func TestExecSharesNamespaces(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to setns into another process's namespaces")
	}
	pid := startJail(t, "visitor-ns")

	out, err := runInside(t, pid, "selfns")
	if err != nil {
		t.Fatalf("exec inside jail: %v (out=%q)", err, out)
	}
	m := parseKV(out)

	for _, name := range []string{"mnt", "uts", "ipc", "pid", "net", "user", "cgroup"} {
		hostLink, hErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, name))
		if hErr != nil {
			continue
		}
		want := nsInode(hostLink)
		if got := nsInode(m["ns_"+name]); got != "" && got != want {
			t.Errorf("namespace %s differs: jail=%s visitor=%s", name, want, got)
		}
	}
}

func TestEnterFailsForStalePid(t *testing.T) {

	err := Enter(SpawnOptions{
		Pid:  99999999,
		Init: jail.InitConfig{Args: []string{"/bin/true"}},
	})
	if err == nil {
		t.Fatal("Enter of a non-existent PID should fail, not run on host")
	}
}
