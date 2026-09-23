package jail

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"jailor/internal/bars"
)

var testExe string

func init() {
	testExe, _ = os.Executable()
}

func TestMain(m *testing.M) {
	switch {
	case len(os.Args) > 1 && os.Args[1] == "__init":
		os.Exit(RunInit())
	case len(os.Args) > 1 && os.Args[1] == "__nsenter":
		os.Exit(RunNSEnter())
	case len(os.Args) > 1 && os.Args[1] == "__visitor":
		os.Exit(RunVisitor())
	case len(os.Args) > 1 && os.Args[1] == "__probe":
		if len(os.Args) > 2 {
			os.Exit(probe(os.Args[2]))
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func probe(kind string) int {
	switch kind {
	case "pid":
		fmt.Printf("pid=%d\n", os.Getpid())
		fmt.Printf("ppid=%d\n", os.Getppid())
	case "hostname":
		h, err := os.Hostname()
		if err != nil {
			fmt.Printf("hostname=err:%v\n", err)
			return 1
		}
		fmt.Printf("hostname=%s\n", h)
	case "net":
		data, err := os.ReadFile("/proc/net/dev")
		if err != nil {
			fmt.Printf("net=err:%v\n", err)
			return 1
		}
		var ifaces []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Inter-") || strings.HasPrefix(line, "face") {
				continue
			}
			iface := strings.SplitN(line, ":", 2)[0]
			iface = strings.TrimSpace(iface)
			ifaces = append(ifaces, iface)
		}
		sort.Strings(ifaces)
		fmt.Printf("net=%s\n", strings.Join(ifaces, ","))
	case "proc1":
		data, err := os.ReadFile("/proc/1/status")
		if err != nil {
			fmt.Printf("proc1=err:%v\n", err)
			return 1
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Pid:") {
				fmt.Printf("proc1_pid=%s\n", strings.TrimSpace(strings.TrimPrefix(line, "Pid:")))
			}
			if strings.HasPrefix(line, "Name:") {
				fmt.Printf("proc1_name=%s\n", strings.TrimSpace(strings.TrimPrefix(line, "Name:")))
			}
			if strings.HasPrefix(line, "PPid:") {
				fmt.Printf("proc1_ppid=%s\n", strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			}
		}
	case "tmp":
		f, err := os.CreateTemp("/tmp", "jailtest-")
		if err != nil {
			fmt.Printf("tmp=err:%v\n", err)
			return 1
		}
		name := f.Name()
		f.WriteString("tmp-ok")
		f.Close()
		data, _ := os.ReadFile(name)
		os.Remove(name)
		fmt.Printf("tmp=%s\n", string(data))
	case "dev":
		entries, err := os.ReadDir("/dev")
		if err != nil {
			fmt.Printf("dev=err:%v\n", err)
			return 1
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		fmt.Printf("dev=%s\n", strings.Join(names, ","))
	case "pscount":
		entries, _ := os.ReadDir("/proc")
		count := 0
		for _, e := range entries {
			var pid int
			if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err == nil {
				count++
			}
		}
		fmt.Printf("pscount=%d\n", count)
	case "selfns":
		fmt.Printf("selfns=ok\n")
	case "sleep":

		time.Sleep(30 * time.Second)
		fmt.Printf("woke\n")
	case "caps":

		data, err := os.ReadFile("/proc/self/status")
		if err != nil {
			fmt.Printf("caps=err:%v\n", err)
			return 1
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "CapEff:") ||
				strings.HasPrefix(line, "CapPrm:") ||
				strings.HasPrefix(line, "CapBnd:") {
				kv := strings.SplitN(line, ":", 2)
				fmt.Printf("caps_%s=%s\n", strings.ToLower(kv[0]), strings.TrimSpace(kv[1]))
			}
		}
	case "sig":

		caught := make(chan os.Signal, 1)
		signal.Notify(caught, syscall.SIGTERM, syscall.SIGINT)
		fmt.Printf("sig=ready\n")
		select {
		case <-caught:
			fmt.Printf("sig=caught\n")
		case <-time.After(10 * time.Second):
			fmt.Printf("sig=timeout\n")
		}
	case "sigignore":

		caught := make(chan os.Signal, 4)
		signal.Notify(caught, syscall.SIGTERM)
		fmt.Printf("sigignore=ready\n")
		for {
			select {
			case <-caught:

			case <-time.After(30 * time.Second):
				os.Exit(0)
			}
		}
	case "selfterm":

		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		time.Sleep(2 * time.Second)
		fmt.Printf("selfterm=survived\n")
	case "init1":

		data, err := os.ReadFile("/proc/1/cmdline")
		if err != nil {
			fmt.Printf("init1=err:%v\n", err)
			return 1
		}
		cmdline := strings.ReplaceAll(string(data), "\x00", " ")
		fmt.Printf("init1=%s\n", strings.TrimSpace(cmdline))
	case "orfarm":

		for i := 0; i < 3; i++ {
			c := exec.Command(testExe, "__probe", "orfarmkid")
			if err := c.Start(); err != nil {
				fmt.Printf("orfarm=err:%v\n", err)
				return 1
			}
			if err := c.Wait(); err != nil {
				fmt.Printf("orfarm_wait=err:%v\n", err)
				return 1
			}
		}
		time.Sleep(700 * time.Millisecond)
		fmt.Printf("orfarm_zombies=%d\n", countJailZombies())
	case "orfarmkid":

		g := exec.Command(testExe, "__probe", "orfarmgrand")
		if err := g.Start(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "orfarmgrand":

		time.Sleep(2 * time.Second)
		os.Exit(0)
	case "write-root":

		if err := os.WriteFile("/jailor-readonly-test", []byte("x"), 0o644); err != nil {
			fmt.Printf("write_root=err\n")
			return 0
		}
		fmt.Printf("write_root=ok\n")
		os.Remove("/jailor-readonly-test")
	case "mount-try":

		if err := syscall.Mount("none", "/tmp", "tmpfs", 0, ""); err != nil {
			fmt.Printf("mount_try=err:%v\n", err)
			return 0
		}
		fmt.Printf("mount_try=ok\n")
	default:
		fmt.Printf("unknown-probe=%s\n", kind)
	}
	return 0
}

func canUseNamespaces() bool {
	if os.Geteuid() == 0 {
		return true
	}

	cmd := exec.Command(testExe, "__probe", "selfns")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func runJail(t *testing.T, kinds []bars.Kind, userns bool, probeKind string, hostname string) (string, int) {
	t.Helper()
	if !canUseNamespaces() {
		t.Skip("environment cannot create namespaces")
	}

	var out bytes.Buffer

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
		Stdout:     &out,
		Stderr:     &out,
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

func countJailZombies() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range entries {
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		s := string(data)
		idx := strings.LastIndex(s, ")")
		if idx >= 0 && strings.Contains(s[idx:idx+8], " Z ") {
			n++
		}
	}
	return n
}

func runCell(t *testing.T, userns bool, probeKind string, hostname string) (string, int) {
	t.Helper()
	if !canUseNamespaces() {
		t.Skip("environment cannot create namespaces")
	}

	var out bytes.Buffer

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
		Stdout:     &out,
		Stderr:     &out,
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
	if os.Geteuid() == 0 {
		t.Skip("run as root; user namespace not required")
	}

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
		t.Skip("environment cannot create namespaces")
	}
	var out bytes.Buffer
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
		Stdout:      &out,
		Stderr:      &out,
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
		t.Skip("environment cannot create namespaces")
	}
	var out syncBuf
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
		Stdout:      &out,
		Stderr:      &out,
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
	if err := waitOutput(t, &out, "sigignore=ready"); err != nil {
		t.Fatal(err)
	}
	if err := child.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}
	start := time.Now()
	code := child.Wait()
	if want := 128 + int(syscall.SIGKILL); code != want {
		t.Errorf("exit code = %d, want %d (escalated SIGKILL)", code, want)
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
		t.Skip("environment cannot create namespaces")
	}
	var out bytes.Buffer
	opts := SpawnOpts{
		Init:       *cfg,
		Namespaces: []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:     userns,
		Stdout:     &out,
		Stderr:     &out,
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
		t.Skip("environment cannot create namespaces")
	}
	var out bytes.Buffer
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
		Stdout:      &out,
		Stderr:      &out,
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
		t.Skip("environment cannot create namespaces")
	}
	var out bytes.Buffer
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
		Stdout:      &out,
		Stderr:      &out,
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

func TestReadOnlyCell(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for pivot_root into the Cell")
	}

	cell := scratchCell(t)
	var out bytes.Buffer
	cfg := &InitConfig{
		Args:      []string{"/bin/sh", "-c", "if touch /ro-marker 2>/dev/null; then echo writable; else echo readonly; fi"},
		Rootfs:    cell,
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,
		ReadOnly:  true,
	}
	if !canUseNamespaces() {
		t.Skip("environment cannot create namespaces")
	}
	opts := SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      &out,
		Stderr:      &out,
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
		t.Skipf("no example rootfs at %s: %v", src, err)
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
