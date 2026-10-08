//go:build linux

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
	"sync"
	"syscall"
	"testing"
	"time"
)

var testExe string

func init() {
	testExe, _ = os.Executable()
}

func TestMain(m *testing.M) {
	switch {
	case len(os.Args) > 1 && os.Args[1] == InitArg:
		os.Exit(RunInit())
	case len(os.Args) > 1 && os.Args[1] == StagerArg:
		os.Exit(RunStager())
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
			if strings.HasPrefix(line, "CapInh:") ||
				strings.HasPrefix(line, "CapEff:") ||
				strings.HasPrefix(line, "CapPrm:") ||
				strings.HasPrefix(line, "CapBnd:") {
				kv := strings.SplitN(line, ":", 2)
				fmt.Printf("caps_%s=%s\n", strings.ToLower(kv[0]), strings.TrimSpace(kv[1]))
			}
		}
	case "env":
		for _, e := range os.Environ() {
			fmt.Println(e)
		}
	case "fds":

		dir, err := os.Open("/proc/self/fd")
		if err != nil {
			fmt.Printf("fds=err:%v\n", err)
			return 1
		}
		self := int(dir.Fd())
		names, err := dir.Readdirnames(-1)
		dir.Close()
		if err != nil {
			fmt.Printf("fds=err:%v\n", err)
			return 1
		}
		sort.Strings(names)
		for _, name := range names {
			fd, convErr := strconv.Atoi(name)
			if convErr != nil || fd == self {
				continue
			}
			target, err := os.Readlink(filepath.Join("/proc/self/fd", name))
			if err != nil {
				fmt.Printf("fd=%s->closed\n", name)
				continue
			}
			fmt.Printf("fd=%s->%s\n", name, target)
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
	case "stat":

		target := os.Args[3]
		info, err := os.Stat(target)
		if err != nil {
			fmt.Printf("stat=%s:err:%v\n", target, err)
			return 0
		}
		fmt.Printf("stat=%s:mode:%v\n", target, info.Mode())
	case "read":

		target := os.Args[3]
		data, err := os.ReadFile(target)
		if err != nil {
			fmt.Printf("read=%s:err:%v\n", target, err)
			return 0
		}
		fmt.Printf("read=%s:%s\n", target, strings.TrimSpace(string(data)))
	case "write":

		target := os.Args[3]
		if err := os.WriteFile(target, []byte("escape"), 0o644); err != nil {
			fmt.Printf("write=%s:err:%v\n", target, err)
			return 0
		}
		fmt.Printf("write=%s:ok\n", target)
	case "mkdir":

		target := os.Args[3]
		if err := os.MkdirAll(target, 0o755); err != nil {
			fmt.Printf("mkdir=%s:err:%v\n", target, err)
			return 0
		}
		fmt.Printf("mkdir=%s:ok\n", target)
	case "traverse":

		target := os.Args[3]
		data, err := os.ReadFile(target)
		if err != nil {
			fmt.Printf("traverse=%s:err:%v\n", target, err)
			return 0
		}
		fmt.Printf("traverse=%s:readable:%s\n", target, strings.TrimSpace(string(data)))
	case "unshare-try":

		flags := uintptr(0)
		for _, name := range os.Args[3:] {
			switch name {
			case "pid":
				flags |= syscall.CLONE_NEWPID
			case "user":
				flags |= syscall.CLONE_NEWUSER
			case "mount":
				flags |= syscall.CLONE_NEWNS
			case "net":
				flags |= syscall.CLONE_NEWNET
			}
		}
		if err := syscall.Unshare(int(flags)); err != nil {
			fmt.Printf("unshare=err:%v\n", err)
			return 0
		}
		fmt.Printf("unshare=ok\n")
	case "clone-try":

		flags := uintptr(0)
		for _, name := range os.Args[3:] {
			switch name {
			case "pid":
				flags |= syscall.CLONE_NEWPID
			case "user":
				flags |= syscall.CLONE_NEWUSER
			case "mount":
				flags |= syscall.CLONE_NEWNS
			case "net":
				flags |= syscall.CLONE_NEWNET
			}
		}
		attr := &syscall.ProcAttr{
			Dir:   "/",
			Env:   []string{"PATH=/usr/bin:/bin"},
			Files: []uintptr{0, 1, 2},
			Sys:   &syscall.SysProcAttr{Cloneflags: flags},
		}
		pid, err := syscall.ForkExec("/bin/true", []string{"/bin/true"}, attr)
		if err != nil {
			fmt.Printf("clone=err:%v\n", err)
			return 0
		}
		_, _ = syscall.Wait4(pid, nil, 0, nil)
		fmt.Printf("clone=ok\n")
	case "seteuid":

		target := os.Args[3]
		uid, err := strconv.Atoi(target)
		if err != nil {
			fmt.Printf("seteuid=err:%v\n", err)
			return 0
		}
		if err := syscall.Setresuid(uid, uid, uid); err != nil {
			fmt.Printf("seteuid=%d:err:%v\n", uid, err)
			return 0
		}
		fmt.Printf("seteuid=%d:ok\n", uid)
	case "setuid-exec":

		target := os.Args[3]
		uid, err := strconv.Atoi(target)
		if err != nil {
			fmt.Printf("setuid=err:%v\n", err)
			return 0
		}
		if err := syscall.Setresuid(uid, uid, uid); err != nil {
			fmt.Printf("setuid_exec=err:%v\n", err)
			return 0
		}
		if err := syscall.Exec(target, []string{target}, os.Environ()); err != nil {
			fmt.Printf("setuid_exec=err:%v\n", err)
			return 0
		}
	case "cap-check":

		fmt.Printf("cap_check=ok\n")
	case "ptrace-try":

		pid, err := strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Printf("ptrace=err:%v\n", err)
			return 0
		}
		if err := syscall.PtraceAttach(pid); err != nil {
			fmt.Printf("ptrace=err:%v\n", err)
			return 0
		}
		_ = syscall.PtraceDetach(pid)
		fmt.Printf("ptrace=ok\n")
	case "device-read":

		target := os.Args[3]
		data, err := os.ReadFile(target)
		if err != nil {
			fmt.Printf("device=%s:err:%v\n", target, err)
			return 0
		}
		fmt.Printf("device=%s:readable:%d\n", target, len(data))
	case "hostproc-pid":

		data, err := os.ReadFile(fmt.Sprintf("/proc/%s/status", os.Args[3]))
		if err != nil {
			fmt.Printf("hostproc=%s:err:%v\n", os.Args[3], err)
			return 0
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Name:") || strings.HasPrefix(line, "Uid:") {
				fmt.Printf("hostproc=%s:%s\n", os.Args[3], strings.Join(strings.Fields(line), " "))
			}
		}
	case "ns":

		for _, kind := range os.Args[3:] {
			link, err := os.Readlink("/proc/self/ns/" + kind)
			if err != nil {
				fmt.Printf("ns_%s=err:%v\n", kind, err)
				continue
			}
			fmt.Printf("ns_%s=%s\n", kind, nsInode(link))
		}
	case "writecount":

		target := os.Args[3]
		limit, err := strconv.Atoi(os.Args[4])
		if err != nil {
			fmt.Printf("writecount=err:%v\n", err)
			return 0
		}
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			fmt.Printf("writecount=%s:err:%v\n", target, err)
			return 0
		}
		chunk := make([]byte, 4096)
		for i := 0; i < limit; i++ {
			if _, err := f.Write(chunk); err != nil {
				fmt.Printf("writecount=%s:err:%v\n", target, err)
				f.Close()
				return 0
			}
		}
		f.Close()
		fmt.Printf("writecount=%s:ok\n", target)
	case "burncpu":

		deadline := time.Now().Add(time.Duration(500) * time.Millisecond)
		for time.Now().Before(deadline) {
			syscall.Getpid()
		}
		fmt.Printf("burncpu=ok\n")
	case "forks":

		limit, err := strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Printf("forks=err:%v\n", err)
			return 0
		}
		created := 0
		for i := 0; i < limit; i++ {
			attr := &syscall.ProcAttr{
				Dir:   "/",
				Env:   []string{"PATH=/usr/bin:/bin"},
				Files: []uintptr{0, 1, 2},
			}
			pid, err := syscall.ForkExec("/bin/true", []string{"/bin/true"}, attr)
			if err != nil {
				fmt.Printf("forks=created:%d:err:%v\n", created, err)
				return 0
			}
			if _, err := syscall.Wait4(pid, nil, 0, nil); err != nil {
				fmt.Printf("forks=created:%d:wait-err:%v\n", created, err)
				return 0
			}
			created++
		}
		fmt.Printf("forks=created:%d:ok\n", created)
	case "sleepms":

		ms, err := strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Printf("sleep=err:%v\n", err)
			return 0
		}
		time.Sleep(time.Duration(ms) * time.Millisecond)
		fmt.Printf("sleep=ok\n")
	case "chroot-try":

		if err := syscall.Chroot("/"); err != nil {
			fmt.Printf("chroot=err:%v\n", err)
			return 0
		}
		fmt.Printf("chroot=ok\n")
	case "sleep-orphan":

		parent := exec.Command(testExe, "__probe", "sleep-orphan-kid")
		parent.Stdout = os.Stdout
		parent.Stderr = os.Stderr
		if err := parent.Start(); err != nil {
			fmt.Printf("sleep_orphan=err:%v\n", err)
			return 0
		}
		fmt.Printf("sleep_orphan=kid:%d\n", parent.Process.Pid)
		_ = parent.Wait()
	case "sleep-orphan-kid":

		time.Sleep(30 * time.Second)
		os.Exit(0)
	default:
		fmt.Printf("unknown-probe=%s\n", kind)
	}
	return 0
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

const cellProbeName = "jailor-cell-probe"

func copyProbeIntoCell(t *testing.T, cell string) string {
	t.Helper()
	dst := filepath.Join(cell, "bin", cellProbeName)
	data, err := os.ReadFile(testExe)
	if err != nil {
		t.Fatalf("read test binary for the Cell: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("create Cell probe directory: %v", err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatalf("install test binary into the Cell: %v", err)
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		t.Fatalf("chmod Cell probe: %v", err)
	}
	return filepath.Join("/bin", cellProbeName)
}

func cellProbeArgs(t *testing.T, cell string, args ...string) []string {
	t.Helper()
	return append([]string{copyProbeIntoCell(t, cell), "__probe"}, args...)
}
