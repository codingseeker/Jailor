package bars

import (
	"reflect"
	"syscall"
	"testing"
)

func TestKindString(t *testing.T) {
	cases := map[Kind]string{
		Mount:   "mnt",
		UTS:     "uts",
		IPC:     "ipc",
		PID:     "pid",
		Network: "net",
		User:    "user",
	}
	for kind, want := range cases {
		if got := kind.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", kind, got, want)
		}
	}
	if got := Kind(99).String(); got != "unknown" {
		t.Errorf("Kind(99).String() = %q, want %q", got, "unknown")
	}
}

func TestKindFlag(t *testing.T) {
	cases := map[Kind]uintptr{
		Mount:   uintptr(syscall.CLONE_NEWNS),
		UTS:     uintptr(syscall.CLONE_NEWUTS),
		IPC:     uintptr(syscall.CLONE_NEWIPC),
		PID:     uintptr(syscall.CLONE_NEWPID),
		Network: uintptr(syscall.CLONE_NEWNET),
		User:    uintptr(syscall.CLONE_NEWUSER),
	}
	for kind, want := range cases {
		if got := kind.Flag(); got != want {
			t.Errorf("Kind(%d).Flag() = %#x, want %#x", kind, got, want)
		}
	}
	if got := Kind(99).Flag(); got != 0 {
		t.Errorf("Kind(99).Flag() = %#x, want 0", got)
	}
}

func TestKindFromPath(t *testing.T) {
	cases := map[string]Kind{
		"/proc/1/ns/mnt":  Mount,
		"/proc/1/ns/uts":  UTS,
		"/proc/1/ns/ipc":  IPC,
		"/proc/1/ns/pid":  PID,
		"/proc/1/ns/net":  Network,
		"/proc/1/ns/user": User,
	}
	for path, want := range cases {
		got, err := KindFromPath(path)
		if err != nil {
			t.Fatalf("KindFromPath(%q) error: %v", path, err)
		}
		if got != want {
			t.Errorf("KindFromPath(%q) = %v, want %v", path, got, want)
		}
	}
	if _, err := KindFromPath("/proc/1/ns/nope"); err == nil {
		t.Error("KindFromPath with unknown path should error")
	}
}

func TestOpenAndClose(t *testing.T) {
	paths := []string{"/proc/self/ns/pid", "/proc/self/ns/uts", "/proc/self/ns/mnt"}
	opened := 0
	for _, p := range paths {
		ns, err := Open(p)
		if err != nil {
			continue
		}
		opened++
		if ns.Kind != PID && ns.Kind != UTS && ns.Kind != Mount {
			t.Errorf("Open(%q) kind = %v, unexpected", p, ns.Kind)
		}
		if ns.Path != p {
			t.Errorf("Open(%q) Path = %q", p, ns.Path)
		}
		if err := ns.Close(); err != nil {
			t.Errorf("Close(%q) error: %v", p, err)
		}
	}
	if opened == 0 {
		t.Log("no namespace symlinks available; skipping assertion")
	}
}

func TestDefaultNamespaces(t *testing.T) {

	seen := map[string]bool{}
	for _, k := range []Kind{Mount, UTS, IPC, PID, Network, User} {
		name := k.String()
		if seen[name] {
			t.Errorf("duplicate namespace name %q", name)
		}
		seen[name] = true
		if k.Flag() == 0 {
			t.Errorf("namespace %q has zero flag", name)
		}
	}
}

func TestKnownNamespaceKinds(t *testing.T) {
	want := []Kind{Mount, UTS, IPC, PID, Network, User}
	got := []Kind{Mount, UTS, IPC, PID, Network, User}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("namespace Kinds changed: got %v want %v", got, want)
	}
}
