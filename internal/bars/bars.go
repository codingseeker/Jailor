package bars

import (
	"fmt"
	"os"
	"syscall"
)

type Kind int

const (
	Mount Kind = iota
	UTS
	IPC
	PID
	Network
	User
)

func (k Kind) String() string {
	switch k {
	case Mount:
		return "mnt"
	case UTS:
		return "uts"
	case IPC:
		return "ipc"
	case PID:
		return "pid"
	case Network:
		return "net"
	case User:
		return "user"
	}
	return "unknown"
}

func (k Kind) Flag() uintptr {
	switch k {
	case Mount:
		return uintptr(syscall.CLONE_NEWNS)
	case UTS:
		return uintptr(syscall.CLONE_NEWUTS)
	case IPC:
		return uintptr(syscall.CLONE_NEWIPC)
	case PID:
		return uintptr(syscall.CLONE_NEWPID)
	case Network:
		return uintptr(syscall.CLONE_NEWNET)
	case User:
		return uintptr(syscall.CLONE_NEWUSER)
	}
	return 0
}

type Namespace struct {
	Kind Kind
	fd   *os.File
	Path string
}

func (n *Namespace) Close() error {
	if n == nil || n.fd == nil {
		return nil
	}
	return n.fd.Close()
}

func KindFromPath(path string) (Kind, error) {
	switch {
	case hasSuffix(path, "/mnt"):
		return Mount, nil
	case hasSuffix(path, "/uts"):
		return UTS, nil
	case hasSuffix(path, "/ipc"):
		return IPC, nil
	case hasSuffix(path, "/pid"):
		return PID, nil
	case hasSuffix(path, "/net"):
		return Network, nil
	case hasSuffix(path, "/user"):
		return User, nil
	}
	return 0, fmt.Errorf("bars: unknown namespace path %q", path)
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func Open(path string) (*Namespace, error) {
	kind, err := KindFromPath(path)
	if err != nil {
		return nil, err
	}
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &Namespace{Kind: kind, fd: fd, Path: path}, nil
}
