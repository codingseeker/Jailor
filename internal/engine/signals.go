package engine

import (
	"syscall"

	"jailor/internal/ledger"
	"jailor/internal/runtimecore"
)

const (
	sigKill = syscall.SIGKILL
	sigTerm = syscall.SIGTERM
)

func kill(pid int, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

func processGone(pid int) bool {
	if pid <= 0 {
		return true
	}
	if !ledger.ProcessAlive(pid) {
		return true
	}
	return runtimecore.IsZombie(pid)
}
