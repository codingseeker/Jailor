//go:build linux

package jail

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"jailor/internal/runtimecore"
)

var escalateAfter = 3 * time.Second

const escalateEnv = "JAILOR_ESCALATE_AFTER"

func escalateTimeout() time.Duration {
	if v := os.Getenv(escalateEnv); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return escalateAfter
}

func statusCode(ws syscall.WaitStatus) int {
	return runtimecore.ExitCode(ws)
}

func servePrisoner(cfg *InitConfig, syncOutFD int) int {
	argv, env, err := resolveCommand(cfg)
	if err != nil {
		fail(syncOutFD, err)
		return 127
	}

	s := newSupervisor(escalateTimeout())
	s.setup()
	defer s.stop()

	pid, err := forkPrisoner(argv, env)
	if err != nil {
		fail(syncOutFD, err)
		return 127
	}
	s.prisonerPID = pid
	s.pgid = pid

	if err := signalReadyPID(syncOutFD, pid); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	return s.run()
}

func forkPrisoner(argv, env []string) (int, error) {
	attr := &syscall.ProcAttr{
		Dir:   "/",
		Env:   env,
		Files: []uintptr{0, 1, 2},
		Sys:   &syscall.SysProcAttr{Setpgid: true},
	}
	pid, err := syscall.ForkExec(argv[0], argv, attr)
	if err != nil {
		return 0, fmt.Errorf("jail: fork prisoner: %w", err)
	}
	return pid, nil
}

func signalReadyPID(fd int, pid int) error {
	f := os.NewFile(uintptr(fd), "sync-out")
	defer f.Close()
	_, err := fmt.Fprintf(f, "%c%d\n", syncReady, pid)
	return err
}

type supervisor struct {
	prisonerPID int
	pgid        int
	timeout     time.Duration
	chld        chan os.Signal
	term        chan os.Signal
}

func newSupervisor(timeout time.Duration) *supervisor {
	return &supervisor{
		timeout: timeout,
		chld:    make(chan os.Signal, 16),
		term:    make(chan os.Signal, 4),
	}
}

func (s *supervisor) setup() {
	signal.Notify(s.chld, syscall.SIGCHLD)
	signal.Notify(s.term, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP)
}

func (s *supervisor) stop() {
	signal.Stop(s.chld)
	signal.Stop(s.term)
}

func (s *supervisor) run() int {
	s.reap()

	escalate := time.NewTimer(s.timeout)
	if !escalate.Stop() {
		<-escalate.C
	}
	escalateArmed := false
	for {
		select {
		case <-s.chld:
			if code, done := s.reap(); done {
				return code
			}
		case sig := <-s.term:
			if escalateArmed {

				escalate.Stop()
				escalateArmed = false
				s.signalTree(syscall.SIGKILL)
				continue
			}
			escalateArmed = true
			escalate.Reset(s.timeout)
			s.signalTree(terminatingSignal(sig))
		case <-escalate.C:
			escalateArmed = false
			s.signalTree(syscall.SIGKILL)
		}
	}
}

func terminatingSignal(sig os.Signal) syscall.Signal {
	if s, ok := sig.(syscall.Signal); ok {
		return s
	}
	return syscall.SIGTERM
}

func (s *supervisor) signalTree(sig syscall.Signal) {
	_ = syscall.Kill(-s.pgid, sig)
}

func (s *supervisor) reap() (int, bool) {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if err != nil || pid <= 0 {
			return 0, false
		}
		if pid == s.prisonerPID {
			return statusCode(ws), true
		}
	}
}
