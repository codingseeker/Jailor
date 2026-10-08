//go:build linux

package jail

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"
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
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

func exitStatusCode(ws syscall.WaitStatus) int {
	return statusCode(ws)
}

func RunInit() int {
	fd, err := mustGetFD(envPrisonerReadFD)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	prisonerPID, err := readPrisonerPID(fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "jail init: %v\n", err)
		return 1
	}
	if self := os.Getpid(); self != 1 {
		fmt.Fprintf(os.Stderr, "jail init: refusing to supervise outside a pid namespace (pid %d)\n", self)
		return 1
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	s := newSupervisor(escalateTimeout())
	s.setup()
	defer s.stop()
	rawUnblockSupervisorSignals()
	s.prisonerPID = prisonerPID
	s.pgid = prisonerPID
	return s.run()
}

func readPrisonerPID(fd int) (int, error) {
	f := os.NewFile(uintptr(fd), "prisoner-pid")
	defer f.Close()
	var digits []byte
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			digits = append(digits, buf[0])
		}
		if err != nil {
			if len(digits) == 0 {
				return 0, fmt.Errorf("prisoner pid was not reported: %w", err)
			}
			break
		}
	}
	pid, err := strconv.Atoi(string(digits))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("bad prisoner pid %q", string(digits))
	}
	return pid, nil
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
	code, done := s.reap()
	if done {
		return code
	}

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
	if err := syscall.Kill(-s.pgid, sig); err != nil {
		_ = syscall.Kill(s.prisonerPID, sig)
	}
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
