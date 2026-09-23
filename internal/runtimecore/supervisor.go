package runtimecore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

const DefaultEscalateAfter = 3 * time.Second

const defaultPollInterval = 20 * time.Millisecond

type Options struct {
	EscalateAfter time.Duration

	PollInterval time.Duration
}

type Supervisor struct {
	proc Proc
	opts Options

	mu    sync.Mutex
	state string

	code int

	events chan Event

	cmd      chan command
	ctx      context.Context
	cancel   context.CancelFunc
	stopped  chan struct{}
	terminal chan struct{}
	termOnce sync.Once
}

type commandType int

const (
	cmdTerminate commandType = iota
	cmdKill
)

type command struct {
	typ commandType
	sig os.Signal
	ack chan struct{}
}

func NewSupervisor(proc Proc, options Options) *Supervisor {
	if proc == nil {
		panic("runtimecore: nil Proc")
	}
	if options.EscalateAfter <= 0 {
		options.EscalateAfter = DefaultEscalateAfter
	}
	if options.PollInterval <= 0 {
		options.PollInterval = defaultPollInterval
	}
	return &Supervisor{
		proc:     proc,
		opts:     options,
		state:    StateCreated,
		events:   make(chan Event, 64),
		cmd:      make(chan command, 8),
		terminal: make(chan struct{}),
	}
}

func (s *Supervisor) Events() <-chan Event { return s.events }

func (s *Supervisor) State() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Supervisor) Pid() int { return s.proc.Pid() }

func (s *Supervisor) ExitCode() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateExited && s.state != StateRecovered {
		return -1
	}
	return s.code
}

func (s *Supervisor) Finished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == StateExited || s.state == StateRecovered
}

func (s *Supervisor) transition(action string, code int, message string) error {
	s.mu.Lock()
	next, err := Transition(s.state, action)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.state = next
	s.code = code
	pid := s.proc.Pid()
	s.mu.Unlock()

	s.events <- Event{
		Time:    time.Now(),
		PID:     pid,
		Event:   action,
		State:   next,
		Code:    code,
		Message: message,
	}
	if next == StateExited || next == StateRecovered {
		s.termOnce.Do(func() { close(s.terminal) })
	}
	return nil
}

func (s *Supervisor) Start(ctx context.Context) error {
	if err := s.transition(ActionStart, -1, "supervision starting"); err != nil {
		return err
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.stopped = make(chan struct{})
	go s.loop()
	return nil
}

func (s *Supervisor) Admit() (string, error) {
	if exited, code := s.proc.Exited(); exited {
		if err := s.transition(ActionRecover, code, "process already gone at admission"); err != nil {
			return "", err
		}
		return s.State(), nil
	}
	if err := s.transition(ActionAdmit, -1, "process admitted"); err != nil {
		return "", err
	}
	return s.State(), nil
}

func (s *Supervisor) Terminate(sig os.Signal) error {
	return s.send(command{typ: cmdTerminate, sig: sig})
}

func (s *Supervisor) Kill() error {
	return s.send(command{typ: cmdKill})
}

func (s *Supervisor) send(c command) error {
	c.ack = make(chan struct{})
	select {
	case s.cmd <- c:
	case <-s.ctx.Done():
		return errors.New("runtimecore: supervisor stopped")
	}
	select {
	case <-c.ack:
		return nil
	case <-s.ctx.Done():
		return errors.New("runtimecore: supervisor stopped")
	case <-s.terminal:
		return nil
	}
}

func (s *Supervisor) Detach() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Supervisor) loop() {
	defer close(s.stopped)

	ticker := time.NewTicker(s.opts.PollInterval)
	defer ticker.Stop()

	var timer *time.Timer
	var escalateCh <-chan time.Time

	for {
		if s.Finished() {
			return
		}
		select {
		case <-s.terminal:
			return
		case <-s.ctx.Done():
			if !s.Finished() {
				s.detach()
			}
			return
		case c := <-s.cmd:
			switch c.typ {
			case cmdTerminate:
				escalateCh = s.armTerminate(c.sig, escalateCh, &timer)
			case cmdKill:
				s.killNow(&timer)
				escalateCh = nil
			}
			close(c.ack)
		case <-escalateCh:
			s.escalateNow(&timer)
			escalateCh = nil
		case <-ticker.C:
			if s.reap() {
				return
			}
		}
	}
}

func (s *Supervisor) armTerminate(sig os.Signal, escalateCh <-chan time.Time, timer **time.Timer) <-chan time.Time {
	switch s.State() {
	case StateRunning:
		if err := s.proc.Signal(sig); err != nil {
			s.events <- Event{Time: time.Now(), PID: s.Pid(), Event: "signal-error", State: StateRunning, Message: err.Error()}
		}
		if err := s.transition(ActionTerminate, -1, fmt.Sprintf("forwarded %s", sig)); err != nil {
			return escalateCh
		}
		if *timer != nil {
			(*timer).Stop()
		}
		*timer = time.NewTimer(s.opts.EscalateAfter)
		return (*timer).C
	case StateTerminating:
		if err := s.proc.Signal(syscall.SIGKILL); err != nil {
			s.events <- Event{Time: time.Now(), PID: s.Pid(), Event: "signal-error", State: StateTerminating, Message: err.Error()}
		}
		if *timer != nil {
			(*timer).Stop()
		}
		if err := s.transition(ActionKill, -1, "second termination signal, SIGKILL delivered"); err != nil {
			return nil
		}
		return nil
	default:
		return escalateCh
	}
}

func (s *Supervisor) escalateNow(timer **time.Timer) {
	if s.State() != StateTerminating {
		return
	}
	if err := s.proc.Signal(syscall.SIGKILL); err != nil {
		s.events <- Event{Time: time.Now(), PID: s.Pid(), Event: "signal-error", State: StateTerminating, Message: err.Error()}
	}
	if *timer != nil {
		(*timer).Stop()
	}
	_ = s.transition(ActionEscalate, -1, "grace period expired, SIGKILL delivered")
}

func (s *Supervisor) killNow(timer **time.Timer) {
	state := s.State()
	if state != StateRunning && state != StateTerminating && state != StateKilling {
		return
	}
	if err := s.proc.Signal(syscall.SIGKILL); err != nil {
		s.events <- Event{Time: time.Now(), PID: s.Pid(), Event: "signal-error", State: state, Message: err.Error()}
	}
	if *timer != nil {
		(*timer).Stop()
	}
	if state != StateKilling {
		_ = s.transition(ActionKill, -1, "SIGKILL delivered")
	}
}

func (s *Supervisor) reap() bool {
	exited, code := s.proc.Exited()
	if !exited {
		return false
	}
	if err := s.transition(ActionReap, code, fmt.Sprintf("reaped, exit code %d", code)); err != nil {
		return false
	}
	return true
}

func (s *Supervisor) detach() {
	s.events <- Event{
		Time:    time.Now(),
		PID:     s.Pid(),
		Event:   "detached",
		State:   s.State(),
		Message: "supervisor detached; process left running",
	}
}

func Takeover(pid int) *Supervisor {
	live := NewLive(pid,
		func(sig os.Signal) error { return syscall.Kill(pid, toSyscallSignal(sig)) },
		aliveReaper(pid),
	)
	return NewSupervisor(live, Options{})
}

func toSyscallSignal(sig os.Signal) syscall.Signal {
	if ss, ok := sig.(syscall.Signal); ok {
		return ss
	}
	return syscall.SIGTERM
}

func aliveReaper(pid int) ReapFn {
	return func() (bool, int) {
		if Alive(pid) && !IsZombie(pid) {
			return false, 0
		}
		return true, 137
	}
}
