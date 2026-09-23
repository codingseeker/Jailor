package runtimecore

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeProc struct {
	mu   sync.Mutex
	pid  int
	dead bool
	code int
	sigs []os.Signal
}

func (f *fakeProc) Pid() int { return f.pid }

func (f *fakeProc) Signal(sig os.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sigs = append(f.sigs, sig)
	return nil
}

func (f *fakeProc) Exited() (bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dead {
		f.dead = false
		return true, f.code
	}
	return false, 0
}

func (f *fakeProc) die(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dead = true
	f.code = code
}

func (f *fakeProc) saw(sig os.Signal) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, got := range f.sigs {
		if got == sig {
			return true
		}
	}
	return false
}

func newFake(pid int) *fakeProc { return &fakeProc{pid: pid} }

type eventLog struct {
	mu sync.Mutex
	ev []Event
}

func (l *eventLog) add(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ev = append(l.ev, e)
}

func (l *eventLog) all() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, len(l.ev))
	copy(out, l.ev)
	return out
}

func (l *eventLog) events() []string {
	out := l.all()
	names := make([]string, len(out))
	for i, e := range out {
		names[i] = e.Event
	}
	return names
}

func startRecorder(ctx context.Context, evs <-chan Event) *eventLog {
	l := &eventLog{}
	go func() {
		for {
			select {
			case e := <-evs:
				l.add(e)
			case <-ctx.Done():
				return
			}
		}
	}()
	return l
}

func waitEvent(t *testing.T, timeout time.Duration, pred func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s", msg)
}

func newSupervisedFake(t *testing.T, fake *fakeProc, opts Options) (*Supervisor, context.Context, *eventLog) {
	t.Helper()
	s := NewSupervisor(fake, opts)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := startRecorder(ctx, s.Events())
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return s, ctx, log
}

func TestTransitionTable(t *testing.T) {
	cases := []struct {
		state, action string
		want          string
		ok            bool
	}{
		{StateCreated, ActionStart, StateStarting, true},
		{StateCreated, ActionAdmit, "", false},
		{StateStarting, ActionAdmit, StateRunning, true},
		{StateStarting, ActionRecover, StateRecovered, true},
		{StateRunning, ActionTerminate, StateTerminating, true},
		{StateRunning, ActionKill, StateKilling, true},
		{StateRunning, ActionReap, StateExited, true},
		{StateTerminating, ActionEscalate, StateKilling, true},
		{StateTerminating, ActionKill, StateKilling, true},
		{StateTerminating, ActionReap, StateExited, true},
		{StateKilling, ActionReap, StateExited, true},
		{StateExited, ActionReap, "", false},
		{StateRecovered, ActionStart, "", false},
		{StateRunning, ActionStart, "", false},
	}
	for _, c := range cases {
		got, err := Transition(c.state, c.action)
		if c.ok {
			if err != nil {
				t.Fatalf("Transition(%s, %s): unexpected error %v", c.state, c.action, err)
			}
			if got != c.want {
				t.Fatalf("Transition(%s, %s) = %s, want %s", c.state, c.action, got, c.want)
			}
		} else if err == nil {
			t.Fatalf("Transition(%s, %s) = %s, want error", c.state, c.action, got)
		}
	}
}

func TestValidStatesIsSeven(t *testing.T) {
	states := ValidStates()
	if len(states) != 7 {
		t.Fatalf("ValidStates() has %d states, want 7: %v", len(states), states)
	}
}

func TestNaturalExit(t *testing.T) {
	fake := newFake(42)
	s, _, log := newSupervisedFake(t, fake, Options{})

	if _, err := s.Admit(); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if s.State() != StateRunning {
		t.Fatalf("state after admit = %s, want %s", s.State(), StateRunning)
	}

	fake.die(0)
	waitEvent(t, 5*time.Second, func() bool {
		return s.Finished() && s.State() == StateExited
	}, "natural exit was never reaped")

	if s.ExitCode() != 0 {
		t.Fatalf("ExitCode = %d, want 0", s.ExitCode())
	}
	waitEvent(t, 5*time.Second, func() bool {
		return strings.Join(log.events(), ",") == "start,admit,reap"
	}, "reap event not observed")
}

func TestGracePeriodEscalatesToKill(t *testing.T) {
	fake := newFake(7)
	s, _, _ := newSupervisedFake(t, fake, Options{EscalateAfter: 100 * time.Millisecond})

	if _, err := s.Admit(); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if err := s.Terminate(syscall.SIGTERM); err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	if s.State() != StateTerminating {
		t.Fatalf("state after terminate = %s, want %s", s.State(), StateTerminating)
	}

	waitEvent(t, 5*time.Second, func() bool {
		return s.State() == StateKilling && fake.saw(syscall.SIGKILL) && !fake.saw(syscall.SIGINT)
	}, "grace period did not escalate to SIGKILL")

	if !fake.saw(syscall.SIGTERM) {
		t.Fatal("SIGTERM was never forwarded")
	}
}

func TestSecondTerminateEscalatesImmediately(t *testing.T) {
	fake := newFake(7)
	s, _, _ := newSupervisedFake(t, fake, Options{EscalateAfter: time.Hour})

	if _, err := s.Admit(); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if err := s.Terminate(syscall.SIGTERM); err != nil {
		t.Fatalf("first Terminate: %v", err)
	}
	if err := s.Terminate(syscall.SIGINT); err != nil {
		t.Fatalf("second Terminate: %v", err)
	}
	if s.State() != StateKilling {
		t.Fatalf("state after second terminate = %s, want %s", s.State(), StateKilling)
	}
	if !fake.saw(syscall.SIGKILL) {
		t.Fatal("SIGKILL was not delivered on second terminate")
	}
	if !fake.saw(syscall.SIGTERM) {
		t.Fatal("SIGTERM was not forwarded before the escalation")
	}
}

func TestSignalExitThenReap(t *testing.T) {
	fake := newFake(3)
	s, _, _ := newSupervisedFake(t, fake, Options{})
	if _, err := s.Admit(); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if err := s.Terminate(syscall.SIGTERM); err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	fake.die(143)
	waitEvent(t, 5*time.Second, func() bool { return s.State() == StateExited }, "process not reaped")
	if s.ExitCode() != 143 {
		t.Fatalf("ExitCode = %d, want 143", s.ExitCode())
	}
}

func TestAdmitRecovered(t *testing.T) {
	fake := newFake(9)
	fake.die(137)
	s, _, log := newSupervisedFake(t, fake, Options{})

	state, err := s.Admit()
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if state != StateRecovered {
		t.Fatalf("Admit = %s, want %s", state, StateRecovered)
	}
	if s.ExitCode() != 137 {
		t.Fatalf("ExitCode = %d, want 137", s.ExitCode())
	}
	waitEvent(t, 5*time.Second, func() bool {
		got := strings.Join(log.events(), ",")
		return got == "start,recover"
	}, "recover event not observed")
}

func TestKillFromRunning(t *testing.T) {
	fake := newFake(11)
	s, _, _ := newSupervisedFake(t, fake, Options{})
	if _, err := s.Admit(); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if err := s.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if s.State() != StateKilling {
		t.Fatalf("state after kill = %s, want %s", s.State(), StateKilling)
	}
	if !fake.saw(syscall.SIGKILL) {
		t.Fatal("SIGKILL was not delivered")
	}
}

func TestDetachLeavesProcessRunning(t *testing.T) {
	fake := newFake(1)
	s, _, log := newSupervisedFake(t, fake, Options{})
	if _, err := s.Admit(); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	s.Detach()
	waitEvent(t, 5*time.Second, func() bool {
		for _, e := range log.all() {
			if e.Event == "detached" {
				return true
			}
		}
		return false
	}, "detach event not emitted")

	if s.State() != StateRunning {
		t.Fatalf("state after detach = %s, want %s (process must be untouched)", s.State(), StateRunning)
	}
	if fake.saw(syscall.SIGKILL) || fake.saw(syscall.SIGTERM) {
		t.Fatal("detach must not signal the process")
	}
}

func TestInvalidStart(t *testing.T) {
	fake := newFake(5)
	s := NewSupervisor(fake, Options{})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := s.Admit(); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("second Start must fail")
	}
}

func TestTakeoverAliveAndDead(t *testing.T) {
	cmd := exec.Command("sleep", "3600")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	s := Takeover(cmd.Process.Pid)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := s.Admit(); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if s.State() != StateRunning {
		t.Fatalf("takeover of live pid state = %s, want %s", s.State(), StateRunning)
	}

	if err := s.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	waitEvent(t, 5*time.Second, func() bool { return s.State() == StateExited }, "takeover kill not reaped")
	if s.ExitCode() != 137 {
		t.Fatalf("ExitCode = %d, want 137", s.ExitCode())
	}

	dead := Takeover(1 << 20)
	deadCtx, deadCancel := context.WithCancel(context.Background())
	t.Cleanup(deadCancel)
	if err := dead.Start(deadCtx); err != nil {
		t.Fatalf("Start dead: %v", err)
	}
	state, err := dead.Admit()
	if err != nil {
		t.Fatalf("Admit dead: %v", err)
	}
	if state != StateRecovered {
		t.Fatalf("takeover of dead pid = %s, want %s", state, StateRecovered)
	}
}

var _ = os.Signal(syscall.SIGTERM)
