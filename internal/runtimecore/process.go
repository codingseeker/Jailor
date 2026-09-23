package runtimecore

import (
	"errors"
	"os"
)

type Proc interface {
	Pid() int

	Signal(sig os.Signal) error

	Exited() (exited bool, code int)
}

type SignalFn func(sig os.Signal) error

type ReapFn func() (exited bool, code int)

type Live struct {
	pid    int
	signal SignalFn
	reap   ReapFn
}

func NewLive(pid int, signal SignalFn, reap ReapFn) *Live {
	return &Live{pid: pid, signal: signal, reap: reap}
}

func (p *Live) Pid() int { return p.pid }

func (p *Live) Signal(sig os.Signal) error {
	if p.signal == nil {
		return errors.New("runtimecore: no signaler configured")
	}
	return p.signal(sig)
}

func (p *Live) Exited() (bool, int) {
	if p.reap == nil {
		return false, 0
	}
	return p.reap()
}

var _ Proc = (*Live)(nil)
