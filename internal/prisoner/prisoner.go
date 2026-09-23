package prisoner

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
)

type Prisoner struct {
	Args []string

	Cmd *exec.Cmd
}

func NewPrisoner(args []string) (*Prisoner, error) {
	if len(args) == 0 {
		return nil, errors.New("prisoner: no command provided")
	}
	return &Prisoner{Args: args}, nil
}

func (p *Prisoner) PID() int {
	if p.Cmd == nil || p.Cmd.Process == nil {
		return 0
	}
	return p.Cmd.Process.Pid
}

func (p *Prisoner) Signal(sig syscall.Signal) error {
	if p.Cmd == nil || p.Cmd.Process == nil {
		return errors.New("prisoner: not running")
	}
	if err := p.Cmd.Process.Signal(sig); err != nil {
		return fmt.Errorf("prisoner: signal %d: %w", sig, err)
	}
	return nil
}
