//go:build linux

package jail

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"jailor/internal/bars"
	"jailor/internal/runtimecore"
)

type SpawnOpts struct {
	Init InitConfig

	Namespaces []bars.Kind

	Userns bool

	UidMappings []syscall.SysProcIDMap
	GidMappings []syscall.SysProcIDMap

	Cwd string

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	Env []string
}

type Child struct {
	cmd *exec.Cmd

	syncToChild   *os.File
	syncFromChild *os.File
	configPipe    *os.File

	prisonerPID int
	init        InitConfig
}

const (
	syncReady = 'R'
	syncWait  = 'W'
	syncFail  = 'F'
)

func Spawn(opts SpawnOpts, cfg *InitConfig) (*Child, error) {
	if len(cfg.Args) == 0 {
		return nil, errors.New("jail: no prisoner command specified")
	}
	if opts.Userns && (len(opts.UidMappings) == 0 || len(opts.GidMappings) == 0) {
		return nil, errors.New("jail: userns enabled without uid/gid mappings")
	}

	configR, configW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	syncOneR, syncOneW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	syncOutR, syncOutW, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("jail: locate self: %w", err)
	}

	cloneFlags := uintptr(0)
	for _, k := range opts.Namespaces {
		cloneFlags |= k.Flag()
	}

	cmd := exec.Command(self, "__init")
	cmd.Dir = opts.Cwd
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr

	env := os.Environ()
	if len(opts.Env) > 0 {
		env = append([]string(nil), opts.Env...)
	}
	env = append(env,
		envInit+"=1",
		envConfigFD+"="+itoa(cfg.configFD()),
		envSyncInFD+"="+itoa(cfg.syncInFD()),
		envSyncOutFD+"="+itoa(cfg.syncOutFD()),
	)
	cmd.Env = env
	cmd.ExtraFiles = []*os.File{configR, syncOneR, syncOutW}

	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: cloneFlags, Setpgid: true}
	if opts.Userns {

		cmd.SysProcAttr.Cloneflags |= uintptr(syscall.CLONE_NEWUSER)
		cmd.SysProcAttr.UidMappings = opts.UidMappings
		cmd.SysProcAttr.GidMappings = opts.GidMappings
	}

	return &Child{
		cmd:           cmd,
		syncToChild:   syncOneW,
		syncFromChild: syncOutR,
		configPipe:    configW,
		init:          *cfg,
	}, nil
}

func itoa(i int) string {
	return strconv.Itoa(i)
}

func (c *Child) Start() error {
	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("jail: start init: %w", err)
	}
	data, err := c.init.marshal()
	if err != nil {
		c.cmd.Process.Kill()
		c.cmd.Wait()
		return err
	}
	if _, err := c.configPipe.Write(data); err != nil {
		c.cmd.Process.Kill()
		c.cmd.Wait()
		return fmt.Errorf("jail: stream init config: %w", err)
	}
	if err := c.configPipe.Close(); err != nil {
		return err
	}
	c.configPipe = nil
	return nil
}

func (c *Child) Release() error {
	if _, err := c.syncToChild.Write([]byte{syncReady}); err != nil {
		return fmt.Errorf("jail: release init: %w", err)
	}
	return c.syncToChild.Close()
}

func (c *Child) ReadReady() error {
	line, err := readSyncMessage(c.syncFromChild)
	if err != nil {
		return fmt.Errorf("jail: init did not become ready: %w", err)
	}
	if len(line) == 0 || line[0] != syncReady {
		return fmt.Errorf("jail: init failed before admitting the prisoner")
	}
	if pid, perr := strconv.Atoi(line[1:]); perr == nil {
		c.prisonerPID = pid
	}
	return c.syncFromChild.Close()
}

func readSyncMessage(f *os.File) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return string(line), nil
			}
			line = append(line, buf[0])
		}
		if err != nil {
			if err == io.EOF {
				if len(line) == 0 {
					return "", errors.New("sync pipe closed")
				}
				return string(line), nil
			}
			return "", err
		}
	}
}

func (c *Child) PID() int {
	return c.cmd.Process.Pid
}

func (c *Child) PrisonerPID() int {
	return c.prisonerPID
}

func (c *Child) Wait() int {
	err := c.cmd.Wait()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return ws.ExitStatus()
		}
		return ee.ExitCode()
	}
	return 1
}

func (c *Child) Signal(sig os.Signal) error {
	if c.cmd.Process == nil {
		return errors.New("jail: process not running")
	}
	return c.cmd.Process.Signal(sig)
}

func (c *Child) Kill() error {
	if c.cmd.Process == nil {
		return errors.New("jail: process not running")
	}
	return c.cmd.Process.Kill()
}

func FindPrisonerHostPID(initPID int) int {
	return runtimecore.ChildHostPID(initPID)
}

func (c *Child) Close() {
	if c.configPipe != nil {
		c.configPipe.Close()
	}
	if c.syncToChild != nil {
		c.syncToChild.Close()
	}
	if c.syncFromChild != nil {
		c.syncFromChild.Close()
	}
}
