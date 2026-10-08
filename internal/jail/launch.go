//go:build linux

package jail

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

	configPipe   *os.File
	releasePipe  *os.File
	readyPipe    *os.File
	initPIDPipe  *os.File
	prisonerPipe *os.File

	init InitConfig

	initPID     int
	prisonerPID int

	waited     bool
	waitStatus int
}

const (
	syncReady = 'R'
	syncWait  = 'W'
	syncFail  = 'F'
	syncInit  = 'I'
)

const InitArg = "__init"

const StagerArg = "__stager"

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
	releaseR, releaseW, err := os.Pipe()
	if err != nil {
		closeAll(configR, configW)
		return nil, err
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		closeAll(configR, configW, releaseR, releaseW)
		return nil, err
	}
	initPIDR, initPIDW, err := os.Pipe()
	if err != nil {
		closeAll(configR, configW, releaseR, releaseW, readyR, readyW)
		return nil, err
	}
	prisonerR, prisonerW, err := os.Pipe()
	if err != nil {
		closeAll(configR, configW, releaseR, releaseW, readyR, readyW, initPIDR, initPIDW)
		return nil, err
	}
	if err := clearCloseOnExec(int(prisonerR.Fd())); err != nil {
		closeAll(configR, configW, releaseR, releaseW, readyR, readyW, initPIDR, initPIDW, prisonerR, prisonerW)
		return nil, fmt.Errorf("jail: keep prisoner pid descriptor open across exec: %w", err)
	}

	self, err := os.Executable()
	if err != nil {
		closeAll(configR, configW, releaseR, releaseW, readyR, readyW, initPIDR, initPIDW, prisonerR, prisonerW)
		return nil, fmt.Errorf("jail: locate self: %w", err)
	}

	cloneFlags := uintptr(0)
	newPIDNS := false
	for _, k := range opts.Namespaces {
		if k.Flag() == uintptr(syscall.CLONE_NEWPID) {
			newPIDNS = true
			continue
		}
		cloneFlags |= k.Flag()
	}

	cmd := exec.Command(self, StagerArg)
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
		envNewPIDNS+"="+boolFlag(newPIDNS),
		envConfigFD+"="+itoa(baseFD+extraConfig),
		envReleaseFD+"="+itoa(baseFD+extraRelease),
		envReadyFD+"="+itoa(baseFD+extraReady),
		envInitPIDFD+"="+itoa(baseFD+extraInitPID),
		envPrisonerReadFD+"="+itoa(baseFD+extraPrisonerRead),
		envPrisonerWriteFD+"="+itoa(baseFD+extraPrisonerWrite),
	)
	cmd.Env = env
	cmd.ExtraFiles = []*os.File{configR, releaseR, readyW, initPIDW, prisonerR, prisonerW}

	keep := map[int]bool{
		baseFD + extraPrisonerRead: true,
	}
	if err := closeInheritedDescriptors(keep); err != nil {
		closeAll(configR, configW, releaseR, releaseW, readyR, readyW, initPIDR, initPIDW, prisonerR, prisonerW)
		return nil, err
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: cloneFlags, Setpgid: true}
	if opts.Userns {
		cmd.SysProcAttr.Cloneflags |= uintptr(syscall.CLONE_NEWUSER)
		cmd.SysProcAttr.UidMappings = opts.UidMappings
		cmd.SysProcAttr.GidMappings = opts.GidMappings
	}

	return &Child{
		cmd:          cmd,
		init:         *cfg,
		configPipe:   configW,
		releasePipe:  releaseW,
		readyPipe:    readyR,
		initPIDPipe:  initPIDR,
		prisonerPipe: prisonerR,
	}, nil
}

const (
	fSetFD   = 2
	fGetFD   = 1
	fDUPFD   = 0
	fCLOEXEC = 1
)

func clearCloseOnExec(fd int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(fSetFD), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func boolFlag(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func itoa(i int) string {
	return strconv.Itoa(i)
}

func closeAll(files ...*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}

func (c *Child) Start() error {
	if err := c.cmd.Start(); err != nil {
		closeAll(c.configPipe, c.releasePipe, c.readyPipe, c.initPIDPipe)
		return fmt.Errorf("jail: start jail stager: %w", err)
	}
	for _, f := range c.cmd.ExtraFiles {
		if f != nil {
			_ = f.Close()
		}
	}
	c.cmd.ExtraFiles = nil
	if err := c.writeConfig(); err != nil {
		c.killStager()
		return err
	}
	return nil
}

func (c *Child) writeConfig() error {
	data, err := marshalConfig(&c.init)
	if err != nil {
		return err
	}
	if _, err := c.configPipe.Write(data); err != nil {
		return fmt.Errorf("jail: stream jail config: %w", err)
	}
	if err := c.configPipe.Close(); err != nil {
		return fmt.Errorf("jail: close jail config pipe: %w", err)
	}
	c.configPipe = nil
	return nil
}

func (c *Child) killStager() {
	if c.cmd.Process == nil {
		return
	}
	_ = c.cmd.Process.Kill()
	_, _ = c.cmd.Process.Wait()
}

func (c *Child) Release() error {
	if c.releasePipe == nil {
		return errors.New("jail: jail already released")
	}
	pipe := c.releasePipe
	c.releasePipe = nil
	if _, err := pipe.Write([]byte{syncReady}); err != nil {
		pipe.Close()
		return fmt.Errorf("jail: release jail: %w", err)
	}
	if err := pipe.Close(); err != nil {
		return err
	}
	return nil
}

func (c *Child) ReadReady() error {
	if c.readyPipe == nil {
		return errors.New("jail: readiness already consumed")
	}
	pipe := c.readyPipe
	c.readyPipe = nil
	line, err := readSyncMessage(pipe)
	_ = pipe.Close()
	if err != nil {
		return fmt.Errorf("jail: init did not become ready: %w", err)
	}
	if len(line) == 0 || line[0] != syncReady {
		reason := strings.TrimSpace(strings.TrimPrefix(line, string(syncFail)))
		if reason == "" {
			reason = "no reason reported"
		}
		return fmt.Errorf("jail: init failed before admitting the prisoner: %s", reason)
	}
	if pid := parseInitPID(line[1:]); pid > 0 {
		c.prisonerPID = pid
	}
	return nil
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
	if c.initPID == 0 && c.initPIDPipe != nil {
		line, err := readSyncMessage(c.initPIDPipe)
		if err == nil && len(line) > 0 && line[0] == syncInit {
			c.initPID = parseInitPID(line[1:])
		}
	}
	return c.initPID
}

func (c *Child) PrisonerPID() int {
	return c.prisonerPID
}

func (c *Child) Wait() int {
	if c.waited {
		return c.waitStatus
	}
	c.waited = true
	err := c.cmd.Wait()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			c.waitStatus = statusCode(ws)
			return c.waitStatus
		}
		c.waitStatus = ee.ExitCode()
		return c.waitStatus
	}
	c.waitStatus = 1
	return c.waitStatus
}

func (c *Child) Signal(sig os.Signal) error {
	pid := c.PID()
	if pid <= 0 {
		return errors.New("jail: jail init not running")
	}
	s, ok := sig.(syscall.Signal)
	if !ok {
		return fmt.Errorf("jail: unsupported signal %v", sig)
	}
	if err := syscall.Kill(pid, s); err != nil {
		return fmt.Errorf("jail: signal jail init: %w", err)
	}
	return nil
}

func (c *Child) Kill() error {
	pid := c.PID()
	if pid <= 0 {
		return errors.New("jail: jail init not running")
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}

func FindPrisonerHostPID(initPID int) int {
	return runtimecore.ChildHostPID(initPID)
}

func (c *Child) Close() {
	if c.configPipe != nil {
		c.configPipe.Close()
	}
	if c.releasePipe != nil {
		c.releasePipe.Close()
	}
	if c.readyPipe != nil {
		c.readyPipe.Close()
	}
	if c.initPIDPipe != nil {
		c.initPIDPipe.Close()
	}
	if c.prisonerPipe != nil {
		c.prisonerPipe.Close()
	}
}
