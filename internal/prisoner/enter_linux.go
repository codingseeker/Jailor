//go:build linux

package prisoner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"jailor/internal/jail"
)

const (
	envVisitorCFG    = "JAILOR_VISITOR_CFG_FD"
	envVisitorTarget = "JAILOR_VISITOR_TARGET_PID"
)

type SpawnOptions struct {
	Pid int

	Init jail.InitConfig

	Stdin  *os.File
	Stdout *os.File
	Stderr *os.File
}

func Enter(opts SpawnOptions) error {
	if opts.Pid <= 0 {
		return errors.New("prisoner: target pid must be positive")
	}
	if len(opts.Init.Args) == 0 {
		return errors.New("prisoner: no command to exec inside the jail")
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("prisoner: locate self: %w", err)
	}
	if err := checkProc(opts.Pid); err != nil {
		return err
	}

	cfgData, err := json.Marshal(opts.Init)
	if err != nil {
		return fmt.Errorf("prisoner: encode config: %w", err)
	}
	cfgR, cfgW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("prisoner: config pipe: %w", err)
	}
	defer cfgW.Close()

	cmd := exec.Command(self, "__nsenter")
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	cmd.ExtraFiles = []*os.File{cfgR}
	cmd.Env = append(os.Environ(),
		envVisitorCFG+"=3",
		envVisitorTarget+"="+strconv.Itoa(opts.Pid),
	)

	if err := cmd.Start(); err != nil {
		cfgR.Close()
		cfgW.Close()
		return fmt.Errorf("prisoner: start visitor: %w", err)
	}

	cfgR.Close()

	if _, err := cfgW.Write(cfgData); err != nil {

		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("prisoner: write config: %w", err)
	}
	cfgW.Close()

	return cmd.Wait()
}

func checkProc(pid int) error {
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid)); err != nil {
		return fmt.Errorf("prisoner: target process %d is not running: %w", pid, err)
	}
	return nil
}
