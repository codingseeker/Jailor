package main

import (
	"fmt"
	"os"
	"syscall"

	"jailor/internal/bars"
	"jailor/internal/jail"
)

func main() {
	cfg := &jail.InitConfig{Args: []string{"/bin/sh", "-c", "echo hi-$$"}}
	child, err := jail.Spawn(jail.SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
	}, cfg)
	if err != nil {
		fmt.Println("spawn err:", err)
		return
	}
	if err := child.Start(); err != nil {
		fmt.Println("start err:", err)
		return
	}
	if err := child.Release(); err != nil {
		fmt.Println("release err:", err)
		return
	}
	if err := child.ReadReady(); err != nil {
		fmt.Println("readready err:", err)
	}
	fmt.Println("exit:", child.Wait())
}
