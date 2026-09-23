package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"jailor/internal/bars"
	"jailor/internal/jail"
)

func logf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "DBG: "+f+"\n", a...)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__init" {
		logf("runinit start")
		os.Exit(jail.RunInit())
	}
	if len(os.Args) > 1 && os.Args[1] == "__probe" {
		os.Exit(probe(os.Args[2]))
	}
	var out bytes.Buffer
	cfg := &jail.InitConfig{
		Args:      []string{"/tmp/jailtest.bin", "__probe", "sig"},
		MountProc: false,
		MountTmp:  false,
		MountDev:  false,
	}
	opts := jail.SpawnOpts{
		Init:        *cfg,
		Namespaces:  []bars.Kind{bars.PID, bars.UTS, bars.Mount},
		Userns:      true,
		Stdout:      &out,
		Stderr:      &out,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}
	logf("spawn")
	child, err := jail.Spawn(opts, cfg)
	if err != nil {
		panic(err)
	}
	defer child.Close()
	logf("start")
	if err := child.Start(); err != nil {
		panic(err)
	}
	logf("release")
	if err := child.Release(); err != nil {
		panic(err)
	}
	logf("readready")
	done := make(chan error, 1)
	go func() { done <- child.ReadReady() }()
	select {
	case err := <-done:
		if err != nil {
			logf("readready err: %v out=%s", err, out.String())
			os.Exit(1)
		}
	case <-time.After(8 * time.Second):
		logf("READY TIMEOUT; out so far: %q", out.String())
		os.Exit(2)
	}
	pid := child.PID()
	data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	for _, line := range bytes.Split(data, []byte("\n")) {
		if strings.HasPrefix(string(line), "SigCgt") || strings.HasPrefix(string(line), "SigIgn") || strings.HasPrefix(string(line), "SigBlk") {
			logf("%s", line)
		}
	}
	logf("init pid=%d", pid)
	for i := 0; i < 3; i++ {
		err = child.Signal(syscall.SIGTERM)
		logf("signal %d err=%v", i, err)
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(3 * time.Second)
	logf("WAIT code=%d", child.Wait())
	logf("OUT: %s", out.String())
}

func probe(kind string) int {
	if kind == "sig" {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		select {
		case <-ch:
			logf("sig=caught")
		case <-time.After(10 * time.Second):
			logf("sig=timeout")
		}
	}
	return 0
}
