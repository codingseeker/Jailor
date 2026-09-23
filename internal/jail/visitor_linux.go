//go:build linux

package jail

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	envVisitorCFG = "JAILOR_VISITOR_CFG_FD"

	envVisitorTarget = "JAILOR_VISITOR_TARGET_PID"
)

func IsVisitor() bool {
	return len(os.Args) > 0 && os.Args[1] == "__visitor"
}

func RunVisitor() int {
	cfgFD, err := mustGetFD(envVisitorCFG)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	f := os.NewFile(uintptr(cfgFD), "visitor-config")
	defer f.Close()
	data, err := readAll(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "visitor: read config: %v\n", err)
		return 1
	}
	var cfg InitConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "visitor: parse config: %v\n", err)
		return 1
	}
	if len(cfg.Args) == 0 {
		fmt.Fprintln(os.Stderr, "visitor: no prisoner command")
		return 1
	}

	if err := applyRestrictions(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "visitor: %v\n", err)
		return 1
	}
	if err := execPrisoner(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "visitor: failed to exec prisoner: %v\n", err)
		return 127
	}
	return 0
}
