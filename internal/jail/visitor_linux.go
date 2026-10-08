//go:build linux

package jail

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"
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
	data, err := readAllFile(f)
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

	runtimeLockThread()

	if err := applyProcessRestrictions(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "visitor: %v\n", err)
		return 1
	}
	argv, err := resolvePrisonerCommand(&cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "visitor: failed to resolve prisoner: %v\n", err)
		return 127
	}
	env, err := prisonerEnvironment(&cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "visitor: failed to build environment: %v\n", err)
		return 127
	}
	if err := syscall.Exec(argv[0], argv, env); err != nil {
		fmt.Fprintf(os.Stderr, "visitor: failed to exec prisoner: %v\n", err)
		return 127
	}
	return 0
}

func applyProcessRestrictions(cfg *InitConfig) error {
	if err := applyNoNewPrivsPolicy(cfg); err != nil {
		return err
	}
	if seccompRequested(cfg) {
		if _, err := buildSeccompFilter(cfg); err != nil {
			return err
		}
		if err := applySeccompProfile(seccompProfileName(cfg)); err != nil {
			return err
		}
	}
	if cfg.LSM != "" {
		if err := applyLSM(cfg.LSM); err != nil {
			return err
		}
	}
	return applyCapabilityPolicy(cfg.Capabilities)
}
