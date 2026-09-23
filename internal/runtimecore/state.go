package runtimecore

import (
	"fmt"
	"sort"
)

const (
	StateCreated = "CREATED"

	StateStarting = "STARTING"

	StateRunning = "RUNNING"

	StateTerminating = "TERMINATING"

	StateKilling = "KILLING"

	StateExited = "EXITED"

	StateRecovered = "RECOVERED"
)

func ValidStates() []string {
	return []string{
		StateCreated,
		StateStarting,
		StateRunning,
		StateTerminating,
		StateKilling,
		StateExited,
		StateRecovered,
	}
}

const (
	ActionStart     = "start"
	ActionAdmit     = "admit"
	ActionTerminate = "terminate"
	ActionEscalate  = "escalate"
	ActionKill      = "kill"
	ActionReap      = "reap"
	ActionRecover   = "recover"
)

var transitions = map[string]map[string]string{
	StateCreated: {
		ActionStart: StateStarting,
	},
	StateStarting: {
		ActionAdmit:   StateRunning,
		ActionRecover: StateRecovered,
	},
	StateRunning: {
		ActionTerminate: StateTerminating,
		ActionKill:      StateKilling,
		ActionReap:      StateExited,
	},
	StateTerminating: {

		ActionEscalate: StateKilling,
		ActionKill:     StateKilling,
		ActionReap:     StateExited,
	},
	StateKilling: {
		ActionReap: StateExited,
	},
}

func ValidActions() []string {
	out := []string{
		ActionStart,
		ActionAdmit,
		ActionTerminate,
		ActionEscalate,
		ActionKill,
		ActionReap,
		ActionRecover,
	}
	sort.Strings(out)
	return out
}

func Transition(state, action string) (string, error) {
	if allowed, ok := transitions[state]; ok {
		if next, ok := allowed[action]; ok {
			return next, nil
		}
	}
	if state == StateExited || state == StateRecovered {
		return "", fmt.Errorf("runtimecore: %s is terminal, no %q transition", state, action)
	}
	return "", fmt.Errorf("runtimecore: invalid transition %q from %s", action, state)
}
