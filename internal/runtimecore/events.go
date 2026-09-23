package runtimecore

import "time"

type Event struct {
	Time time.Time

	PID int

	Event string

	State string

	Code int

	Message string

	Fields map[string]any
}

func (e Event) Terminal() bool {
	return e.State == StateExited || e.State == StateRecovered
}
