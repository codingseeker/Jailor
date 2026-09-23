package warden

import (
	"testing"

	"jailor/internal/ledger"
	"jailor/internal/rations"
)

func TestValidTransitions(t *testing.T) {
	cases := []struct {
		from   string
		action Action
		to     string
	}{
		{ledger.StateCreated, ActionStart, ledger.StateRunning},
		{ledger.StateCreated, ActionDelete, ledger.StateDeleted},
		{ledger.StateRunning, ActionStop, ledger.StateStopped},
		{ledger.StateRunning, ActionKill, ledger.StateStopped},
		{ledger.StateRunning, ActionExit, ledger.StateStopped},
		{ledger.StateStopped, ActionDelete, ledger.StateDeleted},
	}
	for _, c := range cases {
		to, err := Apply(c.from, c.action)
		if err != nil {
			t.Errorf("Apply(%s, %s) unexpectedly failed: %v", c.from, c.action, err)
			continue
		}
		if to != c.to {
			t.Errorf("Apply(%s, %s) = %s, want %s", c.from, c.action, to, c.to)
		}
	}
}

func TestInvalidTransitions(t *testing.T) {
	cases := []struct {
		from   string
		action Action
	}{
		{ledger.StateCreated, ActionStop},
		{ledger.StateCreated, ActionKill},
		{ledger.StateCreated, ActionExit},
		{ledger.StateRunning, ActionCreate},
		{ledger.StateRunning, ActionStart},
		{ledger.StateRunning, ActionDelete},
		{ledger.StateStopped, ActionStart},
		{ledger.StateStopped, ActionStop},
		{ledger.StateStopped, ActionKill},
		{ledger.StateStopped, ActionExit},
		{ledger.StateDeleted, ActionStart},
		{ledger.StateDeleted, ActionStop},
		{ledger.StateDeleted, ActionKill},
		{ledger.StateDeleted, ActionExit},
	}
	for _, c := range cases {
		if to, err := Apply(c.from, c.action); err == nil {
			t.Errorf("Apply(%s, %s) = %s, want an error", c.from, c.action, to)
		}
	}
}

func TestApplyUnknownState(t *testing.T) {
	if _, err := Apply("HALT", ActionStart); err == nil {
		t.Error("Apply with unknown state should error")
	}
}

func TestActionsAreDistinct(t *testing.T) {
	actions := []Action{ActionCreate, ActionStart, ActionStop, ActionKill, ActionExit, ActionDelete}
	seen := map[Action]bool{}
	for _, a := range actions {
		if seen[a] {
			t.Errorf("duplicate action %q", a)
		}
		seen[a] = true
		if a == "" {
			t.Error("empty action defined")
		}
	}
}

func TestRationsFromRecord(t *testing.T) {
	w := &Warden{}

	cases := []struct {
		name string
		rec  ledger.Record
		want rations.Rations
	}{
		{
			name: "unlimited",
			rec:  ledger.Record{},
			want: rations.Rations{Enabled: false},
		},
		{
			name: "memory only",
			rec:  ledger.Record{Memory: 256 << 20},
			want: rations.Rations{MemoryLimitBytes: 256 << 20, Enabled: true},
		},
		{
			name: "fractional cpus",
			rec:  ledger.Record{CPUs: 0.5},
			want: rations.Rations{CPUQuotaMicros: 50000, Enabled: true},
		},
		{
			name: "two cpus",
			rec:  ledger.Record{CPUs: 2},
			want: rations.Rations{CPUQuotaMicros: 200000, Enabled: true},
		},
		{
			name: "all limits",
			rec:  ledger.Record{Memory: 1 << 30, CPUs: 1.5, Pids: 42},
			want: rations.Rations{MemoryLimitBytes: 1 << 30, CPUQuotaMicros: 150000, PIDsLimit: 42, Enabled: true},
		},
	}
	for _, c := range cases {
		got := w.rationsFromRecord(&c.rec)
		if got != c.want {
			t.Errorf("%s: rationsFromRecord = %+v, want %+v", c.name, got, c.want)
		}
	}
}
