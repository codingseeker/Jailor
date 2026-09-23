package warden

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"jailor/internal/cell"
	"jailor/internal/jail"
	"jailor/internal/ledger"
	"jailor/internal/rations"
)

type Action string

const (
	ActionCreate Action = "create"

	ActionStart Action = "start"

	ActionStop Action = "stop"

	ActionKill Action = "kill"

	ActionExit Action = "exit"

	ActionDelete Action = "delete"
)

var transition = map[string]map[Action]string{
	ledger.StateCreated: {
		ActionStart:  ledger.StateRunning,
		ActionDelete: ledger.StateDeleted,
	},
	ledger.StateRunning: {
		ActionStop: ledger.StateStopped,
		ActionKill: ledger.StateStopped,
		ActionExit: ledger.StateStopped,
	},
	ledger.StateStopped: {
		ActionDelete: ledger.StateDeleted,
	},
}

func Apply(state string, action Action) (string, error) {
	if state == ledger.StateDeleted {
		if action == ActionDelete {
			return ledger.StateDeleted, fmt.Errorf("warden: jail is already deleted")
		}
		return "", fmt.Errorf("warden: invalid transition %s -> %s", state, action)
	}
	byAction, ok := transition[state]
	if !ok {
		return "", fmt.Errorf("warden: unknown state %q", state)
	}
	to, ok := byAction[action]
	if !ok {
		return "", fmt.Errorf("warden: invalid transition %s -> %s", state, action)
	}
	return to, nil
}

const terminateGrace = 5 * time.Second

func (w *Warden) Create() (*ledger.Record, error) {
	if len(w.opts.Args) == 0 {
		return nil, errors.New("warden: no command specified")
	}
	id := w.jailID()
	init, c, err := w.prepareCell(id)
	if err != nil {
		return nil, err
	}
	if c != nil {
		_ = c.Cleanup()
	}
	rec := w.newRecord(init, id)
	le := w.openLedger()
	w.log = newLogger(w.opts.Debug, os.Stderr, le)
	if err := le.Set(*rec); err != nil {
		return nil, err
	}
	w.log.info("jail.create", rec.ID, "jail created", map[string]any{
		"command": strings.Join(rec.Args, " "),
		"rootfs":  rec.Rootfs,
	})
	return rec, nil
}

func (w *Warden) Start(ctx context.Context, id string) int {
	le := w.openLedger()
	w.log = newLogger(w.opts.Debug, os.Stderr, le)
	rec, err := le.Find(id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 1
	}
	if _, err := Apply(rec.State, ActionStart); err != nil {
		fmt.Fprintf(os.Stderr, "warden: cannot start jail %s (state %s): %v\n",
			ledger.Short(id), rec.State, err)
		return 1
	}
	w.applyRecord(rec)
	init := w.initFromRecord(rec)
	if init.Rootfs != "" {
		c, err := cell.New(init.Rootfs, init.ReadOnly)
		if err == nil {
			err = c.Validate()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "warden:", err)
			return 127
		}
		init.Rootfs = c.Root
		defer func() { _ = c.Cleanup() }()
	}
	w.log.info("jail.start", rec.ID, "starting sentence", nil)
	return w.supervise(ctx, init, rec, le)
}

func (w *Warden) Stop(id string) int {
	return w.terminate(id, syscall.SIGTERM, ActionStop, "stopped")
}

func (w *Warden) Kill(id string) int {
	return w.terminate(id, syscall.SIGKILL, ActionKill, "killed")
}

func (w *Warden) terminate(id string, sig syscall.Signal, action Action, result string) int {
	le := w.openLedger()
	w.log = newLogger(w.opts.Debug, os.Stderr, le)
	rec, err := le.Find(id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 1
	}
	if _, err := Apply(rec.State, action); err != nil {
		fmt.Fprintf(os.Stderr, "warden: cannot %s jail %s (state %s): %v\n",
			action, ledger.Short(id), rec.State, err)
		return 1
	}
	if rec.Pid <= 0 {
		fmt.Fprintf(os.Stderr, "warden: jail %s has no prisoner pid\n", ledger.Short(id))
		return 1
	}
	if !ledger.ProcessAlive(rec.Pid) {
		rec.State = ledger.StateStopped
		rec.Result = "recovered: prisoner no longer running"
		if rec.ExitCode == 0 {
			rec.ExitCode = -1
		}
		_ = le.Set(*rec)
		fmt.Fprintf(os.Stderr, "warden: jail %s prisoner already gone; recorded STOPPED\n", ledger.Short(id))
		return 0
	}
	if err := syscall.Kill(rec.Pid, sig); err != nil {
		fmt.Fprintf(os.Stderr, "warden: %s prisoner of jail %s: %v\n", action, ledger.Short(id), err)
		return 1
	}
	deadline := time.Now().Add(terminateGrace)
	for time.Now().Before(deadline) {
		if !ledger.ProcessAlive(rec.Pid) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ledger.ProcessAlive(rec.Pid) {
		fmt.Fprintf(os.Stderr, "warden: prisoner of jail %s did not exit within %s after %s\n",
			ledger.Short(id), terminateGrace, sig)
		return 1
	}
	rec.State = ledger.StateStopped
	rec.Result = result
	_ = le.Set(*rec)
	w.log.info("prisoner.terminate", rec.ID, "prisoner terminated", map[string]any{
		"signal": sig.String(), "result": result,
	})
	return 0
}

func (w *Warden) Delete(id string) int {
	le := w.openLedger()
	w.log = newLogger(w.opts.Debug, os.Stderr, le)
	rec, err := le.Find(id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 1
	}
	if _, err := Apply(rec.State, ActionDelete); err != nil {
		fmt.Fprintf(os.Stderr, "warden: cannot delete jail %s (state %s): %v\n",
			ledger.Short(id), rec.State, err)
		return 1
	}
	if err := le.Delete(id); err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 1
	}

	removeJailCgroup(rec.ID)
	if rec.Image != "" {

		w.releaseImageContainer(rec.ID)
		w.log.info("image.release", rec.ID, "image container released", map[string]any{"image": rec.Image})
	}
	w.log.info("jail.delete", rec.ID, "jail released", nil)
	return 0
}

func (w *Warden) rationsFromRecord(rec *ledger.Record) rations.Rations {
	r := rations.Rations{
		MemoryLimitBytes: rec.Memory,
		PIDsLimit:        rec.Pids,
	}
	if rec.CPUs > 0 {
		r.CPUQuotaMicros = int64(math.Round(rec.CPUs * cgroupPeriod))
	}
	r.Enabled = r.MemoryLimitBytes > 0 || r.CPUQuotaMicros > 0 || r.PIDsLimit > 0
	return r
}

const cgroupPeriod = 100000

func (w *Warden) installRations(rec *ledger.Record) (*rations.Cgroup, error) {
	r := w.rationsFromRecord(rec)
	mount, err := rations.FindCgroupV2Mount()
	if err != nil {
		if r.Enabled {
			return nil, fmt.Errorf("warden: cannot serve rations: %w", err)
		}
		return nil, nil
	}
	cg, err := rations.Create(mount, rec.ID, r)
	if err != nil {
		if r.Enabled {
			return nil, fmt.Errorf("warden: cannot allocate rations for jail %s: %w", ledger.Short(rec.ID), err)
		}
		if w.opts.Debug {
			fmt.Fprintf(os.Stderr, "warden: no cgroup for jail %s (unlimited): %v\n", ledger.Short(rec.ID), err)
		}
		return nil, nil
	}
	if err := cg.AddPid(rec.Pid); err != nil {
		return nil, fmt.Errorf("warden: cannot move prisoner %d into cgroup %s: %w", rec.Pid, cg.Path, err)
	}
	if w.opts.Debug {
		fmt.Fprintf(os.Stderr, "warden: jailed prisoner %d in rations %s\n", rec.Pid, cg.Path)
	}
	return cg, nil
}

func removeJailCgroup(id string) {
	cg, err := rations.FindJailCgroup(id)
	if err != nil || !cg.Exists() {
		return
	}
	_ = cg.Remove()
}

func (w *Warden) SweepCgroups(recs []ledger.Record) int {
	mount, err := rations.FindCgroupV2Mount()
	if err != nil {
		return 0
	}
	root := filepath.Join(mount, "jailor")
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	running := make(map[string]bool, len(recs))
	for i := range recs {
		if recs[i].State == ledger.StateRunning {
			running[recs[i].ID] = true
		}
	}
	removed := 0
	for _, e := range entries {
		if !e.IsDir() || running[e.Name()] {
			continue
		}
		if os.Remove(filepath.Join(root, e.Name())) == nil {
			removed++
		}
	}
	return removed
}

func (w *Warden) applyRecord(rec *ledger.Record) {
	if rec.Config != nil {
		if rec.Config.Gate.Mode != "" {
			w.opts.Network = rec.Config.Gate.Mode
		}
		w.opts.Userns = rec.Config.UsernsPolicy()
		if rec.Config.Cell.WorkDir != "" {
			w.opts.WorkDir = rec.Config.Cell.WorkDir
		}
		w.opts.ReadOnly = rec.Config.Cell.ReadOnly
		w.opts.Seccomp = rec.Config.Privileges.Seccomp
		w.opts.NoNewPrivs = rec.Config.Privileges.NoNewPrivs
		w.opts.Capabilities = rec.Config.CapabilityList()
		w.opts.Memory = rec.Memory
		w.opts.CPUs = rec.CPUs
		w.opts.PIDs = rec.Pids
		return
	}
	if rec.Network != "" {
		w.opts.Network = rec.Network
	}
	if rec.Userns == "" {
		rec.Userns = "auto"
	}
	w.opts.Userns = rec.Userns
	if rec.WorkDir != "" {
		w.opts.WorkDir = rec.WorkDir
	}
	w.opts.Memory = rec.Memory
	w.opts.CPUs = rec.CPUs
	w.opts.PIDs = rec.Pids
	w.opts.ReadOnly = rec.ReadOnly
	w.opts.Seccomp = rec.Seccomp
	if len(rec.Capabilities) > 0 {
		w.opts.Capabilities = append([]string(nil), rec.Capabilities...)
	}
}

func (w *Warden) initFromRecord(rec *ledger.Record) *jail.InitConfig {
	return &jail.InitConfig{
		Rootfs:       rec.Rootfs,
		WorkDir:      rec.WorkDir,
		Hostname:     rec.Hostname,
		Args:         rec.Args,
		MountProc:    true,
		MountTmp:     true,
		MountDev:     true,
		ReadOnly:     rec.ReadOnly,
		Seccomp:      rec.Seccomp,
		Capabilities: append([]string(nil), rec.Capabilities...),
	}
}
