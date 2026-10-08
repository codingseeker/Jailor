package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"jailor/internal/api"
	"jailor/internal/config"
	"jailor/internal/image"
	"jailor/internal/ledger"
	"jailor/internal/network"
	"jailor/internal/rations"
	"jailor/internal/warden"
)

func (e *Engine) Create(spec api.Jail) (*ledger.Record, error) {
	if spec.ID != "" {
		if !ledger.ValidID(spec.ID) {
			return nil, api.Usage(fmt.Sprintf("invalid jail id %q", spec.ID))
		}
		if _, err := e.led.Find(spec.ID); err == nil {
			return nil, api.Conflict(fmt.Sprintf("a jail named %s already exists", spec.ID))
		}
	}
	opts, err := e.options(spec)
	if err != nil {
		return nil, err
	}
	opts.ID = spec.ID
	w := warden.New(opts)
	rec, err := w.Create()
	if err != nil {
		return nil, err
	}
	e.hub.publish(api.Event{
		Type:    api.EventJailCreated,
		JailID:  rec.ID,
		Message: "jail created",
		Fields: map[string]any{
			"command": strings.Join(rec.Args, " "),
			"rootfs":  rec.Rootfs,
			"image":   rec.Image,
			"network": rec.Network,
		},
	})
	return rec, nil
}

func (e *Engine) Start(ctx context.Context, id string) (int, error) {
	rec, err := e.led.Find(id)
	if err != nil {
		return 0, err
	}
	run, err := e.startLocked(ctx, rec)
	if err != nil {
		return 0, err
	}

	e.hub.publish(api.Event{
		Type:    api.EventJailStarted,
		JailID:  rec.ID,
		Message: "jail started",
		Fields:  map[string]any{"pid": rec.Pid},
	})

	code, err := waitForRun(ctx, run)
	if err != nil {
		return code, err
	}
	e.hub.publish(api.Event{
		Type:    api.EventJailExited,
		JailID:  rec.ID,
		Message: "jail sentence ended",
		Fields:  map[string]any{"code": code},
	})
	return code, nil
}

func (e *Engine) Run(ctx context.Context, spec api.Jail) (api.RunResult, error) {
	rec, err := e.Create(spec)
	if err != nil {
		return api.RunResult{}, err
	}
	code, err := e.Start(ctx, rec.ID)
	if err != nil {
		return api.RunResult{ID: rec.ID}, err
	}

	if final, ferr := e.led.Find(rec.ID); ferr == nil {
		return api.RunResult{ID: rec.ID, ExitCode: code, Result: final.Result}, nil
	}
	return api.RunResult{ID: rec.ID, ExitCode: code}, nil
}

func (e *Engine) startLocked(ctx context.Context, rec *ledger.Record) (*run, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.active[rec.ID]; ok {
		return nil, fmt.Errorf("jail %s is already supervised by this engine", rec.ID)
	}
	if !e.canStart(rec.State) {
		return nil, fmt.Errorf("jail %s cannot be started from state %s", rec.ID, rec.State)
	}

	stdin := openNull()
	stdout := e.console(rec.ID)
	stderr := e.consoleErr(rec.ID)
	opts := warden.Options{
		LedgerDir: e.dir,
		Debug:     false,
		Stdin:     stdin,
		Stdout:    stdout,
		Stderr:    stderr,
	}
	runCtx, cancel := context.WithCancel(ctx)
	r := &run{id: rec.ID, cancel: cancel, done: make(chan struct{})}
	e.active[rec.ID] = r

	go func() {
		defer close(r.done)

		r.setCode(wardenStart(runCtx, opts, rec.ID))

		closeQuietly(stdin, stdout, stderr)
		if code := r.exitCode(); code != 0 && code != 137 && code != 143 {

			e.bump(rec.ID, "failures")
		}
		e.mu.Lock()
		if e.active[rec.ID] == r {
			delete(e.active, rec.ID)
		}
		e.mu.Unlock()
	}()
	return r, nil
}

func (e *Engine) canStart(state string) bool {
	return state == ledger.StateCreated
}

var wardenStart = func(ctx context.Context, opts warden.Options, id string) int {
	return warden.New(opts).Start(ctx, id)
}

func waitForRun(ctx context.Context, r *run) (int, error) {
	select {
	case <-r.done:
		return r.exitCode(), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (e *Engine) SubscribeEvents() (<-chan api.Event, func()) {
	ch := e.hub.subscribe()
	return ch, func() { e.hub.unsubscribe(ch) }
}

func (e *Engine) Stop(id string) (int, error) {
	return e.terminate(id, sigTerm, "stopped")
}

func (e *Engine) Kill(id string) (int, error) {
	return e.terminate(id, sigKill, "killed")
}

func (e *Engine) isRunning(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.active[id]
	return ok
}

func (e *Engine) terminate(id string, sig syscall.Signal, result string) (int, error) {
	e.mu.Lock()
	r, ok := e.active[id]
	e.mu.Unlock()
	rec, _ := e.led.Find(id)
	pid := 0
	if rec != nil {
		pid = rec.Pid
	}

	if pid <= 0 {
		return 0, api.NotFound(fmt.Sprintf("jail %s has no prisoner to signal", id))
	}

	_ = kill(pid, sig)
	if ok {
		r.cancel()
		e.mu.Lock()
		done := r.done
		e.mu.Unlock()
		select {
		case <-done:
		case <-time.After(terminateGrace):
		}
	}

	deadline := time.Now().Add(terminateGrace)
	sentKill := sig == sigKill
	for !processGone(pid) && !sentKill && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !processGone(pid) {

		_ = kill(pid, sigKill)
		sentKill = true
		deadline = time.Now().Add(terminateGrace)
	}
	for !processGone(pid) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}

	if !processGone(pid) {
		return 1, fmt.Errorf("jail %s did not terminate", id)
	}
	e.markStopped(id, result)
	e.mu.Lock()
	if r != nil && e.active[id] == r {
		delete(e.active, id)
	}
	e.mu.Unlock()
	e.hub.publish(api.Event{Type: api.EventJailStopped, JailID: id, Message: result})
	return 0, nil
}

func (e *Engine) Restart(ctx context.Context, id string) (int, error) {
	rec, err := e.led.Find(id)
	if err != nil {
		return 0, err
	}
	if e.isRunning(id) {
		if code, err := e.terminate(id, sigTerm, "restart"); err != nil {
			return code, err
		}
	}

	spec, serr := specFromRecord(rec)
	if serr != nil {
		return 0, serr
	}
	oldRestarts, oldFailures := rec.Restarts, rec.Failures
	if err := e.remove(id, false); err != nil {
		return 0, err
	}
	if _, err := e.Create(spec); err != nil {
		return 0, err
	}

	if fresh, err := e.led.Find(id); err == nil {
		fresh.Restarts = oldRestarts + 1
		fresh.Failures = oldFailures
		_ = e.led.Set(*fresh)
	}
	return e.Start(ctx, id)
}

func (e *Engine) remove(id string, force bool) error {
	e.mu.Lock()
	_, running := e.active[id]
	e.mu.Unlock()
	if running && !force {
		return api.Conflict(fmt.Sprintf("jail %s is running; stop it first", id))
	}
	w := warden.New(warden.Options{LedgerDir: e.dir, Debug: false})
	if code := w.Delete(id); code != 0 {
		return fmt.Errorf("delete jail %s failed", id)
	}
	e.hub.publish(api.Event{Type: api.EventJailRemoved, JailID: id, Message: "jail removed"})
	return nil
}

func (e *Engine) Remove(id string) error {
	return e.remove(id, false)
}

func (e *Engine) markStopped(id, result string) {
	rec, err := e.led.Find(id)
	if err != nil {
		return
	}
	rec.State = ledger.StateStopped
	rec.Result = result
	if rec.ExitCode == 0 {
		rec.ExitCode = -1
	}
	_ = e.led.Set(*rec)
}

func (e *Engine) bump(id, field string) {
	rec, err := e.led.Find(id)
	if err != nil {
		return
	}
	switch field {
	case "restarts":
		rec.Restarts++
	case "failures":
		rec.Failures++
	default:
		return
	}
	_ = e.led.Set(*rec)
}

func (e *Engine) List() ([]ledger.Record, error) {
	if _, err := e.led.Recover(); err != nil {
		return nil, err
	}
	return e.led.List()
}

func (e *Engine) StorageUsage(id string) int64 {
	return e.led.Usage(id)
}

func (e *Engine) Inspect(id string) (*ledger.Record, error) {
	rec, err := e.led.Find(id)
	if err != nil {
		return nil, err
	}
	if rec.State == ledger.StateRunning && !ledger.ProcessAlive(rec.Pid) {
		rec.State = ledger.StateStopped
		rec.Result = "recovered: prisoner no longer running"
		if rec.ExitCode == 0 {
			rec.ExitCode = -1
		}
		_ = e.led.Set(*rec)
	}
	return rec, nil
}

func (e *Engine) Logs(id string) ([]ledger.Log, error) {
	if _, err := e.led.Find(id); err != nil {
		return nil, err
	}
	return e.led.Logs(id)
}

func (e *Engine) Stats(id string) (*rations.Stats, *ledger.Record, error) {
	rec, err := e.led.Find(id)
	if err != nil {
		return nil, nil, err
	}
	cg, err := rations.FindJailCgroup(rec.ID)
	if err != nil || !cg.Exists() {
		return nil, rec, nil
	}
	st, err := cg.Stats()
	if err != nil {
		return nil, rec, err
	}
	return st, rec, nil
}

func (e *Engine) Images() ([]image.Image, error) {
	is, err := image.Open(e.dir)
	if err != nil {
		return nil, err
	}
	return is.List()
}

func (e *Engine) ImageInspect(ref string) (*image.Image, error) {
	is, err := image.Open(e.dir)
	if err != nil {
		return nil, err
	}
	return is.Inspect(ref)
}

func (e *Engine) ImageRemove(refs ...string) (int, error) {
	is, err := image.Open(e.dir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, ref := range refs {
		if err := is.Remove(ref); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func (e *Engine) NetworkCreate(name, subnet, gateway, ipv6 string, dns []string) (*network.Network, error) {
	nm, err := network.Open(e.dir)
	if err != nil {
		return nil, err
	}
	return nm.Create(name, subnet, gateway, ipv6, dns)
}

func (e *Engine) NetworkList() ([]network.Network, error) {
	nm, err := network.Open(e.dir)
	if err != nil {
		return nil, err
	}
	return nm.List()
}

func (e *Engine) NetworkInspect(name string) (*network.Network, []string, error) {
	nm, err := network.Open(e.dir)
	if err != nil {
		return nil, nil, err
	}
	n, err := nm.Get(name)
	if err != nil {
		return nil, nil, err
	}
	allocs, err := nm.Allocations(n.Name)
	if err != nil {
		return n, nil, err
	}
	return n, allocs, nil
}

func (e *Engine) NetworkRemove(names ...string) (int, error) {
	nm, err := network.Open(e.dir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, name := range names {
		if err := nm.Remove(name); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func (e *Engine) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	ids := make([]string, 0, len(e.active))
	for id := range e.active {
		ids = append(ids, id)
	}
	e.mu.Unlock()

	done := make(chan struct{}, 1)
	go func() {
		for _, id := range ids {
			if _, err := e.terminate(id, sigTerm, "daemon shutdown"); err != nil {
				_, _ = e.terminate(id, sigKill, "daemon shutdown")
			}
		}
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	e.hub.publish(api.Event{Type: api.EventDaemonStopped, Message: "daemon stopped"})
	e.hub.close()
	e.shutdownOnce.Do(func() { close(e.stopped) })
	return nil
}

func (e *Engine) options(spec api.Jail) (warden.Options, error) {
	opts := warden.Options{
		Args:         append([]string(nil), spec.Command...),
		Hostname:     spec.Hostname,
		Rootfs:       spec.Rootfs,
		Image:        spec.Image,
		WorkDir:      spec.WorkDir,
		Network:      spec.Network,
		Ports:        append([]string(nil), spec.Ports...),
		DNS:          append([]string(nil), spec.DNS...),
		Userns:       spec.Userns,
		ReadOnly:     spec.ReadOnly,
		Seccomp:      spec.Seccomp,
		Capabilities: append([]string(nil), spec.Caps...),
		NoNewPrivs:   spec.NoNewPriv,
		Env:          append([]string(nil), spec.Env...),
		Memory:       spec.Memory,
		CPUs:         spec.CPUs,
		PIDs:         spec.PIDs,
		LedgerDir:    e.dir,
		Debug:        false,
	}
	if spec.WorkDir == "" {
		opts.WorkDir = "/"
	}
	if len(spec.Command) == 0 {
		return opts, api.Usage("a jail needs a command")
	}
	return opts, nil
}

func specFromRecord(rec *ledger.Record) (api.Jail, error) {
	if rec == nil {
		return api.Jail{}, errors.New("no jail record")
	}
	cfg := (*config.Config)(nil)
	if rec.Config != nil {
		c := *rec.Config
		cfg = &c
	}
	return api.Jail{
		Command:  append([]string(nil), rec.Args...),
		Hostname: rec.Hostname,
		Rootfs:   rec.Rootfs,
		Image:    rec.Image,
		WorkDir:  rec.WorkDir,
		Network:  rec.Network,
		Ports:    append([]string(nil), rec.Ports...),
		DNS:      append([]string(nil), rec.DNS...),
		Userns:   rec.Userns,
		ReadOnly: rec.ReadOnly,
		Seccomp:  rec.Seccomp,
		Caps:     append([]string(nil), rec.Capabilities...),
		Env:      append([]string(nil), rec.Env...),
		Memory:   rec.Memory,
		CPUs:     rec.CPUs,
		PIDs:     rec.Pids,
		ID:       rec.ID,
		Config:   cfgJSON(cfg),
	}, nil
}

func cfgJSON(c *config.Config) []byte {
	if c == nil {
		return nil
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	return b
}

func (e *Engine) onExit(id string, code int, result string) {
	rec, err := e.led.Find(id)
	if err == nil {
		rec.State = ledger.StateStopped
		rec.Result = result
		if code > 0 {
			rec.ExitCode = code
		}
		_ = e.led.Set(*rec)
	}
	e.hub.publish(api.Event{
		Type:    api.EventJailExited,
		JailID:  id,
		Message: result,
		Fields:  map[string]any{"code": code},
	})
}

func (e *Engine) console(id string) *os.File {
	f, err := os.OpenFile(filepath.Join(e.dir, id, "console.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil
	}
	return f
}

func (e *Engine) consoleErr(id string) *os.File {
	f, err := os.OpenFile(filepath.Join(e.dir, id, "console.err.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil
	}
	return f
}

func openNull() *os.File {
	f, _ := os.Open(os.DevNull)
	return f
}

func closeQuietly(files ...*os.File) {
	for _, f := range files {
		if f == nil {
			continue
		}
		_ = f.Close()
	}
}

const terminateGrace = 8 * time.Second
