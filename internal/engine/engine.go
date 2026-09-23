package engine

import (
	"context"
	"sync"
	"time"

	"jailor/internal/api"
	"jailor/internal/ledger"
)

const EventsCapacity = 512

type Engine struct {
	dir string

	mu     sync.Mutex
	led    *ledger.Ledger
	active map[string]*run

	hub *hub

	stopped chan struct{}

	shutdownOnce sync.Once
}

type run struct {
	id     string
	cancel context.CancelFunc
	done   chan struct{}
	code   int
}

func New(dir string) (*Engine, error) {
	if dir == "" {
		dir = ledger.DefaultDir()
	}
	led, err := ledger.New(dir)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		dir:     dir,
		led:     led,
		active:  make(map[string]*run),
		hub:     newHub(EventsCapacity),
		stopped: make(chan struct{}),
	}
	if n, err := e.Recover(); err != nil {
		return nil, err
	} else if n > 0 {
		e.hub.publish(api.Event{
			Type:   api.EventJailRecovered,
			Fields: map[string]any{"count": n},
		})
	}
	return e, nil
}

func (e *Engine) Dir() string { return e.dir }

func (e *Engine) Recover() (int, error) {
	recs, err := e.led.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for i := range recs {
		r := &recs[i]
		if r.State != ledger.StateRunning {
			continue
		}
		if !ledger.ProcessAlive(r.Pid) || r.Pid <= 0 {
			r.State = ledger.StateStopped
			r.Result = "recovered: prisoner no longer running"
			if r.ExitCode == 0 {
				r.ExitCode = -1
			}
			if err := e.led.Set(*r); err != nil {
				return n, err
			}
			n++
			e.hub.publish(api.Event{
				Type:    api.EventJailRecovered,
				JailID:  r.ID,
				Message: "recovered: prisoner no longer running",
			})
			continue
		}

		if err := e.adopt(r); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (e *Engine) adopt(rec *ledger.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.active[rec.ID]; ok {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &run{id: rec.ID, cancel: cancel, done: make(chan struct{})}
	e.active[rec.ID] = r
	go func() {
		code := e.superviseAdopted(ctx, rec)
		close(r.done)
		e.onExit(rec.ID, code, "recovered: adopted after daemon restart")
	}()
	e.hub.publish(api.Event{
		Type:    api.EventJailRecovered,
		JailID:  rec.ID,
		Message: "adopted running jail after daemon restart",
		Fields:  map[string]any{"pid": rec.Pid},
	})
	return nil
}

func (e *Engine) superviseAdopted(ctx context.Context, rec *ledger.Record) int {
	for {
		if processGone(rec.Pid) {
			return rec.ExitCode
		}
		select {
		case <-ctx.Done():
			_ = kill(rec.Pid, sigKill)
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) && !processGone(rec.Pid) {
				time.Sleep(50 * time.Millisecond)
			}
			if !processGone(rec.Pid) {
				return -1
			}
			return 137
		case <-time.After(250 * time.Millisecond):
		}
	}
}
