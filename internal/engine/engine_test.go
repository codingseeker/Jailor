package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"jailor/internal/api"
	"jailor/internal/ledger"
	"jailor/internal/warden"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ledger")
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = e.Shutdown(ctx)
	})
	return e
}

func stubStart(t *testing.T, code int) chan string {
	t.Helper()
	started := make(chan string, 1)
	orig := wardenStart
	wardenStart = func(_ context.Context, _ warden.Options, id string) int {
		select {
		case started <- id:
		default:
		}
		return code
	}
	t.Cleanup(func() { wardenStart = orig })
	return started
}

func stubBlock(t *testing.T, code int) chan string {
	t.Helper()
	started := make(chan string, 1)
	orig := wardenStart
	wardenStart = func(ctx context.Context, _ warden.Options, id string) int {
		select {
		case started <- id:
		default:
		}
		<-ctx.Done()
		return code
	}
	t.Cleanup(func() { wardenStart = orig })
	return started
}

func liveChild(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "120")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn child: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return cmd.Process.Pid
}

func TestEngineCreateInspectListRemove(t *testing.T) {
	e := newTestEngine(t)
	spec := api.Jail{Command: []string{"/bin/echo", "hi"}, Hostname: "cell", WorkDir: "/home"}

	rec, err := e.Create(spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.State != ledger.StateCreated {
		t.Errorf("state = %s, want %s", rec.State, ledger.StateCreated)
	}
	if rec.ID == "" {
		t.Error("Create returned empty id")
	}

	got, err := e.Inspect(rec.ID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.Hostname != "cell" {
		t.Errorf("hostname = %q, want cell", got.Hostname)
	}

	list, err := e.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List len = %d, want 1", len(list))
	}

	if err := e.Remove(rec.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := e.Inspect(rec.ID); err == nil {
		t.Error("Inspect after Remove should fail")
	}
}

func TestEngineCreateRequiresCommand(t *testing.T) {
	e := newTestEngine(t)
	if _, err := e.Create(api.Jail{}); err == nil {
		t.Error("Create without command should fail")
	}
}

func TestEngineStartRunsToCompletion(t *testing.T) {
	e := newTestEngine(t)
	started := stubStart(t, 7)

	rec, err := e.Create(api.Jail{Command: []string{"/bin/true"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	done := make(chan int, 1)
	go func() {
		code, err := e.Start(context.Background(), rec.ID)
		if err != nil {
			t.Errorf("Start: %v", err)
			done <- -1
			return
		}
		done <- code
	}()

	select {
	case id := <-started:
		if id != rec.ID {
			t.Errorf("seam started %s, want %s", id, rec.ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start never invoked the supervision seam")
	}

	select {
	case code := <-done:
		if code != 7 {
			t.Errorf("exit code = %d, want 7", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return")
	}
}

func TestEngineCannotDoubleStart(t *testing.T) {
	e := newTestEngine(t)
	started := stubBlock(t, 0)

	rec, err := e.Create(api.Jail{Command: []string{"/bin/true"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _, _ = e.Start(ctx, rec.ID) }()
	<-started

	if _, err := e.Start(context.Background(), rec.ID); err == nil {
		t.Error("double start should fail while supervised")
	}
}

func TestEngineStopKillsWithSignal(t *testing.T) {
	e := newTestEngine(t)
	started := stubBlock(t, 0)

	rec, err := e.Create(api.Jail{Command: []string{"/bin/sleep", "30"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	pid := liveChild(t)
	rec2, _ := e.led.Find(rec.ID)
	rec2.Pid = pid
	_ = e.led.Set(*rec2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		code, err := e.Start(ctx, rec.ID)
		if err != nil {
			t.Errorf("Start: %v", err)
			done <- -1
			return
		}
		done <- code
	}()
	<-started

	if _, err := e.Kill(rec.ID); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	select {
	case code := <-done:
		t.Logf("sentence ended with code %d", code)
	case <-time.After(5 * time.Second):
		t.Fatal("Kill did not let supervision end")
	}
}

func TestEngineRestartRecreatesAndRuns(t *testing.T) {
	e := newTestEngine(t)
	started := stubStart(t, 0)

	rec, err := e.Create(api.Jail{Command: []string{"/bin/echo", "once"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	id := rec.ID

	done := make(chan int, 1)
	go func() {
		code, err := e.Start(context.Background(), id)
		if err != nil {
			t.Errorf("Start: %v", err)
			done <- -1
			return
		}
		done <- code
	}()
	<-started
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("first sentence did not end")
	}

	rc := make(chan int, 1)
	go func() {
		code, err := e.Restart(context.Background(), id)
		if err != nil {
			t.Errorf("Restart: %v", err)
			rc <- -1
			return
		}
		rc <- code
	}()
	select {
	case sid := <-started:
		if sid != id {
			t.Errorf("restarted %s, want %s", sid, id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Restart never re-started the jail")
	}
	select {
	case code := <-rc:
		if code != 0 {
			t.Errorf("restart code = %d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Restart did not return")
	}
}

func TestEngineCreateRejectsInvalidID(t *testing.T) {
	e := newTestEngine(t)
	for _, id := range []string{"..", "../x", "a/b", "a..b"} {
		if _, err := e.Create(api.Jail{Command: []string{"/bin/true"}, ID: id}); err == nil {
			t.Errorf("Create with id %q should fail", id)
		}
	}

	if _, err := os.Stat(filepath.Join(filepath.Dir(e.dir), "x")); err == nil {
		t.Errorf("traversal created %s", filepath.Join(filepath.Dir(e.dir), "x"))
	}
}

func TestEngineObservabilityCounters(t *testing.T) {
	e := newTestEngine(t)

	orig := wardenStart
	wardenStart = func(_ context.Context, _ warden.Options, _ string) int { return 3 }
	t.Cleanup(func() { wardenStart = orig })

	rec, err := e.Create(api.Jail{Command: []string{"/bin/false"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	id := rec.ID
	if got := e.StorageUsage(id); got <= 0 {
		t.Errorf("StorageUsage(%s) = %d, want > 0", id, got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code, err := e.Start(ctx, id)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if code != 3 {
		t.Errorf("Start code = %d, want 3", code)
	}
	got, _ := e.led.Find(id)
	if got.Failures != 1 {
		t.Errorf("Failures = %d, want 1", got.Failures)
	}
}

func TestEngineRestartCarriesCounters(t *testing.T) {
	e := newTestEngine(t)
	started := stubStart(t, 0)

	rec, err := e.Create(api.Jail{Command: []string{"/bin/echo", "hi"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	id := rec.ID
	e.bump(id, "failures")

	done := make(chan int, 1)
	go func() {
		code, err := e.Restart(context.Background(), id)
		if err != nil {
			t.Errorf("Restart: %v", err)
			done <- -1
			return
		}
		done <- code
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("Restart never re-started the jail")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Restart did not return")
	}

	got, _ := e.led.Find(id)
	if got.Restarts != 1 {
		t.Errorf("Restarts = %d, want 1", got.Restarts)
	}
	if got.Failures != 1 {
		t.Errorf("Failures = %d, want 1 (carried across restart)", got.Failures)
	}
}

func TestEngineShutdownCancelsActiveJails(t *testing.T) {
	e := newTestEngine(t)
	started := stubBlock(t, 3)

	rec, err := e.Create(api.Jail{Command: []string{"/bin/sleep", "60"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	pid := liveChild(t)
	rec2, _ := e.led.Find(rec.ID)
	rec2.Pid = pid
	_ = e.led.Set(*rec2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _, _ = e.Start(ctx, rec.ID) }()
	<-started

	shut, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	if err := e.Shutdown(shut); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestEngineEventsFireForLifecycle(t *testing.T) {
	e := newTestEngine(t)
	ch, unsub := e.SubscribeEvents()
	seen := make(chan []api.Event, 1)
	var evs []api.Event
	go func() {
		for ev := range ch {
			evs = append(evs, ev)
		}
		seen <- evs
	}()

	rec, err := e.Create(api.Jail{Command: []string{"/bin/true"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := e.Remove(rec.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	unsub()
	<-seen

	found := map[string]bool{}
	for _, ev := range evs {
		found[ev.Type] = true
	}
	if !found[api.EventJailCreated] {
		t.Errorf("missing created event; got %v", found)
	}
	if !found[api.EventJailRemoved] {
		t.Errorf("missing removed event; got %v", found)
	}
}

func TestEngineRecoverReclassifiesDeadRunning(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ledger")
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := ledger.Record{
		ID:      "ghost",
		State:   ledger.StateRunning,
		Command: "/bin/true",
		Pid:     1 << 30,
		Args:    []string{"/bin/true"},
	}
	_ = e.led.Set(rec)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = e.Shutdown(ctx)

	e2, err := New(dir)
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = e2.Shutdown(ctx)
	}()
	got, err := e2.Inspect("ghost")
	if err != nil {
		t.Fatalf("Inspect ghost: %v", err)
	}
	if got.State != ledger.StateStopped {
		t.Errorf("ghost state = %s, want %s", got.State, ledger.StateStopped)
	}
}

func TestEngineAdoptsLiveRunning(t *testing.T) {
	e := newTestEngine(t)

	rec := ledger.Record{
		ID:      "live",
		State:   ledger.StateRunning,
		Command: "/bin/true",
		Pid:     liveChild(t),
		Args:    []string{"/bin/true"},
	}
	_ = e.led.Set(rec)
	n, err := e.Recover()
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if n < 1 {
		t.Fatalf("Recover adopted %d records, want >= 1", n)
	}

	if _, err := e.Stop("live"); err != nil {
		t.Fatalf("Stop on adopted jail: %v", err)
	}
}

func TestEngineCreateDuplicateID(t *testing.T) {
	e := newTestEngine(t)
	spec := api.Jail{Command: []string{"/bin/true"}, ID: "fixed"}
	if _, err := e.Create(spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := e.Create(spec); err == nil {
		t.Error("Create with duplicate id should fail")
	}
}

func countOpenFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(ents)
}

func TestEngineStartDoesNotLeakFDs(t *testing.T) {
	e := newTestEngine(t)
	stubStart(t, 0)
	before := countOpenFDs(t)
	const cycles = 10
	for i := 0; i < cycles; i++ {
		rec, err := e.Create(api.Jail{Command: []string{"/bin/true"}, ID: fmt.Sprintf("fd-%d", i)})
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		if err := e.led.Set(*rec); err != nil {
			t.Fatalf("Set %d: %v", i, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		code, err := e.Start(ctx, rec.ID)
		cancel()
		if err != nil {
			t.Fatalf("Start %d: %v", i, err)
		}
		if code != 0 {
			t.Fatalf("Start %d: code = %d, want 0", i, code)
		}
	}
	after := countOpenFDs(t)

	if after > before+3 {
		t.Errorf("fd count grew from %d to %d after %d completed Sentences (per-Sentence leak?)", before, after, cycles)
	}
	if os.Getpid() == 0 {
		t.Skip("unreachable")
	}
}

func TestEngineStartFailureLeavesNoGhost(t *testing.T) {
	e := newTestEngine(t)
	orig := wardenStart
	wardenStart = func(_ context.Context, _ warden.Options, _ string) int {
		return 1
	}
	t.Cleanup(func() { wardenStart = orig })

	rec, err := e.Create(api.Jail{Command: []string{"/bin/sleep", "60"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	id := rec.ID

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code, err := e.Start(ctx, id)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if code != 1 {
		t.Errorf("Start code = %d, want 1", code)
	}

	e.mu.Lock()
	_, running := e.active[id]
	e.mu.Unlock()
	if running {
		t.Error("failed Sentence left a tracked runner")
	}
	recGot, err := e.Inspect(id)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if recGot.State == ledger.StateRunning {
		t.Errorf("failed Sentence left a RUNNING record %+v", recGot)
	}
	if recGot.Failures < 1 {
		t.Errorf("Failures = %d, want >= 1", recGot.Failures)
	}
}

func TestEngineConcurrentCreatesAreConsistent(t *testing.T) {
	e := newTestEngine(t)
	const n = 100
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := e.Create(api.Jail{Command: []string{"/bin/true"}, ID: fmt.Sprintf("cc-%03d", i)})
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent create: %v", err)
	}
	recs, err := e.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != n {
		t.Errorf("ledger has %d records, want %d (consistency)", len(recs), n)
	}
	seen := make(map[string]bool, len(recs))
	for i := range recs {
		if seen[recs[i].ID] {
			t.Errorf("duplicate record %s", recs[i].ID)
		}
		seen[recs[i].ID] = true
	}
}

func TestEngineConcurrentLifecycleMix(t *testing.T) {
	e := newTestEngine(t)
	stubStart(t, 0)
	const n = 50
	var wg sync.WaitGroup
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		rec, err := e.Create(api.Jail{Command: []string{"/bin/true"}, ID: fmt.Sprintf("mix-%03d", i)})
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		ids[i] = rec.ID
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := e.Start(ctx, id); err != nil {
				t.Errorf("Start %s: %v", id, err)
				return
			}
			if _, err := e.Inspect(id); err != nil {
				t.Errorf("Inspect %s: %v", id, err)
			}
			if err := e.Remove(id); err != nil {
				t.Errorf("Remove %s: %v", id, err)
			}
		}(ids[i])
	}
	wg.Wait()

	recs, err := e.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, rec := range recs {
		if rec.State != ledger.StateStopped {
			t.Errorf("record %s left in state %s after full lifecycle", rec.ID, rec.State)
		}
	}
}

func TestEngineSoakDetectsLeaks(t *testing.T) {
	e := newTestEngine(t)
	stubStart(t, 0)
	goroutineBase := runtime.NumGoroutine()
	fdBase := countOpenFDs(t)
	const cycles = 60
	for i := 0; i < cycles; i++ {
		rec, err := e.Create(api.Jail{Command: []string{"/bin/true"}, ID: fmt.Sprintf("soak-%04d", i)})
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		if err := e.led.Set(*rec); err != nil {
			t.Fatalf("Set %d: %v", i, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		code, err := e.Start(ctx, rec.ID)
		cancel()
		if err != nil || code != 0 {
			t.Fatalf("Start %d: code=%d err=%v", i, code, err)
		}
		if err := e.Remove(rec.ID); err != nil {
			t.Fatalf("Remove %d: %v", i, err)
		}
	}

	time.Sleep(200 * time.Millisecond)
	goroutineAfter := runtime.NumGoroutine()
	fdAfter := countOpenFDs(t)
	if goroutineAfter > goroutineBase+10 {
		t.Errorf("goroutines grew from %d to %d after %d cycles (goroutine leak?)", goroutineBase, goroutineAfter, cycles)
	}
	if fdAfter > fdBase+3 {
		t.Errorf("fds grew from %d to %d after %d cycles (fd leak?)", fdBase, fdAfter, cycles)
	}
}

var _ = os.Getpid
