package ledger

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSetGet(t *testing.T) {
	l, err := New(filepath.Join(t.TempDir(), "led"))
	if err != nil {
		t.Fatal(err)
	}
	rec := Record{
		ID:        "abc123",
		Command:   "echo",
		Args:      []string{"echo", "hi"},
		State:     StateCreated,
		CreatedAt: time.Now(),
	}
	if err := l.Set(rec); err != nil {
		t.Fatal(err)
	}
	got, err := l.Get("abc123")
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != "echo" || got.State != StateCreated || len(got.Args) != 2 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestValidID(t *testing.T) {
	allowed := []string{"abc123", "cell_a", "weird-name", "a.b.c", "A9_"}
	rejected := []string{"", ".", "..", "../x", "a/b", `a\b`, "a..b", "-lead", ".lead", "a b", "a:b"}
	for _, id := range allowed {
		if !ValidID(id) {
			t.Errorf("ValidID(%q) = false, want true", id)
		}
	}
	for _, id := range rejected {
		if ValidID(id) {
			t.Errorf("ValidID(%q) = true, want false", id)
		}
	}
}

func TestSetRejectsTraversal(t *testing.T) {
	l, err := New(filepath.Join(t.TempDir(), "led"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"..", "../escape", "sub/../../escape", `a\b`} {
		if err := l.Set(Record{ID: id, State: StateCreated}); err == nil {
			t.Errorf("Set with id %q should be rejected", id)
		}
	}

	esc := filepath.Join(filepath.Dir(l.Root), "escape")
	if _, err := os.Stat(esc); err == nil {
		t.Errorf("traversal wrote %s", esc)
	}
}

func TestRecordEnvRoundTrip(t *testing.T) {
	l, err := New(filepath.Join(t.TempDir(), "led"))
	if err != nil {
		t.Fatal(err)
	}
	rec := Record{
		ID:           "envjail",
		Command:      "echo",
		Args:         []string{"echo", "hi"},
		State:        StateCreated,
		CreatedAt:    time.Now(),
		Env:          []string{"A=1", "B=two"},
		Capabilities: []string{"CAP_CHOWN"},
	}
	if err := l.Set(rec); err != nil {
		t.Fatal(err)
	}
	got, err := l.Get("envjail")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Env) != 2 || got.Env[0] != "A=1" || got.Env[1] != "B=two" {
		t.Errorf("env round-trip = %v, want [A=1 B=two]", got.Env)
	}
}

func TestGetMissing(t *testing.T) {
	l, _ := New(t.TempDir())
	if _, err := l.Get("nope"); err == nil {
		t.Error("Get of missing id should error")
	}
}

func TestListSortsAscending(t *testing.T) {
	l, _ := New(t.TempDir())
	base := time.Now()
	for i, id := range []string{"a", "b", "c"} {
		if err := l.Set(Record{ID: id, State: StateStopped, CreatedAt: base.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	recs, _ := l.List()
	if len(recs) != 3 {
		t.Fatalf("want 3 records, got %d", len(recs))
	}
	if recs[0].ID != "a" || recs[1].ID != "b" || recs[2].ID != "c" {
		t.Errorf("list should be ascending, got %s %s %s", recs[0].ID, recs[1].ID, recs[2].ID)
	}
}

func TestDelete(t *testing.T) {
	l, _ := New(t.TempDir())
	_ = l.Set(Record{ID: "x", State: StateStopped})
	if err := l.Delete("x"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get("x"); err == nil {
		t.Error("record should be gone after Delete")
	}
}

func TestRecoverStale(t *testing.T) {
	l, _ := New(t.TempDir())

	_ = l.Set(Record{ID: "stale", State: StateRunning, Pid: 999999999})

	_ = l.Set(Record{ID: "live", State: StateRunning, Pid: os.Getpid()})

	recovered, err := l.Recover()
	if err != nil {
		t.Fatal(err)
	}
	if recovered != 1 {
		t.Errorf("want 1 recovered, got %d", recovered)
	}
	stale, _ := l.Get("stale")
	if stale.State != StateStopped {
		t.Errorf("stale should be STOPPED, got %s", stale.State)
	}
	live, _ := l.Get("live")
	if live.State != StateRunning {
		t.Errorf("live should remain RUNNING, got %s", live.State)
	}
}

func TestDefaultDirFallbacks(t *testing.T) {
	oldEnv := os.Getenv("JAILOR_LEDGER")
	defer os.Setenv("JAILOR_LEDGER", oldEnv)
	_ = os.Setenv("JAILOR_LEDGER", "/tmp/custom-ledger")
	if got := DefaultDir(); got != "/tmp/custom-ledger" {
		t.Errorf("env override: got %s", got)
	}
	_ = os.Setenv("JAILOR_LEDGER", "")
	if os.Geteuid() == 0 {
		if got := DefaultDir(); got != DefaultRoot {
			t.Errorf("root default: got %s", got)
		}
	}
}

func TestProcessAlive(t *testing.T) {
	if !ProcessAlive(os.Getpid()) {
		t.Error("self should be alive")
	}
	if ProcessAlive(999999999) {
		t.Error("huge pid should be dead")
	}
	if ProcessAlive(0) {
		t.Error("pid 0 should be dead")
	}
}

func TestIsValidState(t *testing.T) {
	for _, s := range []string{StateCreated, StateRunning, StateStopped, StateDeleted} {
		if !IsValidState(s) {
			t.Errorf("%s should be valid", s)
		}
	}
	if IsValidState("HALT") {
		t.Error("HALT should be invalid")
	}
}

func TestShort(t *testing.T) {
	if got := Short("0123456789abcdef"); got != "0123456789ab" {
		t.Errorf("short: got %s", got)
	}
	if got := Short("ab"); got != "ab" {
		t.Errorf("short short id: got %s", got)
	}
}

func TestFindExact(t *testing.T) {
	l, _ := New(t.TempDir())
	_ = l.Set(Record{ID: "0123456789abcdefaaaaaaaa", State: StateCreated})
	rec, err := l.Find("0123456789abcdefaaaaaaaa")
	if err != nil {
		t.Fatalf("Find exact: %v", err)
	}
	if rec.ID != "0123456789abcdefaaaaaaaa" {
		t.Errorf("Find exact id returned %q", rec.ID)
	}
}

func TestFindPrefix(t *testing.T) {
	l, _ := New(t.TempDir())
	_ = l.Set(Record{ID: "0123456789abcdefaaaaaaaa", State: StateCreated})
	rec, err := l.Find("0123456789ab")
	if err != nil {
		t.Fatalf("Find prefix: %v", err)
	}
	if rec.ID != "0123456789abcdefaaaaaaaa" {
		t.Errorf("Find prefix returned %q", rec.ID)
	}
}

func TestFindAmbiguous(t *testing.T) {
	l, _ := New(t.TempDir())
	_ = l.Set(Record{ID: "aaaa1111", State: StateCreated})
	_ = l.Set(Record{ID: "aaaa2222", State: StateCreated})
	if _, err := l.Find("aaaa"); err == nil {
		t.Error("Find with ambiguous prefix should error")
	}
}

func TestFindMissing(t *testing.T) {
	l, _ := New(t.TempDir())
	_ = l.Set(Record{ID: "bbbb1111", State: StateCreated})
	if _, err := l.Find("cccc"); err == nil {
		t.Error("Find with unknown id should error")
	}
	if _, err := l.Find(""); err == nil {
		t.Error("Find with empty id should error")
	}
}
