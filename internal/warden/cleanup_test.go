package warden

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"jailor/internal/ledger"
)

func newTempLedger(t *testing.T, state string, pid int) *ledger.Ledger {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ledger")
	le, err := ledger.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	live := pid
	if live <= 0 || !ledger.ProcessAlive(live) {
		live = 1024 * 1024
	}
	le.Set(ledger.Record{
		ID:        "abc",
		State:     state,
		Pid:       live,
		CreatedAt: time.Now(),
	})
	return le
}

func TestRecoverIdempotent(t *testing.T) {
	le := newTempLedger(t, ledger.StateRunning, 1024*1024)

	n1, err := le.Recover()
	if err != nil || n1 != 1 {
		t.Fatalf("first recover = %d, err=%v", n1, err)
	}

	n2, err := le.Recover()
	if err != nil || n2 != 0 {
		t.Fatalf("second recover = %d, err=%v (recovery must be idempotent)", n2, err)
	}
	rec, err := le.Get("abc")
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != ledger.StateStopped {
		t.Errorf("recovered record state = %s, want STOPPED", rec.State)
	}
}

func TestRecoverSkipsLivePrisoner(t *testing.T) {

	le := newTempLedger(t, ledger.StateRunning, os.Getpid())
	n, err := le.Recover()
	if err != nil || n != 0 {
		t.Fatalf("recover = %d, err=%v (live prisoner must not be moved)", n, err)
	}
	rec, err := le.Get("abc")
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != ledger.StateRunning {
		t.Errorf("live record state = %s, want RUNNING", rec.State)
	}
}

func TestDeleteIsIdempotentAfterRecordGone(t *testing.T) {

	le := newTempLedger(t, ledger.StateCreated, 0)
	if err := le.Delete("abc"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := le.Delete("abc"); err == nil {
		t.Error("second delete should error: record already gone")
	}
}
