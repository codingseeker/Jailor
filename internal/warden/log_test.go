package warden

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailor/internal/ledger"
)

func TestLoggerPersistsAndPrints(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ledger")
	le, err := ledger.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log := newLogger(true, &buf, le)
	log.info("jail.create", "abc", "created", map[string]any{"network": "none"})
	log.err("spawn.failed", "abc", "boom", map[string]any{"error": "kernel panic"})
	log.debug("details", "abc", "verbose", nil)

	logs, err := le.Logs("abc")
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 3 {
		t.Fatalf("expected 3 persisted events, got %d", len(logs))
	}
	if logs[0].Event != "jail.create" || logs[0].Level != ledger.LevelInfo {
		t.Errorf("event[0] = %+v", logs[0])
	}
	if logs[0].Fields["network"] != "none" {
		t.Errorf("event[0] fields = %v", logs[0].Fields)
	}
	if logs[1].Level != ledger.LevelError {
		t.Errorf("event[1] level = %v, want error", logs[1].Level)
	}

	debugOut := buf.String()
	for _, want := range []string{"jail.create", "spawn.failed", "details"} {
		if !strings.Contains(debugOut, want) {
			t.Errorf("debug output missing %q: %q", want, debugOut)
		}
	}
}

func TestLoggerNoDebugSilent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ledger")
	le, err := ledger.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log := newLogger(false, &buf, le)
	log.info("jail.create", "abc", "created", nil)
	if buf.Len() != 0 {
		t.Errorf("non-debug logger should not print, got %q", buf.String())
	}
	logs, err := le.Logs("abc")
	if err != nil || len(logs) != 1 {
		t.Errorf("event not persisted: %v (%v)", logs, err)
	}
}

func TestLoggerNilLedgerSafe(t *testing.T) {
	log := newLogger(true, os.Stderr, nil)
	log.info("jail.create", "abc", "created", nil)
}
