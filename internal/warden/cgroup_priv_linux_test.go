//go:build linux && jailor_priv

package warden

import (
	"os"
	"path/filepath"
	"testing"

	"jailor/internal/ledger"
	"jailor/internal/rations"
)

func TestSweepCgroupsKeepsRunning(t *testing.T) {
	mount, err := rations.FindCgroupV2Mount()
	if err != nil {
		t.Fatalf("the privileged tier requires a cgroup v2 hierarchy: %v", err)
	}
	root := filepath.Join(mount, "jailor-test-sweep")
	if err := os.MkdirAll(filepath.Join(root, "runningjail"), 0o755); err != nil {
		t.Fatalf("the privileged tier must be able to create cgroups: %v", err)
	}
	defer os.RemoveAll(root)

	w := &Warden{}
	recs := []ledger.Record{{ID: "runningjail", State: ledger.StateRunning}}
	if n := w.SweepCgroups(recs); n != 0 {
		t.Errorf("sweep removed %d cgroups; must never remove a RUNNING jail's cgroup", n)
	}
	if _, err := os.Stat(filepath.Join(root, "runningjail")); err != nil {
		t.Error("running jail's cgroup should have been preserved")
	}
}
