//go:build linux && jailor_priv

package rations

import "testing"

func TestCgroupRoundTrip(t *testing.T) {
	mount, err := FindCgroupV2Mount()
	jailID := "test-cgroup-roundtrip"
	cg, err := Create(mount, jailID, Rations{MemoryLimitBytes: 512 * 1024 * 1024, PIDsLimit: 5})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer cg.Remove()

	st, err := cg.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.MemoryMax != 512*1024*1024 {
		t.Errorf("MemoryMax = %d, want %d", st.MemoryMax, 512*1024*1024)
	}
	if st.PIDsMax != 5 {
		t.Errorf("PIDsMax = %d, want 5", st.PIDsMax)
	}
	if st.MemoryCurrent < 0 || st.CPUUsageUsec < 0 || st.PIDsCurrent != 0 {
		t.Errorf("unexpected counters: %+v", st)
	}
}
