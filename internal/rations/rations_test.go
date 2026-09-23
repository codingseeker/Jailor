package rations

import (
	"os"
	"testing"
)

func TestParseMemory(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		err  bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"1024", 1024, false},
		{"512K", 512 * 1024, false},
		{"256M", 256 * 1024 * 1024, false},
		{"1G", 1 << 30, false},
		{"2g", 2 << 30, false},
		{" 64M ", 64 * 1024 * 1024, false},
		{"abc", 0, true},
		{"-5M", 0, true},
		{"1.5G", 0, true},
	}
	for _, c := range cases {
		got, err := ParseMemory(c.in)
		if c.err {
			if err == nil {
				t.Errorf("ParseMemory(%q) = %d, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseMemory(%q) unexpectedly failed: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseMemory(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		b    int64
		want string
	}{
		{-1, "unlimited"},
		{0, "0 B"},
		{512, "512 B"},
		{2048, "2.0 KiB"},
		{64 * 1024 * 1024, "64.00 MiB"},
		{1 << 30, "1.00 GiB"},
	}
	for _, c := range cases {
		if got := HumanBytes(c.b); got != c.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", c.b, got, c.want)
		}
	}
}

func TestCgroupRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create cgroups; skipping")
	}
	mount, err := FindCgroupV2Mount()
	if err != nil {
		t.Skipf("no cgroup v2 hierarchy: %v", err)
	}
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
