package idmap

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestBuildMappings(t *testing.T) {
	uid, gid, err := BuildMappings(1000, 1000,
		[]Range{{Start: 524288, Size: 65536}},
		[]Range{{Start: 524288, Size: 65536}})
	if err != nil {
		t.Fatalf("BuildMappings = %v", err)
	}
	wantUID := []MapLine{
		{ContainerID: 0, HostID: 1000, Size: 1},
		{ContainerID: 1, HostID: 524288, Size: 65536},
	}
	wantGID := []MapLine{
		{ContainerID: 0, HostID: 1000, Size: 1},
		{ContainerID: 1, HostID: 524288, Size: 65536},
	}
	assertLines(t, "uid", uid, wantUID)
	assertLines(t, "gid", gid, wantGID)
	if got := MapsToString(uid); len(got) != 2 || got[0] != "0->1000,1" || got[1] != "1->524288,65536" {
		t.Errorf("MapsToString(uid) = %v, want ['0->1000,1' '1->524288,65536']", got)
	}
}

func TestBuildMappings_multiRange(t *testing.T) {
	uid, gid, err := BuildMappings(1000, 1000,
		[]Range{{Start: 100000, Size: 1000}, {Start: 200000, Size: 2000}},
		[]Range{{Start: 100000, Size: 1000}})
	if err != nil {
		t.Fatalf("BuildMappings = %v", err)
	}
	want := []MapLine{
		{ContainerID: 0, HostID: 1000, Size: 1},
		{ContainerID: 1, HostID: 100000, Size: 1000},
		{ContainerID: 1001, HostID: 200000, Size: 2000},
	}
	assertLines(t, "uid", uid, want)
	if got := gid[1].ContainerID; got != 1 {
		t.Errorf("gid second map container base = %d, want 1", got)
	}
}
func TestBuildMappings_noSubordinate(t *testing.T) {
	uid, gid, err := BuildMappings(1000, 1000, nil, nil)
	if err != nil {
		t.Fatalf("BuildMappings(nil) = %v", err)
	}
	if len(uid) != 1 || len(gid) != 1 || uid[0].HostID != 1000 {
		t.Fatalf("BuildMappings(nil) = %v, want single identity line each", uid)
	}
}
func TestToProcLines(t *testing.T) {
	got := ToProcLines([]MapLine{{ContainerID: 0, HostID: 0, Size: 1}, {ContainerID: 1, HostID: 524288, Size: 65536}})
	if len(got) != 2 {
		t.Fatalf("ToProcLines len = %d, want 2", len(got))
	}
	want := []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: 0, Size: 1},
		{ContainerID: 1, HostID: 524288, Size: 65536},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ToProcLines[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestWriteMaps_missingHelper(t *testing.T) {
	old := os.Getenv("PATH")
	t.Cleanup(func() { t.Setenv("PATH", old) })
	t.Setenv("PATH", t.TempDir())
	err := WriteMaps(1, []MapLine{{ContainerID: 0, HostID: 1000, Size: 1}}, []MapLine{{ContainerID: 0, HostID: 1000, Size: 1}})
	if err == nil {
		t.Fatal("WriteMaps with no helper should error")
	}
	if !strings.Contains(err.Error(), "newuidmap") {
		t.Errorf("error should name the missing helper: %v", err)
	}
	if !IsUnavailable(err) {
		t.Errorf("error should be an *Unavailable: %v", err)
	}
}

func assertLines(t *testing.T, name string, got, want []MapLine) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %+v, want %+v", name, i, got[i], want[i])
		}
	}
}
