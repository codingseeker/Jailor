//go:build linux

package jail

import (
	"reflect"
	"sort"
	"testing"
)

const seccompRetActionMask = 0xffff0000

func TestDenyFilterShape(t *testing.T) {
	prog := buildDenyFilter(defaultDeniedSyscalls())
	if len(prog) < 3 {
		t.Fatalf("filter too short: %d", len(prog))
	}

	ld := prog[0]
	if ld.K != seccompDataNR {
		t.Fatalf("first instruction must load seccomp data nr, got K=%d", ld.K)
	}

	var jeq []uint32
	for _, f := range prog[1 : len(prog)-2] {
		if f.Code != bpfClassJMP|bpfJEQ|bpfK {
			t.Fatalf("expected JEQ instruction, got code %d", f.Code)
		}
		jeq = append(jeq, f.K)
	}
	sort.Slice(jeq, func(i, j int) bool { return jeq[i] < jeq[j] })

	var want []uint32
	for _, n := range defaultDeniedSyscalls() {
		want = append(want, uint32(n))
	}
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if !reflect.DeepEqual(jeq, want) {
		t.Errorf("JEQ set mismatch:\n got %v\nwant %v", jeq, want)
	}

	allow := prog[len(prog)-2]
	errno := prog[len(prog)-1]
	if allow.Code != bpfClassRET|bpfRETK || allow.K != seccompRetAllow {
		t.Errorf("expected RET ALLOW as penultimate instruction, got code=%d K=%d", allow.Code, allow.K)
	}
	if errno.Code != bpfClassRET|bpfRETK || errno.K&seccompRetActionMask != seccompRetErrno {
		t.Errorf("expected RET ERRNO as final instruction, got code=%d K=%d", errno.Code, errno.K)
	}

	for i, f := range prog[1 : len(prog)-2] {
		k := i + 1
		if int(f.Jt)+k+1 != len(prog)-1 {
			t.Errorf("JEQ at %d jumps to %d, want %d", k, int(f.Jt)+k+1, len(prog)-1)
		}
	}
}
