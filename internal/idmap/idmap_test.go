package idmap

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestParseFileBytes_strictValid(t *testing.T) {
	const fixture = `# subordinate file fixture
alice:100000:65536
alice:200000:1000
bob:300000:65536
carol:0:0

# trailing comment-only region stays ignored
`
	m, err := ParseFileBytes("fixture/subuid", []byte(fixture))
	if err != nil {
		t.Fatalf("ParseFileBytes(fixture) = %v, want nil", err)
	}
	if len(m) != 4 {
		t.Fatalf("ParseFileBytes(fixture) = %d mappings, want 4 (alice x2, bob, carol-empty)", len(m))
	}
	if m[0].User != "alice" || m[0].Range.Start != 100000 || m[0].Range.Size != 65536 {
		t.Errorf("m[0] = %+v, want alice 100000/65536", m[0])
	}
	if m[1].Range.Start != 200000 || m[1].Range.Size != 1000 {
		t.Errorf("m[1] = %+v, want alice second range 200000/1000", m[1])
	}
	if m[3].Range.Start != 0 || m[3].Range.Size != 0 {
		t.Errorf("m[3] = %+v, want the empty carol range preserved at parse level", m[3])
	}
}

func TestParseFileBytes_strictValidNoio(t *testing.T) {
	const fixture = "\n\n# leading junk\n\n\nalice:100000:65536\n\n# trailing\n\n"
	m, err := ParseFileBytes("f", []byte(fixture))
	if err != nil {
		t.Fatalf("ParseFileBytes = %v", err)
	}
	if len(m) != 1 || m[0].User != "alice" {
		t.Errorf("ParseFileBytes(blank/comment-heavy) = %v, want single alice mapping", m)
	}
}
func TestRangesFor_multimap(t *testing.T) {
	m, err := ParseFileBytes("f", []byte("alice:100000:65536\nalice:200000:1000\nbob:300000:65536\ncarol:0:0\n"))
	if err != nil {
		t.Fatalf("ParseFileBytes = %v", err)
	}
	alice := RangesFor(m, "alice")
	if len(alice) != 2 || alice[0].Start != 100000 || alice[1].Start != 200000 {
		t.Fatalf("RangesFor(alice) = %v, want the two alice ranges in file order", alice)
	}
	if r := PrimaryRange(m, "alice"); r == nil || r.Start != 100000 {
		t.Errorf("PrimaryRange(alice) = %v, want 100000/65536", r)
	}
	if rs := RangesFor(m, "carol"); len(rs) != 0 {
		t.Errorf("RangesFor(carol) = %v, want empty (empty range is not usable)", rs)
	}
	if rs := RangesFor(m, "nobody"); len(rs) != 0 {
		t.Errorf("RangesFor(nobody) = %v, want empty", rs)
	}
}
func TestParseFileBytes_malformed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"twofield", "alice:100000\n"},
		{"extrafield", "alice:100000:65536:x\n"},
		{"badstart", "alice:ten:65536\n"},
		{"badsize", "alice:100000:many\n"},
		{"bare", "carol:\n"},
		{"negativesize", "alice:100000:-5\n"},
		{"negativestart", "alice:-5:65536\n"},
		{"overflow", "alice:2000000000:3000000000\n"},
	}
	for _, c := range cases {
		if _, err := ParseFileBytes("f", []byte(c.data)); err == nil {
			t.Errorf("ParseFileBytes(%q) = nil error, want error for %s", c.data, c.name)
		}
	}
}

func TestUnavailableError(t *testing.T) {
	m, err := ParseFileBytes("f", []byte("alice:100000:65536\n"))
	if err != nil {
		t.Fatalf("ParseFileBytes = %v", err)
	}
	if rs := RangesFor(m, "dave"); len(rs) != 0 {
		t.Fatalf("RangesFor(dave) = %v, want empty", rs)
	}
	u := &Unavailable{File: SubUID, User: "dave", Why: "probe"}
	if !IsUnavailable(u) {
		t.Fatal("IsUnavailable(*Unavailable) = false, want true")
	}
	if got := u.Error(); !strings.Contains(got, "dave") || !strings.Contains(got, "subuid") {
		t.Errorf("Unavailable.Error() = %q, want to name user dave and file subuid", got)
	}
}

func TestParseFile_disjointOrder(t *testing.T) {
	m, err := ParseFileBytes("f", []byte("alice:500000:100\nalice:100000:65536\n"))
	if err != nil {
		t.Fatalf("ParseFileBytes = %v", err)
	}
	rs := RangesFor(m, "alice")
	if len(rs) != 2 || rs[0].Start != 500000 || rs[1].Start != 100000 {
		t.Fatalf("RangesFor(alice) = %v, want file order 500000 then 100000", rs)
	}
}
func TestRangeBounds(t *testing.T) {
	r := Range{Start: 100000, Size: 65536}
	if !r.Contains(100000) || !r.Contains(165535) || r.Contains(165536) || r.Contains(99999) {
		t.Errorf("Range.Contains bounds wrong for %v", r)
	}
	if r.After() != 165536 {
		t.Errorf("Range.After() = %d, want 165536", r.After())
	}
	if got := r.String(); got != "100000-165535" {
		t.Errorf("Range.String() = %q, want 100000-165535", got)
	}
}
func TestParseFromRealSubuid(t *testing.T) {
	f, err := os.Open("/etc/subuid")
	if err != nil {
		t.Skip("host has no /etc/subuid; skipping host-file check")
	}
	defer f.Close()
	m, err := ParseFile(f)
	if err != nil {
		t.Fatalf("ParseFile(/etc/subuid) = %v", err)
	}
	if len(m) == 0 {
		t.Skip("host /etc/subuid is empty")
	}
	for _, mp := range m {
		if mp.Range.Size == 0 {
			continue
		}
		_ = strings.TrimSpace(mp.User)
	}
}

var _ = bufio.NewReader
var _ bytes.Buffer
var _ = strconv.Itoa
