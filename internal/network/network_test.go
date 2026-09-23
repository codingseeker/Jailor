package network

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "ledger")
}

func openManager(t *testing.T) *Manager {
	t.Helper()
	m, err := Open(testDir(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return m
}

func TestValidName(t *testing.T) {
	cases := map[string]bool{
		"bridge":                true,
		"mynet":                 true,
		"a_b-c.d":               true,
		"none":                  false,
		"":                      false,
		"-net":                  false,
		".net":                  false,
		"Uppercase":             false,
		"with space":            false,
		strings.Repeat("x", 41): false,
	}
	for in, want := range cases {
		if got := ValidName(in); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCreateAndGet(t *testing.T) {
	m := openManager(t)
	n, err := m.Create("web", "10.71.0.0/24", "", "", []string{"1.1.1.1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n.Name != "web" || n.Subnet != "10.71.0.0/24" {
		t.Errorf("Create populated wrong: %+v", n)
	}
	if n.Gateway != "10.71.0.1" {
		t.Errorf("default gateway = %q, want 10.71.0.1", n.Gateway)
	}
	if n.Bridge != "jailor-web" {
		t.Errorf("bridge = %q, want jailor-web", n.Bridge)
	}
	if len(n.DNS) != 1 || n.DNS[0] != "1.1.1.1" {
		t.Errorf("dns = %v", n.DNS)
	}

	got, err := m.Get("web")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != n.ID || got.CreatedAt.IsZero() {
		t.Errorf("Get did not round-trip: %+v", got)
	}

	m2, err := Open(m.Root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := m2.Get("web"); err != nil {
		t.Errorf("network lost after reopen: %v", err)
	}
}

func TestCreateRejectsDuplicatesAndBadNames(t *testing.T) {
	m := openManager(t)
	if _, err := m.Create("web", "", "", "", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.Create("web", "10.9.0.0/24", "", "", nil); !strings.Contains(err.Error(), "already exists") {
		t.Errorf("duplicate create err = %v", err)
	}
	if _, err := m.Create("Bad", "", "", "", nil); err == nil {
		t.Error("uppercase name should be rejected")
	}
	if _, err := m.Create("none", "", "", "", nil); err == nil {
		t.Error("'none' name should be rejected")
	}
}

func TestCreateValidatesSubnets(t *testing.T) {
	m := openManager(t)
	for i, c := range []struct {
		subnet, gateway, ipv6 string
		want                  string
	}{
		{"not-a-cidr", "", "", "invalid subnet"},
		{"fd00::/120", "", "", "not IPv4"},
		{"10.1.0.0/31", "", "", "no usable host"},
		{"10.1.0.0/8", "", "", "too large"},
		{"10.2.0.0/24", "10.99.0.1", "", "not within"},
		{"10.3.0.0/24", "10.3.0.1", "bogus", "invalid IPv6"},
		{"10.4.0.0/24", "", "fd00::/64", ""},
	} {
		_, err := m.Create(fmt.Sprintf("net%d", i), c.subnet, c.gateway, c.ipv6, nil)
		if c.want == "" && err != nil {
			t.Errorf("Create(%s) unexpected error: %v", c.subnet, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("Create(%s) err = %v, want containing %q", c.subnet, err, c.want)
		}
	}
}

func TestIPAMAllocateRelease(t *testing.T) {
	m := openManager(t)
	if _, err := m.Create("net0", "10.66.0.0/24", "", "", nil); err != nil {
		t.Fatal(err)
	}

	ip, err := m.Allocate("net0")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if ip != "10.66.0.2" {
		t.Errorf("first allocation = %s, want 10.66.0.2", ip)
	}
	ip2, err := m.Allocate("net0")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if ip2 != "10.66.0.3" {
		t.Errorf("second allocation = %s, want 10.66.0.3", ip2)
	}

	allocs, err := m.Allocations("net0")
	if err != nil {
		t.Fatal(err)
	}
	if len(allocs) != 2 {
		t.Fatalf("Allocations = %v", allocs)
	}

	if err := m.Release("net0", ip); err != nil {
		t.Fatalf("Release: %v", err)
	}
	allocs, _ = m.Allocations("net0")
	if len(allocs) != 1 {
		t.Errorf("after release Allocations = %v, want 1", allocs)
	}

	ip3, err := m.Allocate("net0")
	if err != nil {
		t.Fatalf("re-Allocate: %v", err)
	}
	if ip3 != "10.66.0.2" {
		t.Errorf("released address not reused, got %s", ip3)
	}
}

func TestIPAMNoCollisionAcrossInstances(t *testing.T) {
	m := openManager(t)
	if _, err := m.Create("net0", "10.5.0.0/24", "", "", nil); err != nil {
		t.Fatal(err)
	}

	m2, err := Open(m.Root)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[string]bool{}
	var wg sync.WaitGroup
	var firstErr error
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(which int) {
			defer wg.Done()
			mm := m
			if which%2 == 0 {
				mm = m2
			}
			for j := 0; j < 10; j++ {
				ip, err := mm.Allocate("net0")
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
				mu.Lock()
				if seen[ip] {
					mu.Unlock()
					firstErr = fmt.Errorf("collision: %s", ip)
					return
				}
				seen[ip] = true
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("IPAM collision/concurrency: %v", firstErr)
	}
	if got := len(seen); got != 80 {
		t.Fatalf("allocated %d distinct addresses, want 80", got)
	}
}

func TestIPAMExhaustion(t *testing.T) {
	m := openManager(t)
	if _, err := m.Create("tiny", "10.5.0.0/30", "", "", nil); err != nil {
		t.Fatal(err)
	}

	ip, err := m.Allocate("tiny")
	if err != nil || ip != "10.5.0.2" {
		t.Fatalf("first Allocate = %q, %v", ip, err)
	}
	if _, err := m.Allocate("tiny"); err == nil {
		t.Error("exhausted network should error")
	} else if !strings.Contains(err.Error(), "exhausted") {
		t.Errorf("err = %v", err)
	}
}

func TestAllocateOnMissingNetwork(t *testing.T) {
	m := openManager(t)
	if _, err := m.Allocate("nope"); err == nil {
		t.Error("allocating on a missing network should error")
	}
}

func TestDefaultNetwork(t *testing.T) {
	m := openManager(t)
	n, err := m.Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if n.Name != DefaultName || n.Subnet != DefaultSubnet || n.Bridge != DefaultBridge {
		t.Errorf("default network = %+v", n)
	}
	if _, err := m.Default(); err != nil {
		t.Errorf("Default twice: %v", err)
	}
	all := m.Networks()
	if len(all) != 1 {
		t.Errorf("Networks() = %d entries, want 1", len(all))
	}
}

func TestDefaultBridgeEgress(t *testing.T) {

	m := openManager(t)
	d, _ := m.Default()
	if d.Bridge != "jailor0" {
		t.Fatalf("default bridge = %q", d.Bridge)
	}
	for _, name := range []string{"one", "two"} {
		if _, err := m.Create(name, "10.6.0.0/24", "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	one, _ := m.Get("one")
	two, _ := m.Get("two")
	if one.Bridge == two.Bridge {
		t.Errorf("two networks share bridge %q; they must be isolated", one.Bridge)
	}
	if len(one.Bridge) > 15 || len(two.Bridge) > 15 {
		t.Errorf("bridge names exceed the 15-char IFNAMSIZ limit: %q %q", one.Bridge, two.Bridge)
	}
}

func TestListAndRemove(t *testing.T) {
	m := openManager(t)
	for _, name := range []string{"zeb", "alpha", "mid"} {
		if _, err := m.Create(name, "", "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	all, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].Name != "alpha" || all[2].Name != "zeb" {
		t.Errorf("List = %v", all)
	}

	ip, err := m.Allocate("alpha")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Remove("alpha"); err == nil {
		t.Error("removing a network with allocations should fail")
	}
	if err := m.Release("alpha", ip); err != nil {
		t.Fatal(err)
	}
	if err := m.Remove("alpha"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := m.Get("alpha"); err == nil {
		t.Error("removed network should be gone")
	}
	if err := m.Remove(DefaultName); err == nil {
		t.Error("removing the default network should fail")
	}
}

func TestBridgeCollisionRejected(t *testing.T) {
	m := openManager(t)

	if _, err := m.Create(strings.Repeat("verylong", 4), "", "", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(strings.Repeat("verylongprefixsame", 4), "", "", "", nil); err == nil {
		t.Error("colliding bridge device should be rejected")
	}
}

func TestCIDR(t *testing.T) {
	m := openManager(t)
	if _, err := m.Create("c", "10.80.0.0/24", "", "", nil); err != nil {
		t.Fatal(err)
	}
	n, _ := m.Get("c")
	if got := n.CIDR("10.80.0.9"); got != "10.80.0.9/24" {
		t.Errorf("CIDR = %q", got)
	}
}
