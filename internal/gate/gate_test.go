package gate

import (
	"net"
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	g, err := New("none")
	if err != nil {
		t.Fatalf("New(none): %v", err)
	}
	if g.Mode != ModeNone {
		t.Errorf("New(none).Mode = %q", g.Mode)
	}
	if g.RequiresSetup() {
		t.Error("none mode should not require setup")
	}

	g, err = New("bridge")
	if err != nil {
		t.Fatalf("New(bridge): %v", err)
	}
	if g.Mode != ModeBridge {
		t.Errorf("New(bridge).Mode = %q", g.Mode)
	}
	if !g.RequiresSetup() {
		t.Error("bridge mode should require setup")
	}
	if g.Bridge == "" || g.Subnet == "" {
		t.Errorf("bridge gate missing defaults: %+v", g)
	}

	g, err = New("")
	if err != nil {
		t.Fatalf("New(''): %v", err)
	}
	if g.Mode != ModeNone {
		t.Errorf("New('').Mode = %q, want none", g.Mode)
	}
}

func TestNewInvalid(t *testing.T) {
	if _, err := New("bogus"); err == nil {
		t.Error("New(bogus) should error")
	}
}

func TestValidate(t *testing.T) {
	g, err := New("none")
	if err != nil {
		t.Fatalf("New(none): %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Errorf("valid gate rejected: %v", err)
	}
	var nilGate *Gate
	if err := nilGate.Validate(); err == nil {
		t.Error("nil gate should not validate")
	}
	bad := &Gate{Mode: Mode("nope")}
	if err := bad.Validate(); err == nil {
		t.Error("invalid mode should not validate")
	}
}

func TestValidateBridge(t *testing.T) {
	g, err := New("bridge")
	if err != nil {
		t.Fatalf("New(bridge): %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Errorf("valid bridge gate rejected: %v", err)
	}

	bad := &Gate{Mode: ModeBridge, Subnet: "not-a-cidr"}
	if err := bad.Validate(); err == nil {
		t.Error("bridge with invalid subnet should not validate")
	}
}

func TestParseMode(t *testing.T) {
	cases := []struct {
		in   string
		want Mode
		err  bool
	}{
		{"", ModeNone, false},
		{"none", ModeNone, false},
		{"bridge", ModeBridge, false},
		{"None", ModeNone, true},
		{"BRIDGE", ModeNone, true},
		{"host", ModeNone, true},
	}
	for _, c := range cases {
		got, err := ParseMode(c.in)
		if c.err {
			if err == nil {
				t.Errorf("ParseMode(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseMode(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseMode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAllocateSequential(t *testing.T) {
	g, err := New("bridge")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	allocMu.Lock()
	for k := range usedAddrs {
		delete(usedAddrs, k)
	}
	allocMu.Unlock()

	addrs := make(map[string]bool)
	for i := 0; i < 5; i++ {
		ip, gw, err := g.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
		if addrs[ip] {
			t.Errorf("duplicate allocation: %s", ip)
		}
		addrs[ip] = true
		if !subnetContains(g.Subnet, ip) {
			t.Errorf("allocated IP %s not in subnet %s", ip, g.Subnet)
		}
		if !subnetContains(g.Subnet, gw) {
			t.Errorf("allocated gateway %s not in subnet %s", gw, g.Subnet)
		}
		if ip == gw {
			t.Errorf("IP and gateway are the same: %s", ip)
		}
	}
	allocMu.Lock()
	var first string
	for k := range addrs {
		first = k
		break
	}
	allocMu.Unlock()
	Release(first)

	ip2, _, err := g.Allocate()
	if err != nil {
		t.Fatalf("re-Allocate: %v", err)
	}
	if addrs[ip2] && ip2 != first {
		t.Errorf("re-allocated non-released address %s", ip2)
	}
}

func TestAllocateExhaustion(t *testing.T) {
	g, err := New("bridge")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	allocMu.Lock()
	for k := range usedAddrs {
		delete(usedAddrs, k)
	}
	allocMu.Unlock()

	for i := 0; i < 253; i++ {
		_, _, err := g.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d unexpected error: %v", i, err)
		}
	}
	_, _, err = g.Allocate()
	if err == nil {
		t.Error("expected exhaustion error, got nil")
	}
}

func TestAllocateConcurrency(t *testing.T) {
	g, err := New("bridge")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	allocMu.Lock()
	for k := range usedAddrs {
		delete(usedAddrs, k)
	}
	allocMu.Unlock()

	const goroutines = 20
	type result struct {
		ip  string
		err error
	}
	results := make(chan result, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ip, _, err := g.Allocate()
			results <- result{ip, err}
		}()
	}
	wg.Wait()
	close(results)

	seen := make(map[string]bool)
	for r := range results {
		if r.err != nil {
			t.Errorf("concurrent Allocate: %v", r.err)
			continue
		}
		if seen[r.ip] {
			t.Errorf("concurrent duplicate allocation: %s", r.ip)
		}
		seen[r.ip] = true
	}
	if len(seen) != goroutines {
		t.Errorf("expected %d unique allocations, got %d", goroutines, len(seen))
	}
}

func TestRelease(t *testing.T) {
	Release("10.66.0.2/24")
	Release("")
}

func TestHostVethName(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{"aabbccdd00112233", "v00112233"},
		{"abc", "vabc"},
		{"12345678", "v12345678"},
		{"1234567890123456", "v90123456"},
	}
	for _, c := range cases {
		got := hostVethName(c.id)
		if got != c.want {
			t.Errorf("hostVethName(%q) = %q, want %q", c.id, got, c.want)
		}
		if len(got) > 15 {
			t.Errorf("hostVethName(%q) = %q exceeds IFNAMSIZ(15)", c.id, got)
		}
	}
}

func TestBaseIP(t *testing.T) {
	g, err := New("bridge")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	base := g.BaseIP()
	if base == nil {
		t.Fatal("BaseIP() returned nil")
	}
	if !base.Equal(net.ParseIP("10.66.0.0")) {
		t.Errorf("BaseIP() = %s, want 10.66.0.0", base)
	}
}

func TestGatewayOf(t *testing.T) {
	gw := gatewayOf("10.66.0.1/24")
	if gw == nil {
		t.Fatal("gatewayOf returned nil")
	}
	if !gw.Equal(net.ParseIP("10.66.0.1")) {
		t.Errorf("gatewayOf = %s, want 10.66.0.1", gw)
	}
}

func TestNetPrefix(t *testing.T) {
	if got := netPrefix("10.66.0.0/24"); got != 24 {
		t.Errorf("netPrefix(/24) = %d, want 24", got)
	}
	if got := netPrefix("10.66.0.0/16"); got != 16 {
		t.Errorf("netPrefix(/16) = %d, want 16", got)
	}
	if got := netPrefix("invalid"); got != 24 {
		t.Errorf("netPrefix(invalid) = %d, want 24 (default)", got)
	}
}

func TestSortedHosts(t *testing.T) {
	hosts := sortedHosts("10.66.0.0")
	if len(hosts) != 254 {
		t.Errorf("sortedHosts returned %d hosts, want 254", len(hosts))
	}
	for _, h := range hosts {
		if net.ParseIP(h) == nil {
			t.Errorf("sortedHosts returned invalid IP: %s", h)
		}
	}

	for i := 1; i < len(hosts); i++ {
		if hosts[i] <= hosts[i-1] {
			t.Errorf("sortedHosts not sorted: %s <= %s", hosts[i], hosts[i-1])
		}
	}
}

func subnetContains(cidr, addr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(addr)
	if ip == nil {

		ip, _, err = net.ParseCIDR(addr)
		if err != nil {
			return false
		}
	}
	return network.Contains(ip)
}

func TestRequiresSetup(t *testing.T) {
	g, _ := New("none")
	if g.RequiresSetup() {
		t.Error("none should not require setup")
	}
	g, _ = New("bridge")
	if !g.RequiresSetup() {
		t.Error("bridge should require setup")
	}
	var nilGate *Gate
	if nilGate.RequiresSetup() {
		t.Error("nil gate should not require setup")
	}
}

func TestAssignManaged(t *testing.T) {
	g, _ := New("bridge")
	if err := g.Assign("10.9.0.8/24", "10.9.0.1/24"); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if !g.Managed {
		t.Error("Assign should mark the gate managed")
	}
	if g.IP != "10.9.0.8/24" || g.Gateway != "10.9.0.1/24" {
		t.Errorf("Assign set wrong fields: %+v", g)
	}
	g2, _ := New("bridge")
	if err := g2.Assign("10.7.0.1/24", "10.7.0.1/24"); err == nil {
		t.Error("IP equal to gateway should be rejected")
	}
}

func TestPortsValidate(t *testing.T) {
	g, _ := New("bridge")
	g.Ports = []Port{{Host: 8080, Guest: 80}}
	if err := g.Validate(); err != nil {
		t.Errorf("valid ports rejected: %v", err)
	}
	g.Ports = []Port{{Host: 0, Guest: 80}}
	if err := g.Validate(); err == nil {
		t.Error("host port 0 should be rejected")
	}
	g.Ports = []Port{{Host: 8080, Guest: 70000}}
	if err := g.Validate(); err == nil {
		t.Error("guest port 70000 should be rejected")
	}
	g2, _ := New("none")
	g2.Ports = []Port{{Host: 1, Guest: 1}}
	if err := g2.Validate(); err != nil {
		t.Errorf("ports on none gate rejected: %v", err)
	}
}

func TestTeardownNilSafe(t *testing.T) {
	var g *Gate
	g.Teardown("any-id")
}

func TestDefaultConstants(t *testing.T) {
	if DefaultBridge != "jailor0" {
		t.Errorf("DefaultBridge = %q, want jailor0", DefaultBridge)
	}
	if DefaultSubnet != "10.66.0.0/24" {
		t.Errorf("DefaultSubnet = %q, want 10.66.0.0/24", DefaultSubnet)
	}
	if GuestVethName != "eth0" {
		t.Errorf("GuestVethName = %q, want eth0", GuestVethName)
	}
}

func TestShort(t *testing.T) {
	if got := short("abcdef"); got != "cdef" {
		t.Errorf("short(abcdef) = %q, want cdef", got)
	}
	if got := short("ab"); got != "ab" {
		t.Errorf("short(ab) = %q, want ab (too short)", got)
	}
}
