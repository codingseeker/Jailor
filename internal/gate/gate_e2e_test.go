//go:build linux

package gate

import (
	"os"
	"os/exec"
	"testing"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root for network interface operations; skipping")
	}
}
func TestBridgeCreateAndDelete(t *testing.T) {
	requireRoot(t)

	name := "test-br0"
	defer deleteLink(name)

	if err := createBridge(name); err != nil {
		t.Fatalf("createBridge: %v", err)
	}
	if !linkExists(name) {
		t.Fatal("bridge not created")
	}
	if !isBridge(name) {
		t.Fatal("interface is not a bridge")
	}
	if err := linkUp(name); err != nil {
		t.Fatalf("linkUp: %v", err)
	}
	if err := deleteLink(name); err != nil {
		t.Fatalf("deleteLink: %v", err)
	}
	if linkExists(name) {
		t.Error("bridge still exists after delete")
	}
}
func TestVethPairCreateAndDelete(t *testing.T) {
	requireRoot(t)

	host := "test-vh0"
	guest := "test-vg0"
	defer deleteLink(host)
	defer deleteLink(guest)

	if err := createVethPair(host, guest); err != nil {
		t.Fatalf("createVethPair: %v", err)
	}
	if !linkExists(host) {
		t.Error("host veth not created")
	}
	if !linkExists(guest) {
		t.Error("guest veth not created")
	}
	if err := deleteLink(host); err != nil {
		t.Fatalf("deleteLink host: %v", err)
	}

	if linkExists(guest) {
		t.Error("guest veth still exists after host delete")
	}
}
func TestBridgeIdempotentCreate(t *testing.T) {
	requireRoot(t)

	name := "test-br-idem"
	defer deleteLink(name)

	if err := createBridge(name); err != nil {
		t.Fatalf("createBridge first: %v", err)
	}
	if err := createBridge(name); err != nil {
		t.Fatalf("createBridge second: %v", err)
	}
	_ = deleteLink(name)
}
func TestSetLinkMaster(t *testing.T) {
	requireRoot(t)

	bridge := "test-br-master"
	host := "test-vh-master"
	guest := "test-vg-master"
	defer func() {
		deleteLink(host)
		deleteLink(guest)
		deleteLink(bridge)
	}()

	if err := createBridge(bridge); err != nil {
		t.Fatalf("createBridge: %v", err)
	}
	if err := createVethPair(host, guest); err != nil {
		t.Fatalf("createVethPair: %v", err)
	}
	if err := setLinkMaster(host, bridge); err != nil {
		t.Fatalf("setLinkMaster: %v", err)
	}
	if !isBridgeMember(host) {
		t.Error("host veth not a bridge member after setLinkMaster")
	}
}
func TestAddAddrToInterface(t *testing.T) {
	requireRoot(t)

	bridge := "test-br-addr"
	defer deleteLink(bridge)

	if err := createBridge(bridge); err != nil {
		t.Fatalf("createBridge: %v", err)
	}
	if err := addAddrTo(bridge, "10.99.0.1/24"); err != nil {
		t.Fatalf("addAddrTo: %v", err)
	}
}
func TestSweepRemovesOrphans(t *testing.T) {
	requireRoot(t)

	bridge := "test-br-sweep"
	host := "vdeadbeef"
	guest := "veth-orphan"
	defer deleteLink(bridge)

	if err := createBridge(bridge); err != nil {
		t.Fatalf("createBridge: %v", err)
	}
	if err := createVethPair(host, guest); err != nil {
		t.Fatalf("createVethPair: %v", err)
	}
	if err := setLinkMaster(host, bridge); err != nil {
		t.Fatalf("setLinkMaster: %v", err)
	}
	removed := Sweep(map[string]bool{})
	if removed != 1 {
		t.Errorf("Sweep removed %d, want 1", removed)
	}
	if linkExists(host) {
		t.Error("orphan veth still exists after Sweep")
	}
}
func TestSweepPreservesRunning(t *testing.T) {
	requireRoot(t)

	bridge := "test-br-sweep2"
	jailID := "aabbccdd00112233"
	host := hostVethName(jailID)
	guest := "veth-running"
	defer func() {
		deleteLink(host)
		deleteLink(guest)
		deleteLink(bridge)
	}()

	if err := createBridge(bridge); err != nil {
		t.Fatalf("createBridge: %v", err)
	}
	if err := createVethPair(host, guest); err != nil {
		t.Fatalf("createVethPair: %v", err)
	}
	if err := setLinkMaster(host, bridge); err != nil {
		t.Fatalf("setLinkMaster: %v", err)
	}

	running := map[string]bool{jailID: true}
	removed := Sweep(running)
	if removed != 0 {
		t.Errorf("Sweep removed %d, want 0 (running jail)", removed)
	}
	if !linkExists(host) {
		t.Error("running veth was removed by Sweep")
	}
}
func TestTeardownRemovesVeth(t *testing.T) {
	requireRoot(t)

	bridge := "test-br-teardown"
	jailID := "aabbccdd00112233"
	host := hostVethName(jailID)
	guest := "veth-teardown"
	defer deleteLink(bridge)

	if err := createBridge(bridge); err != nil {
		t.Fatalf("createBridge: %v", err)
	}
	if err := createVethPair(host, guest); err != nil {
		t.Fatalf("createVethPair: %v", err)
	}

	g := &Gate{Mode: ModeBridge, Bridge: bridge, Subnet: DefaultSubnet, VethHost: host}
	g.Teardown(jailID)

	if linkExists(host) {
		t.Error("host veth still exists after Teardown")
	}
}
func TestTeardownAllRemovesEverything(t *testing.T) {
	requireRoot(t)

	bridge := DefaultBridge
	host := "vtestal01"
	guest := "veth-all"
	defer deleteLink(bridge)

	if err := createBridge(bridge); err != nil {
		t.Fatalf("createBridge: %v", err)
	}
	if err := createVethPair(host, guest); err != nil {
		t.Fatalf("createVethPair: %v", err)
	}
	if err := setLinkMaster(host, bridge); err != nil {
		t.Fatalf("setLinkMaster: %v", err)
	}

	TeardownAll()

	if linkExists(bridge) {
		t.Error("bridge still exists after TeardownAll")
	}
	if linkExists(host) {
		t.Error("host veth still exists after TeardownAll")
	}
}
func TestEnsureBridgeAddrIdempotent(t *testing.T) {
	requireRoot(t)

	bridge := "test-br-addr2"
	defer deleteLink(bridge)

	if err := createBridge(bridge); err != nil {
		t.Fatalf("createBridge: %v", err)
	}
	if err := ensureBridgeAddr(bridge, "10.99.0.1/24"); err != nil {
		t.Fatalf("ensureBridgeAddr first: %v", err)
	}
	if err := ensureBridgeAddr(bridge, "10.99.0.1/24"); err != nil {
		t.Fatalf("ensureBridgeAddr second: %v", err)
	}
}
func TestDefaultEgressIface(t *testing.T) {
	requireRoot(t)
	iface := defaultEgressIface()
	if iface == "" {
		t.Log("no default egress interface found (may be expected in containers)")
	} else {
		t.Logf("default egress interface: %s", iface)
	}
}
func TestIptablesRules(t *testing.T) {
	requireRoot(t)

	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables not found; skipping")
	}

	g := &Gate{Mode: ModeBridge, Bridge: "jailor0", Subnet: "10.66.0.0/24"}
	g.routeAndNAT("test")

	g.cleanupIPTables()
}
