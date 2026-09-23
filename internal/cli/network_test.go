package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"jailor/internal/network"
)

func TestNetworkCreateListInspectRemove(t *testing.T) {
	ledgerDir := filepath.Join(t.TempDir(), "ledger")

	out, code := runCLI(t, ledgerDir, "network", "create",
		"--subnet", "10.66.1.0/24", "--gateway", "10.66.1.1", "--dns", "1.1.1.1,8.8.8.8", "backbone")
	if code != 0 {
		t.Fatalf("network create code = %d, out=%s", code, out)
	}
	id := strings.TrimSpace(out)
	if id == "" {
		t.Fatal("network create printed no id")
	}

	ls, lcode := runCLI(t, ledgerDir, "network", "ls")
	if lcode != 0 {
		t.Fatalf("network ls code = %d, out=%s", lcode, ls)
	}
	if !strings.Contains(ls, "backbone") || !strings.Contains(ls, "10.66.1.0/24") || !strings.Contains(ls, "10.66.1.1") {
		t.Errorf("ls missing backbone network:\n%s", ls)
	}

	ins, icode := runCLI(t, ledgerDir, "network", "inspect", "backbone")
	if icode != 0 {
		t.Fatalf("network inspect code = %d, out=%s", icode, ins)
	}
	for _, want := range []string{"10.66.1.0/24", "10.66.1.1", "1.1.1.1", "8.8.8.8", "Allocated   0"} {
		if !strings.Contains(ins, want) {
			t.Errorf("inspect missing %q:\n%s", want, ins)
		}
	}

	nm, err := network.Open(ledgerDir)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := nm.Allocate("backbone")
	if err != nil {
		t.Fatal(err)
	}
	ins2, icode := runCLI(t, ledgerDir, "network", "inspect", "backbone")
	if icode != 0 {
		t.Fatalf("second inspect code = %d", icode)
	}
	if !strings.Contains(ins2, "Allocated   1") || !strings.Contains(ins2, addr) {
		t.Errorf("inspect should show the delegated address %s:\n%s", addr, ins2)
	}

	_, rcode := runCLI(t, ledgerDir, "network", "rm", "backbone")
	if rcode == 0 {
		t.Error("rm should refuse while an address is still allocated")
	}

	if err := nm.Release("backbone", addr); err != nil {
		t.Fatal(err)
	}
	rm, rcode := runCLI(t, ledgerDir, "network", "rm", "backbone")
	if rcode != 0 {
		t.Fatalf("rm code = %d, out=%s", rcode, rm)
	}
	ls2, _ := runCLI(t, ledgerDir, "network", "ls")
	if strings.Contains(ls2, "backbone") {
		t.Errorf("removed network still listed:\n%s", ls2)
	}
}
func TestNetworkDuplicateAndDefaultPrevented(t *testing.T) {
	ledgerDir := filepath.Join(t.TempDir(), "ledger")

	if out, code := runCLI(t, ledgerDir, "network", "create", "net1"); code != 0 {
		t.Fatalf("create net1 code = %d, out=%s", code, out)
	}
	if _, code := runCLI(t, ledgerDir, "network", "create", "net1"); code == 0 {
		t.Error("duplicate network create should fail")
	}
	if _, code := runCLI(t, ledgerDir, "network", "create", "none"); code == 0 {
		t.Error("reserved name 'none' should be rejected")
	}
	if _, code := runCLI(t, ledgerDir, "network", "rm", "bridge"); code == 0 {
		t.Error("removing the default network should fail")
	}
	if _, code := runCLI(t, ledgerDir, "network", "inspect", "nope"); code == 0 {
		t.Error("inspect of an unknown network should fail")
	}
}
