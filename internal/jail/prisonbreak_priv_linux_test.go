//go:build linux && jailor_priv

package jail

import (
	"strings"
	"testing"

	"jailor/internal/bars"
)

func TestNamespaceLeakage(t *testing.T) {
	out, code := runJail(t, []bars.Kind{bars.PID, bars.UTS, bars.Mount}, true, "proc1", "jail-hostname")
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)
	if m["proc1_pid"] != "1" {
		t.Errorf("Prisoner should be PID 1 in its PID namespace, got %s", m["proc1_pid"])
	}
	if m["proc1_name"] == "" {
		t.Errorf("missing /proc/1 status, output: %s", out)
	}

	hout, _ := runJail(t, []bars.Kind{bars.UTS, bars.Mount}, true, "hostname", "jail-hostname")
	mh := parseKV(hout)
	if mh["hostname"] != "jail-hostname" {
		t.Errorf("Jail hostname = %q, want jail-hostname", mh["hostname"])
	}
}

func TestNetworkBarIsolates(t *testing.T) {
	out, code := runJail(t, []bars.Kind{bars.PID, bars.UTS, bars.Mount, bars.Network}, true, "net", "")
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	m := parseKV(out)
	if m["net"] == "" {
		t.Fatalf("no net probe output: %s", out)
	}
	for _, iface := range strings.Split(m["net"], ",") {
		if iface == "lo" {
			continue
		}
		if strings.HasPrefix(iface, "veth") || strings.HasPrefix(iface, "eth") ||
			strings.HasPrefix(iface, "br") || iface == "docker0" {
			t.Errorf("network leakage: Jail sees host interface %q in its namespace", iface)
		}
	}
}
