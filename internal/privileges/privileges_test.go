package privileges

import "testing"

func TestValidCapability(t *testing.T) {
	for _, name := range []string{
		"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN",
		"CAP_CHECKPOINT_RESTORE", "CAP_BPF",
	} {
		if !ValidCapability(name) {
			t.Errorf("expected %s to be a valid capability", name)
		}
	}
	for _, name := range []string{"", "CHOWN", "CAP_NOT_A_REAL_CAP", "CAP_"} {
		if ValidCapability(name) {
			t.Errorf("expected %q to be rejected", name)
		}
	}
}

func TestValidateFailClosed(t *testing.T) {

	p := &Privileges{Capabilities: []string{"CAP_CHOWN", "CAP_BOGUS"}}
	if err := p.Validate(); err == nil {
		t.Fatal("expected unknown capability to fail validation")
	}
	ok := &Privileges{Capabilities: []string{"CAP_CHOWN", "CAP_SETUID"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid capabilities rejected: %v", err)
	}
}

func TestNormalizeCapabilities(t *testing.T) {
	out, err := NormalizeCapabilities([]string{"CAP_CHOWN", "cap_setuid"})
	if err == nil {
		t.Fatalf("expected lowercase capability to be rejected, got %v", out)
	}
	out, err = NormalizeCapabilities([]string{"CAP_CHOWN", "CAP_CHOWN", "CAP_KILL"})
	if err != nil {
		t.Fatalf("valid caps rejected: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("duplicate not deduplicated: %v", out)
	}
}
