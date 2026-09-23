package cli

import (
	"bytes"
	"testing"

	"jailor/internal/bars"
	"jailor/internal/config"
)

func TestConfigOptions(t *testing.T) {
	c := config.Default()
	c.Command = []string{"/bin/echo", "hi"}
	c.Bars.Namespaces = []string{"pid", "uts"}
	c.Gate.Mode = "none"
	c.Cell.Rootfs = ""
	c.Rations.CPUs = 2
	o, err := configOptions(&c)
	if err != nil {
		t.Fatalf("configOptions: %v", err)
	}
	if o.Config == nil {
		t.Error("options should carry the resolved config")
	}
	if len(o.Args) != 2 {
		t.Errorf("args = %v", o.Args)
	}
	if !containsBar(o.Bars, bars.PID) || !containsBar(o.Bars, bars.UTS) {
		t.Errorf("bars = %v", o.Bars)
	}
	if o.CPUs != 2 {
		t.Errorf("cpus = %v", o.CPUs)
	}
}

func containsBar(have []bars.Kind, want bars.Kind) bool {
	for _, k := range have {
		if k == want {
			return true
		}
	}
	return false
}

func TestChangedFlags(t *testing.T) {
	fs := flagSet("test", &bytes.Buffer{})
	fs.String("network", "none", "")
	fs.String("hostname", "", "")
	fs.Bool("seccomp", false, "")
	if err := fs.Parse([]string{"--network", "bridge", "--seccomp"}); err != nil {
		t.Fatal(err)
	}
	set := changedFlags(fs)
	if !set["network"] {
		t.Error("network should be marked set")
	}
	if !set["seccomp"] {
		t.Error("seccomp should be marked set")
	}
	if set["hostname"] {
		t.Error("hostname should not be marked set")
	}
}
