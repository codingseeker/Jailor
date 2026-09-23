package cli

import (
	"flag"
	"fmt"
	"strings"

	"jailor/internal/bars"
	"jailor/internal/config"
	"jailor/internal/rations"
	"jailor/internal/warden"
)

func changedFlags(fs *flag.FlagSet) map[string]bool {
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

func opt(set map[string]bool, name string, apply func()) {
	if set[name] {
		apply()
	}
}

func loadConfig(r *Root, path string) (*config.Config, error) {
	if r == nil {
		r = New()
	}
	if path == "" {
		return nil, nil
	}
	return config.Load(path)
}

func configOptions(base *config.Config) (warden.Options, error) {
	if base == nil {
		return warden.Options{}, nil
	}
	var o warden.Options
	o.Args = append([]string(nil), base.Command...)
	o.Rootfs = base.Cell.Rootfs
	o.Image = base.Cell.Image
	o.WorkDir = base.Cell.WorkDir
	o.ReadOnly = base.Cell.ReadOnly
	o.Hostname = base.Cell.Hostname
	o.Userns = base.UsernsPolicy()
	o.Network = base.Gate.Mode
	o.Ports = append([]string(nil), base.Gate.Ports...)
	o.DNS = append([]string(nil), base.Gate.DNS...)
	o.Seccomp = base.Privileges.Seccomp
	o.NoNewPrivs = base.Privileges.NoNewPrivs
	o.Capabilities = base.CapabilityList()
	o.Env = append([]string(nil), base.Cell.Env...)
	o.Config = base

	for _, n := range base.Bars.Namespaces {
		kind, ok := map[string]bars.Kind{
			"pid":  bars.PID,
			"uts":  bars.UTS,
			"mnt":  bars.Mount,
			"net":  bars.Network,
			"user": bars.User,
			"ipc":  bars.IPC,
		}[n]
		if ok {
			o.Bars = append(o.Bars, kind)
		}
	}

	if base.Rations.Memory != "" {
		v, err := rations.ParseMemory(base.Rations.Memory)
		if err != nil {
			return o, fmt.Errorf("config: rations.memory: %w", err)
		}
		o.Memory = v
	}
	o.CPUs = base.Rations.CPUs
	o.PIDs = base.Rations.PIDs
	return o, nil
}
func splitList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
