package oci

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"jailor/internal/config"
	"jailor/internal/gate"
	"jailor/internal/rations"
)

const FileName = "config.json"

const RootfsDir = "rootfs"

type Bundle struct {
	Dir string

	Config *config.Config
}

type Schema struct {
	OciVersion string `json:"ociVersion"`

	Process Process `json:"process"`

	Root Root `json:"root"`

	Hostname string `json:"hostname,omitempty"`

	Linux Linux `json:"linux,omitempty"`

	Mounts []Mount `json:"mounts,omitempty"`
	Hooks  Hooks   `json:"hooks,omitempty"`

	Jailor JailorExt `json:"jailor,omitempty"`
}

type Process struct {
	Args []string `json:"args,omitempty"`

	Env []string `json:"env,omitempty"`

	Cwd string `json:"cwd,omitempty"`

	Terminal bool `json:"terminal,omitempty"`

	ConsoleSize *ConsoleSize `json:"consoleSize,omitempty"`

	User User `json:"user,omitempty"`

	NoNewPrivileges bool `json:"noNewPrivileges,omitempty"`

	Capabilities Capabilities `json:"capabilities,omitempty"`
}

type ConsoleSize struct {
	Height int `json:"height"`
	Width  int `json:"width"`
}

type User struct {
	UID        uint32   `json:"uid"`
	GID        uint32   `json:"gid"`
	Umask      *uint32  `json:"umask,omitempty"`
	Additional []uint32 `json:"additionalGids,omitempty"`
}

type Capabilities struct {
	Bounding    []string `json:"bounding,omitempty"`
	Effective   []string `json:"effective,omitempty"`
	Permitted   []string `json:"permitted,omitempty"`
	Inheritable []string `json:"inheritable,omitempty"`
}

type Root struct {
	Path string `json:"path,omitempty"`

	Readonly bool `json:"readonly,omitempty"`
}

type Mount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type,omitempty"`
	Source      string   `json:"source,omitempty"`
	Options     []string `json:"options,omitempty"`
}

type Hooks struct {
	Prestart        []Hook `json:"prestart,omitempty"`
	CreateRuntime   []Hook `json:"createRuntime,omitempty"`
	CreateContainer []Hook `json:"createContainer,omitempty"`
	StartContainer  []Hook `json:"startContainer,omitempty"`
	Poststart       []Hook `json:"poststart,omitempty"`
	Poststop        []Hook `json:"poststop,omitempty"`
}

type Hook struct {
	Path    string   `json:"path"`
	Args    []string `json:"args,omitempty"`
	Env     []string `json:"env,omitempty"`
	Timeout int      `json:"timeout,omitempty"`
}

type Linux struct {
	Namespaces []Namespace `json:"namespaces,omitempty"`

	Resources Resources `json:"resources,omitempty"`

	Seccomp json.RawMessage `json:"seccomp,omitempty"`

	UidMappings []IDMapping `json:"uidMappings,omitempty"`
	GidMappings []IDMapping `json:"gidMappings,omitempty"`

	Sysctl map[string]string `json:"sysctl,omitempty"`

	MaskedPaths   []string `json:"maskedPaths,omitempty"`
	ReadonlyPaths []string `json:"readonlyPaths,omitempty"`
}

type IDMapping struct {
	ContainerID uint32 `json:"containerID"`
	HostID      uint32 `json:"hostID"`
	Size        uint32 `json:"size"`
}

type Namespace struct {
	Type string `json:"type"`
}

type Resources struct {
	Memory Memory `json:"memory,omitempty"`

	CPU CPU `json:"cpu,omitempty"`

	Pids Pids `json:"pids,omitempty"`
}

type Memory struct {
	Limit int64 `json:"limit,omitempty"`
}

type CPU struct {
	Shares uint64 `json:"shares,omitempty"`

	Quota int64 `json:"quota,omitempty"`

	Period int64 `json:"period,omitempty"`
}

type Pids struct {
	Limit int64 `json:"limit,omitempty"`
}

type JailorExt struct {
	Network string `json:"network,omitempty"`

	Userns string `json:"userns,omitempty"`
}

func LoadBundle(dir string) (*Bundle, error) {
	if dir == "" {
		return nil, errors.New("oci: no bundle directory specified")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("oci: resolve bundle %s: %w", dir, err)
	}
	cfgPath := filepath.Join(abs, FileName)
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("oci: read %s: %w", cfgPath, err)
	}
	var s Schema
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("oci: parse %s: %w", cfgPath, err)
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("oci: %s: %w", cfgPath, err)
	}

	c := config.Default()
	c.Command = append([]string(nil), s.Process.Args...)
	c.Cell.WorkDir = s.Process.Cwd
	if c.Cell.WorkDir == "" {
		c.Cell.WorkDir = "/"
	}
	c.Cell.Hostname = s.Hostname
	c.Cell.ReadOnly = s.Root.Readonly
	if len(s.Process.Env) > 0 {
		c.Cell.Env = append([]string(nil), s.Process.Env...)
	}

	if s.Root.Path != "" {
		rp := s.Root.Path
		if !filepath.IsAbs(rp) {
			rp = filepath.Join(abs, rp)
		}
		c.Cell.Rootfs = rp
	}

	if len(s.Linux.Namespaces) > 0 {
		var kinds []string
		for _, ns := range s.Linux.Namespaces {
			kind := namespaceKind(ns.Type)
			if kind != "" {
				kinds = append(kinds, kind)
			}
		}
		if len(kinds) > 0 {
			c.Bars.Namespaces = kinds
		}
	}

	if s.Linux.Resources.Memory.Limit > 0 {
		c.Rations.Memory = fmt.Sprintf("%d", s.Linux.Resources.Memory.Limit)
	}
	if s.Linux.Resources.Pids.Limit > 0 {
		c.Rations.PIDs = s.Linux.Resources.Pids.Limit
	}
	if s.Linux.Resources.CPU.Quota > 0 && s.Linux.Resources.CPU.Period > 0 {
		c.Rations.CPUs = float64(s.Linux.Resources.CPU.Quota) / float64(s.Linux.Resources.CPU.Period)
	}

	c.Privileges.NoNewPrivs = s.Process.NoNewPrivileges
	c.Privileges.Seccomp = s.Linux.SeccompEnabled()
	caps := mergeCaps(s.Process.Capabilities)
	if len(caps) > 0 {
		c.Privileges.Capabilities = strings.Join(caps, ",")
	}

	if s.Jailor.Network == "" {
		c.Gate.Mode = string(gate.ModeNone)
	} else {
		c.Gate.Mode = s.Jailor.Network
	}
	if s.Jailor.Userns == "" {
		c.Privileges.Userns = "auto"
	} else {
		c.Privileges.Userns = s.Jailor.Userns
	}

	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("oci: %s: %w", cfgPath, err)
	}
	return &Bundle{Dir: abs, Config: &c}, nil
}

func (l *Linux) SeccompEnabled() bool {
	if len(l.Seccomp) == 0 || string(l.Seccomp) == "false" || string(l.Seccomp) == "null" {
		return false
	}
	return true
}

func (s *Schema) validate() error {
	switch s.OciVersion {
	case "1.0", "1.1", "":
	default:
		return fmt.Errorf("unsupported ociVersion %q", s.OciVersion)
	}
	if len(s.Process.Args) == 0 {
		return errors.New("process.args is required")
	}

	if s.Process.Terminal {
		return errors.New("process.terminal is not supported (Jailor supervises plain stdio, not a pty)")
	}
	if s.Process.ConsoleSize != nil {
		return errors.New("process.consoleSize is not supported (Jailor does not allocate ptys)")
	}

	if s.Process.User.UID != 0 || s.Process.User.GID != 0 {
		return fmt.Errorf("process.user uid/gid %d/%d is not supported (Jailor runs the Prisoner as the mapped root of its own user namespace)", s.Process.User.UID, s.Process.User.GID)
	}
	if s.Process.User.Umask != nil {
		return errors.New("process.user.umask is not supported")
	}
	if len(s.Process.User.Additional) > 0 {
		return errors.New("process.user.additionalGids is not supported")
	}

	if len(s.Mounts) > 0 {
		return errors.New("linux.mounts is not supported (Jailor mounts /proc,/tmp,/dev by its own Warden policy; a mounts list would be silently ignored)")
	}

	if !s.Hooks.empty() {
		return errors.New("hooks are not supported (Jailor has no prestart/poststart/poststop hook execution)")
	}

	for _, ns := range s.Linux.Namespaces {
		if namespaceKind(ns.Type) == "" {
			return fmt.Errorf("linux.namespaces type %q is not supported (Jailor models pid, network, mount, uts, user, ipc)", ns.Type)
		}
	}

	if len(s.Linux.Seccomp) > 0 {
		trimmed := strings.TrimSpace(string(s.Linux.Seccomp))
		if trimmed != "true" && trimmed != "false" {
			return errors.New("linux.seccomp as a full filter object is not supported (Jailor applies its own deny-list; use \"seccomp\": true to enable it)")
		}
	}

	if len(s.Linux.UidMappings) > 0 || len(s.Linux.GidMappings) > 0 {
		return errors.New("linux.uidMappings/gidMappings are not supported (Jailor installs its own subordinate-range maps)")
	}

	if len(s.Linux.Sysctl) > 0 {
		return errors.New("linux.sysctl is not supported")
	}
	if len(s.Linux.MaskedPaths) > 0 || len(s.Linux.ReadonlyPaths) > 0 {
		return errors.New("linux.maskedPaths/readonlyPaths are not supported")
	}

	if s.Linux.Resources.CPU.Shares != 0 {
		return errors.New("linux.resources.cpu.shares is not supported (Jailor limits CPU by quota/period; set cpus via quota=period*cpus)")
	}
	return nil
}

func (h Hooks) empty() bool {
	return len(h.Prestart) == 0 && len(h.CreateRuntime) == 0 &&
		len(h.CreateContainer) == 0 && len(h.StartContainer) == 0 &&
		len(h.Poststart) == 0 && len(h.Poststop) == 0
}

func Export(c *config.Config) ([]byte, error) {
	if c == nil {
		return nil, errors.New("oci: cannot export a nil config")
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("oci: export: %w", err)
	}
	if len(c.Command) == 0 {
		return nil, errors.New("oci: cannot export a config with no command")
	}
	s := Schema{
		OciVersion: "1.0",
		Process: Process{
			Args:            append([]string(nil), c.Command...),
			Env:             append([]string(nil), c.Cell.Env...),
			Cwd:             c.Cell.WorkDir,
			NoNewPrivileges: c.Privileges.NoNewPrivs,
		},
		Root:     Root{Path: c.Cell.Rootfs, Readonly: c.Cell.ReadOnly},
		Hostname: c.Cell.Hostname,
		Linux: Linux{
			Namespaces: barsToNamespaces(c.Bars.Namespaces),
			Resources: Resources{
				Memory: Memory{Limit: memoryBytes(c.Rations.Memory)},
				CPU:    CPU{Quota: cpuQuota(c.Rations.CPUs), Period: 100000},
				Pids:   Pids{Limit: c.Rations.PIDs},
			},
		},
		Jailor: JailorExt{
			Network: c.Gate.Mode,
			Userns:  c.Privileges.Userns,
		},
	}
	if caps := strings.Split(c.Privileges.Capabilities, ","); len(caps) > 0 && caps[0] != "" {
		s.Process.Capabilities = Capabilities{Bounding: caps, Effective: append([]string(nil), caps...)}
	}
	if c.Privileges.Seccomp {
		s.Linux.Seccomp = json.RawMessage("true")
	}
	data, err := json.MarshalIndent(&s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("oci: encode export: %w", err)
	}
	return append(data, '\n'), nil
}

func namespaceKind(t string) string {
	switch strings.ToLower(t) {
	case "pid":
		return "pid"
	case "network":
		return "net"
	case "mount":
		return "mnt"
	case "uts":
		return "uts"
	case "user":
		return "user"
	case "ipc":
		return "ipc"
	default:
		return ""
	}
}

func barsToNamespaces(kinds []string) []Namespace {
	var out []Namespace
	for _, k := range kinds {
		switch k {
		case "pid":
			out = append(out, Namespace{Type: "pid"})
		case "mnt":
			out = append(out, Namespace{Type: "mount"})
		case "net":
			out = append(out, Namespace{Type: "network"})
		case "uts":
			out = append(out, Namespace{Type: "uts"})
		case "user":
			out = append(out, Namespace{Type: "user"})
		case "ipc":
			out = append(out, Namespace{Type: "ipc"})
		}
	}
	return out
}

func memoryBytes(s string) int64 {
	if s == "" {
		return 0
	}
	if n, err := rations.ParseMemory(s); err == nil {
		return n
	}
	return 0
}

func cpuQuota(cpus float64) int64 {
	if cpus <= 0 {
		return 0
	}
	q := int64(cpus * 100000)
	if q < 0 {
		return 0
	}
	return q
}

func mergeCaps(cc Capabilities) []string {
	set := map[string]bool{}
	for _, c := range append(append(append(append([]string(nil),
		cc.Bounding...), cc.Effective...), cc.Permitted...), cc.Inheritable...) {
		set[c] = true
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
