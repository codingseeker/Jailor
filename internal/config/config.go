package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"jailor/internal/cell"
	"jailor/internal/gate"
	"jailor/internal/privileges"
)

const Version = 1
const FileName = "jail.json"

type Config struct {
	Version    int              `json:"version"`
	Command    []string         `json:"command,omitempty"`
	Cell       CellConfig       `json:"cell"`
	Bars       BarsConfig       `json:"bars"`
	Rations    RationsConfig    `json:"rations"`
	Gate       GateConfig       `json:"gate"`
	Privileges PrivilegesConfig `json:"privileges"`
}
type CellConfig struct {
	Rootfs   string `json:"rootfs,omitempty"`
	Image    string `json:"image,omitempty"`
	WorkDir  string `json:"workdir,omitempty"`
	ReadOnly bool   `json:"readOnly,omitempty"`
	Hostname string `json:"hostname,omitempty"`

	Env []string `json:"env,omitempty"`
}
type BarsConfig struct {
	Namespaces []string `json:"namespaces,omitempty"`
}
type RationsConfig struct {
	Memory string  `json:"memory,omitempty"`
	CPUs   float64 `json:"cpu,omitempty"`
	PIDs   int64   `json:"pids,omitempty"`
}
type GateConfig struct {
	Mode  string   `json:"mode,omitempty"`
	Name  string   `json:"name,omitempty"`
	Ports []string `json:"ports,omitempty"`
	DNS   []string `json:"dns,omitempty"`
}
type PrivilegesConfig struct {
	Userns       string `json:"userns,omitempty"`
	Capabilities string `json:"capabilities,omitempty"`
	NoNewPrivs   bool   `json:"noNewPrivs,omitempty"`
	Seccomp      bool   `json:"seccomp,omitempty"`
}

func Default() Config {
	return Config{
		Version: Version,
		Bars: BarsConfig{
			Namespaces: []string{"pid", "uts", "mnt"},
		},
		Cell: CellConfig{
			WorkDir: "/",
		},
		Rations: RationsConfig{},
		Gate: GateConfig{
			Mode: string(gate.ModeNone),
		},
		Privileges: PrivilegesConfig{
			Userns:       "auto",
			Capabilities: "",
			NoNewPrivs:   true,
			Seccomp:      false,
		},
	}
}
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return &c, nil
}
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.Version != Version {
		return fmt.Errorf("unsupported config version %d (want %d)", c.Version, Version)
	}
	if len(c.Command) == 0 {
		return errors.New("config: no command specified")
	}
	for _, n := range c.Bars.Namespaces {
		switch n {
		case "pid", "uts", "mnt", "net", "user", "ipc":
		default:
			return fmt.Errorf("config: unknown namespace bar %q", n)
		}
	}
	switch c.Gate.Mode {
	case "", string(gate.ModeNone), string(gate.ModeBridge):
	default:
		return fmt.Errorf("config: invalid gate mode %q (want none or bridge; set the network name in gate.name)", c.Gate.Mode)
	}
	if c.Gate.Name != "" && c.Gate.Mode == string(gate.ModeNone) {
		return errors.New("config: gate.name is only valid in bridge mode")
	}
	if c.Gate.Name != "" && !validNetworkName(c.Gate.Name) {
		return fmt.Errorf("config: invalid gate.name %q", c.Gate.Name)
	}
	for _, p := range c.Gate.Ports {
		if err := validatePortMap(p); err != nil {
			return fmt.Errorf("config: gate.ports: %w", err)
		}
	}
	for _, d := range c.Gate.DNS {
		if net.ParseIP(d) == nil {
			return fmt.Errorf("config: gate.dns: invalid nameserver %q", d)
		}
	}
	switch c.Privileges.Userns {
	case "", "auto", "on", "off":
	default:
		return fmt.Errorf("config: invalid userns policy %q (want auto, on, or off)", c.Privileges.Userns)
	}
	if err := validateHostname(c.Cell.Hostname); err != nil {
		return err
	}
	if c.Privileges.Capabilities != "" && c.Privileges.Capabilities != "all" {
		for _, cap := range privileges.ParseCapabilities(c.Privileges.Capabilities) {
			if !privileges.ValidCapability(cap) {
				return fmt.Errorf("config: unknown capability %q", cap)
			}
		}
	}
	if c.Cell.WorkDir == "" {
		c.Cell.WorkDir = "/"
	}
	for i, e := range c.Cell.Env {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" {
			return fmt.Errorf("config: cell.env[%d]: %q is not KEY=VALUE", i, e)
		}
		if strings.ContainsAny(k, "\x00\n\t") {
			return fmt.Errorf("config: cell.env[%d]: key %q contains control characters", i, k)
		}
	}
	if c.Cell.Rootfs != "" && c.Cell.Image != "" {
		return errors.New("config: cell.rootfs and cell.image are mutually exclusive")
	}
	if c.Cell.Image != "" {
		if err := validateImageRef(c.Cell.Image); err != nil {
			return fmt.Errorf("config: invalid cell.image %q: %w", c.Cell.Image, err)
		}
		return nil
	}
	if c.Cell.Rootfs == "" {
		return nil
	}
	return cell.ValidateRootfsNotEscape(c.Cell.Rootfs)
}
func (c *Config) UsernsPolicy() string {
	switch c.Privileges.Userns {
	case "", "auto":
		return "auto"
	default:
		return c.Privileges.Userns
	}
}
func (c *Config) CapabilityList() []string {
	return resolveCaps(c.Privileges.Capabilities)
}

func ResolveCaps(s string) []string {
	return resolveCaps(s)
}

func resolveCaps(s string) []string {
	if s == "" {
		return privileges.DefaultCapabilities
	}
	if s == "all" {
		return []string{"all"}
	}
	return privileges.ParseCapabilities(strings.Join(strings.Fields(s), ""))
}
func validNetworkName(s string) bool {
	if s == "" || s == "none" || len(s) > 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '_', c == '-', c == '.':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func validatePortMap(p string) error {
	parts := strings.Split(p, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid port mapping %q (want HOST:GUEST)", p)
	}
	for _, s := range parts {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid port mapping %q (ports must be 1-65535)", p)
		}
	}
	return nil
}
func validateImageRef(ref string) error {
	if ref == "" {
		return errors.New("empty reference")
	}
	if strings.Contains(ref, "..") {
		return errors.New("reference contains a '..' segment")
	}
	if strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, ".") {
		return errors.New("reference must be a repository name, not a path")
	}
	if strings.ContainsAny(ref, "\x00\n\t") {
		return errors.New("reference contains control characters")
	}
	return nil
}
func validateHostname(h string) error {
	if h == "" {
		return nil
	}
	if len(h) > 63 {
		return fmt.Errorf("config: hostname %q exceeds the 63-byte UTS limit", h)
	}
	for i := 0; i < len(h); i++ {
		if h[i] == 0 {
			return errors.New("config: hostname contains a NUL byte")
		}
	}
	return nil
}
