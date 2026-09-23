package security

import "strings"

const (
	SeccompNone    = "none"
	SeccompDefault = "default"
	SeccompStrict  = "strict"
	SeccompCustom  = "custom"
)

const (
	UsernsAuto = "auto"
	UsernsOn   = "on"
	UsernsOff  = "off"
)

type Policy struct {
	Capabilities []string `json:"capabilities,omitempty"`

	NoNewPrivs bool `json:"noNewPrivs,omitempty"`

	Seccomp string `json:"seccomp,omitempty"`

	Userns string `json:"userns,omitempty"`

	ReadOnly bool `json:"readOnly,omitempty"`

	LSM string `json:"lsm,omitempty"`
}

var DefaultPolicy = Policy{
	Userns:     UsernsAuto,
	Seccomp:    SeccompNone,
	NoNewPrivs: true,
}

func ParseCapabilities(s string) []string {
	var out []string
	for _, c := range strings.Split(s, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

func (p *Policy) Validate() error {
	switch p.Seccomp {
	case "", SeccompNone, SeccompDefault, SeccompStrict, SeccompCustom:
	default:
		return &Unavailable{Feature: "seccomp",
			Why: "unknown profile " + p.Seccomp + " (want none, default, strict, custom)"}
	}
	switch p.Userns {
	case "", UsernsAuto, UsernsOn, UsernsOff:
	default:
		return &Unavailable{Feature: "userns",
			Why: "unknown mode " + p.Userns + " (want auto, on, off)"}
	}
	if p.LSM != "" && !validLSM(p.LSM) {
		return &Unavailable{Feature: "lsm",
			Why: "invalid LSM transition \"" + p.LSM + "\" (want apparmor:<profile> or selinux:<context>)"}
	}
	return nil
}

func NormalizeProfile(s string) string {
	switch s {
	case "", SeccompNone:
		return SeccompNone
	case SeccompDefault, SeccompStrict, SeccompCustom:
		return s
	default:
		return SeccompDefault
	}
}

func validLSM(s string) bool {
	return strings.HasPrefix(s, "apparmor:") || strings.HasPrefix(s, "selinux:")
}
