package privileges

import (
	"errors"
	"strings"
)

type Privileges struct {
	Capabilities []string

	NoNewPrivs bool

	Seccomp bool

	OnlyAllows []string

	ReadOnly bool
}

var DefaultCapabilities = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETPCAP",
	"CAP_NET_BIND_SERVICE",
	"CAP_NET_RAW",
	"CAP_SYS_CHROOT",
	"CAP_MKNOD",
	"CAP_AUDIT_WRITE",
	"CAP_SETFCAP",
}

func ParseCapabilities(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, c := range strings.Split(s, ",") {
		c = strings.TrimSpace(c)
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

var LinuxCapabilities = map[string]bool{
	"CAP_CHOWN": true, "CAP_DAC_OVERRIDE": true, "CAP_DAC_READ_SEARCH": true,
	"CAP_FOWNER": true, "CAP_FSETID": true, "CAP_KILL": true,
	"CAP_SETGID": true, "CAP_SETUID": true, "CAP_SETPCAP": true,
	"CAP_LINUX_IMMUTABLE": true, "CAP_NET_BIND_SERVICE": true,
	"CAP_NET_BROADCAST": true, "CAP_NET_ADMIN": true, "CAP_NET_RAW": true,
	"CAP_IPC_LOCK": true, "CAP_IPC_OWNER": true, "CAP_SYS_MODULE": true,
	"CAP_SYS_RAWIO": true, "CAP_SYS_CHROOT": true, "CAP_SYS_PTRACE": true,
	"CAP_SYS_PACCT": true, "CAP_SYS_ADMIN": true, "CAP_SYS_BOOT": true,
	"CAP_SYS_NICE": true, "CAP_SYS_RESOURCE": true, "CAP_SYS_TIME": true,
	"CAP_SYS_TTY_CONFIG": true, "CAP_MKNOD": true, "CAP_LEASE": true,
	"CAP_AUDIT_WRITE": true, "CAP_AUDIT_CONTROL": true, "CAP_SETFCAP": true,
	"CAP_MAC_OVERRIDE": true, "CAP_MAC_ADMIN": true, "CAP_SYSLOG": true,
	"CAP_WAKE_ALARM": true, "CAP_BLOCK_SUSPEND": true, "CAP_AUDIT_READ": true,
	"CAP_PERFMON": true, "CAP_BPF": true, "CAP_CHECKPOINT_RESTORE": true,
}

func ValidCapability(name string) bool {
	return LinuxCapabilities[name]
}

func (p *Privileges) Validate() error {
	if p == nil {
		return errors.New("privileges: no privileges configured")
	}
	for _, c := range p.Capabilities {
		if !ValidCapability(c) {
			return errors.New("privileges: invalid capability name " + c)
		}
	}
	return nil
}

func NormalizeCapabilities(caps []string) ([]string, error) {
	seen := make(map[string]bool, len(caps))
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		if !ValidCapability(c) {
			return nil, errors.New("privileges: unknown capability " + c)
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}
