package jail

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type State string

const (
	StateCreated State = "CREATED"

	StateRunning State = "RUNNING"

	StateStopped State = "STOPPED"

	StateDeleted State = "DELETED"
)

type ID string

func NewID() ID {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ID(hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000"))))
	}
	return ID(hex.EncodeToString(b))
}

type Jail struct {
	ID ID

	Hostname string

	Rootfs string

	Args []string

	Stdin  string
	Stdout string
	Stderr string

	State State

	PrisonerPID int

	ExitCode int

	Result string

	CreatedAt time.Time

	Config Config
}

type Config struct {
	Bars BarsConfig

	Cell CellConfig

	Rations RationsConfig

	Gate GateConfig

	Privileges PrivilegesConfig
}

type BarsConfig struct {
	Namespaces []string
}

type CellConfig struct {
	Rootfs string

	WorkDir string

	ReadOnly bool
}

type RationsConfig struct {
	Memory int64

	CPUs float64

	PIDs int64
}

type GateConfig struct {
	Mode string
}

type PrivilegesConfig struct {
	UserNS bool

	Capabilities []string

	NoNewPrivs bool

	Seccomp bool
}
