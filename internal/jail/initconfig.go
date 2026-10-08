package jail

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

const (
	extraConfig = iota
	extraRelease
	extraReady
	extraInitPID
	extraPrisonerRead
	extraPrisonerWrite

	baseFD = 3
)

type InitConfig struct {
	Rootfs string

	WorkDir string

	MountProc bool

	MountTmp bool

	MountDev bool

	Hostname string

	ReadOnly bool

	Args []string

	Env []string

	NoNewPrivs bool

	Capabilities []string

	Seccomp bool

	SeccompProfile string

	LSM string

	DropRootID bool
}

const (
	envInit            = "JAILOR_INIT"
	envNewPIDNS        = "JAILOR_NEWPIDNS"
	envConfigFD        = "JAILOR_CONFIG_FD"
	envReleaseFD       = "JAILOR_RELEASE_FD"
	envReadyFD         = "JAILOR_READY_FD"
	envInitPIDFD       = "JAILOR_INITPID_FD"
	envPrisonerReadFD  = "JAILOR_PRISONER_FD"
	envPrisonerWriteFD = "JAILOR_PRISONER_WFD"
)

func (c *InitConfig) marshal() ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("jail: encode init config: %w", err)
	}
	return data, nil
}

func mustGetFD(name string) (int, error) {
	v := os.Getenv(name)
	if v == "" {
		return 0, fmt.Errorf("jail: missing env %s", name)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("jail: bad fd env %s=%q", name, v)
	}
	return n, nil
}
