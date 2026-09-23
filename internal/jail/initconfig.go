package jail

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

const (
	extraConfig = iota
	extraSyncIn
	extraSyncOut
	extraStdio

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
	envInit      = "JAILOR_INIT"
	envConfigFD  = "JAILOR_CONFIG_FD"
	envSyncInFD  = "JAILOR_SYNCIN_FD"
	envSyncOutFD = "JAILOR_SYNCOUT_FD"
)

func (c *InitConfig) configFD() int  { return baseFD + extraConfig }
func (c *InitConfig) syncInFD() int  { return baseFD + extraSyncIn }
func (c *InitConfig) syncOutFD() int { return baseFD + extraSyncOut }

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
