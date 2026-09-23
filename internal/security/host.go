package security

import (
	"os"
	"os/exec"
	"sync"

	"jailor/internal/idmap"
)

type Host struct {
	Euid uint32
	Egid uint32

	Root bool

	Username string

	SubUID []idmap.Range
	SubGID []idmap.Range

	HasNewUIDMap bool
	HasNewGIDMap bool

	UsernsSupported bool

	MountNamespaceSupported bool
}

var probeOnce sync.Once
var probed Host
var probeErr error

func ProbeHost() (Host, error) {
	probeOnce.Do(func() {
		probed, probeErr = probeHost()
	})
	return probed, probeErr
}

func probeHost() (Host, error) {
	h := Host{
		Euid:            uint32(os.Geteuid()),
		Egid:            uint32(os.Getegid()),
		Root:            os.Geteuid() == 0,
		UsernsSupported: os.Geteuid() == 0 || canCreateUserNamespace(),
	}
	h.MountNamespaceSupported = h.Root || h.UsernsSupported

	h.Username, _ = idmap.LookupUsername(h.Euid)

	if !h.Root {
		if name, rs, err := idmap.Lookup(idmap.SubUID, h.Euid); err == nil {
			h.Username = name
			h.SubUID = rs
		}
		if _, gs, err := idmap.Lookup(idmap.SubGID, h.Egid); err == nil {
			h.SubGID = gs
		}
	}
	h.HasNewUIDMap = lookPath("newuidmap")
	h.HasNewGIDMap = lookPath("newgidmap")
	return h, nil
}

func canCreateUserNamespace() bool {
	p, err := exec.LookPath("unshare")
	if err != nil {
		return false
	}
	cmd := exec.Command(p, "--user", "--map-root-user", "true")
	return cmd.Run() == nil
}

func lookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
