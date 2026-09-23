package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"jailor/internal/api"
	"jailor/internal/daemon"
	"jailor/internal/ledger"
	"jailor/internal/warden"
)

func (r *Root) daemonClient(ledgerDir, socket string) *daemon.Client {
	if socket == "" {
		if ledgerDir == "" {
			ledgerDir = ledger.DefaultDir()
		}
		socket = filepath.Join(ledgerDir, api.DefaultSocketName)
	}
	c := daemon.NewClient(socket)
	if aerr := c.Ping(); aerr != nil {
		return nil
	}
	return c
}

func jailSpecFromOptions(o warden.Options) api.Jail {
	spec := api.Jail{
		Command:   append([]string(nil), o.Args...),
		Hostname:  o.Hostname,
		Rootfs:    o.Rootfs,
		Image:     o.Image,
		WorkDir:   o.WorkDir,
		Network:   o.Network,
		Ports:     append([]string(nil), o.Ports...),
		DNS:       append([]string(nil), o.DNS...),
		Userns:    o.Userns,
		ReadOnly:  o.ReadOnly,
		Seccomp:   o.Seccomp,
		Caps:      append([]string(nil), o.Capabilities...),
		NoNewPriv: o.NoNewPrivs,
		Env:       append([]string(nil), o.Env...),
		Memory:    o.Memory,
		CPUs:      o.CPUs,
		PIDs:      o.PIDs,
	}
	if o.Config != nil {
		if b, err := json.Marshal(o.Config); err == nil {
			spec.Config = b
		}
	}
	return spec
}

func exitCodeForError(aerr *api.Error) int {
	if aerr == nil {
		return 0
	}
	if aerr.Code != 0 {
		return aerr.Code
	}
	return 1
}

var errNoDaemon = fmt.Errorf("no jailord daemon reachable")
