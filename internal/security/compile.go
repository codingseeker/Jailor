package security

import (
	"fmt"

	"jailor/internal/idmap"
	"jailor/internal/privileges"
)

type Context struct {
	RequireMounts bool
}

func Compile(p Policy, ctx Context, h Host) (*AppliedReport, error) {
	if err := p.Validate(); err != nil {
		var u *Unavailable
		if IsUnavailable(err) {
			u = asU(err)
			return &AppliedReport{Version: 1, Unavailable: u}, err
		}
		return &AppliedReport{Version: 1}, err
	}

	r := &AppliedReport{Version: 1, Rootless: !h.Root}

	caps := p.Capabilities
	if len(caps) == 0 {
		caps = make([]string, len(privileges.DefaultCapabilities))
		copy(caps, privileges.DefaultCapabilities)
	}
	if _, err := privileges.NormalizeCapabilities(caps); err != nil {
		return r, fmt.Errorf("security: %w", err)
	}
	r.Capabilities = caps

	mode := p.Userns
	if mode == "" {
		mode = UsernsAuto
	}
	if mode == UsernsAuto {
		if h.Root {
			mode = UsernsOff
		} else {
			mode = UsernsOn
		}
	}
	r.UsernsMode = mode

	switch mode {
	case UsernsOn:
		if !h.UsernsSupported {
			return fail(r, &Unavailable{Feature: "userns",
				Why: "host cannot create user namespaces"})
		}
		if h.Root {
			r.UsernsApplied = true
			r.UidRanges = []string{"0->0,4294967295"}
			r.GidRanges = []string{"0->0,4294967295"}
		} else {

			if miss := missingRootless(h); miss != nil {
				return fail(r, miss)
			}
			uidLines, gidLines, err := idmap.BuildMappings(h.Euid, h.Egid, h.SubUID, h.SubGID)
			if err != nil {
				return fail(r, &Unavailable{Feature: "userns.rootless", Why: err.Error()})
			}
			r.UsernsApplied = true
			r.UidRanges = idmap.MapsToString(uidLines)
			r.GidRanges = idmap.MapsToString(gidLines)
		}
	case UsernsOff:
		if !h.Root && ctx.RequireMounts {
			return fail(r, &Unavailable{Feature: "mounts",
				Why: "rootless execution requires a user namespace to install the Cell mounts"})
		}
		r.UsernsApplied = false
	default:
		return fail(r, &Unavailable{Feature: "userns",
			Why: "unknown mode " + p.Userns})
	}

	switch p.Seccomp {
	case "", SeccompNone:
		r.SeccompProfile = ""
	case SeccompDefault:
		r.SeccompApplied = true
		r.SeccompProfile = SeccompDefault
	case SeccompStrict:
		r.SeccompApplied = true
		r.SeccompProfile = SeccompStrict
	case SeccompCustom:
		return fail(r, &Unavailable{Feature: "seccomp",
			Why: "custom seccomp profiles are not yet supported"})
	default:
		return fail(r, &Unavailable{Feature: "seccomp",
			Why: "unknown profile " + p.Seccomp})
	}

	r.NoNewPrivsApplied = p.NoNewPrivs || r.SeccompApplied

	r.ReadOnlyApplied = p.ReadOnly

	r.LSM = p.LSM

	return r, nil
}

func missingRootless(h Host) *Unavailable {
	if len(h.SubUID) == 0 || len(h.SubGID) == 0 {
		return &Unavailable{Feature: "userns.subordinate",
			Why: "no subordinate UID/GID range for user \"" + h.Username +
				"\" in /etc/subuid or /etc/subgid; cannot build a rootless userns map"}
	}
	if !h.HasNewUIDMap || !h.HasNewGIDMap {
		return &Unavailable{Feature: "userns.map",
			Why: "newuidmap/newgidmap are required to install a rootless id map but are not on PATH"}
	}
	return nil
}

func fail(r *AppliedReport, u *Unavailable) (*AppliedReport, error) {
	r.Unavailable = u
	return r, u
}

func asU(err error) *Unavailable {
	var u *Unavailable
	if IsUnavailable(err) {
		u = err.(*Unavailable)
	}
	return u
}
