package security

import (
	"errors"
	"strings"
)

type AppliedReport struct {
	Version int `json:"version"`

	Rootless bool `json:"rootless,omitempty"`

	UsernsApplied bool `json:"usernsApplied,omitempty"`

	UsernsMode string `json:"usernsMode,omitempty"`

	UidRanges []string `json:"uidRanges,omitempty"`
	GidRanges []string `json:"gidRanges,omitempty"`

	SeccompApplied bool `json:"seccompApplied,omitempty"`

	SeccompProfile string `json:"seccompProfile,omitempty"`

	NoNewPrivsApplied bool `json:"noNewPrivsApplied,omitempty"`

	Capabilities []string `json:"capabilities,omitempty"`

	ReadOnlyApplied bool `json:"readOnlyApplied,omitempty"`

	LSM string `json:"lsm,omitempty"`

	LsmApplied bool `json:"lsmApplied,omitempty"`

	Unavailable *Unavailable `json:"unavailable,omitempty"`
}

type Unavailable struct {
	Feature string `json:"feature,omitempty"`

	Why string `json:"why,omitempty"`
}

func (u *Unavailable) Error() string {
	if u == nil {
		return ""
	}
	return u.Feature + ": " + u.Why
}

func IsUnavailable(err error) bool {
	var u *Unavailable
	return errors.As(err, &u)
}

func (r *AppliedReport) AllApplied() bool {
	if r == nil {
		return false
	}
	return r.Unavailable == nil
}

type AppliedCapabilities = []string

var _ = strings.Join
