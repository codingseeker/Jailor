package api

import (
	"encoding/json"

	"jailor/internal/config"
	"jailor/internal/image"
	"jailor/internal/ledger"
	"jailor/internal/network"
)

type Jail struct {
	Command   []string `json:"command"`
	Hostname  string   `json:"hostname,omitempty"`
	Rootfs    string   `json:"rootfs,omitempty"`
	Image     string   `json:"image,omitempty"`
	WorkDir   string   `json:"workdir,omitempty"`
	Network   string   `json:"network,omitempty"`
	Ports     []string `json:"ports,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	Userns    string   `json:"userns,omitempty"`
	ReadOnly  bool     `json:"readOnly,omitempty"`
	Seccomp   bool     `json:"seccomp,omitempty"`
	Caps      []string `json:"caps,omitempty"`
	NoNewPriv bool     `json:"noNewPrivs,omitempty"`
	Env       []string `json:"env,omitempty"`
	Memory    int64    `json:"memory,omitempty"`
	CPUs      float64  `json:"cpus,omitempty"`
	PIDs      int64    `json:"pids,omitempty"`

	ID string `json:"id,omitempty"`

	Config json.RawMessage `json:"config,omitempty"`

	WithLogs bool `json:"withLogs,omitempty"`
}

type CreateParams struct {
	Jail Jail `json:"jail"`
}

type RunParams struct {
	Jail Jail `json:"jail"`
}

type RunResult struct {
	ID       string `json:"id"`
	ExitCode int    `json:"exitCode"`
	Result   string `json:"result,omitempty"`
}

type IDParams struct {
	ID string `json:"id"`
}

type IDResult struct {
	ID string `json:"id"`
}

type CountResult struct {
	Count int `json:"count"`
}

type ListParams struct {
	All bool `json:"all,omitempty"`
}

type JailList struct {
	Records []ledger.Record `json:"records"`
}

type JailRecord struct {
	Record ledger.Record `json:"record"`

	StorageBytes int64 `json:"storageBytes,omitempty"`
}

type StatsParams struct {
	ID string `json:"id"`
}

type RationsStats struct {
	ID            string `json:"id"`
	State         string `json:"state"`
	MemoryCurrent int64  `json:"memoryCurrent"`
	MemoryMax     int64  `json:"memoryMax"`
	CPUQuotaUsec  int64  `json:"cpuQuotaUsec"`
	CPUPeriodUsec int64  `json:"cpuPeriodUsec"`
	CPUUsageUsec  int64  `json:"cpuUsageUsec"`
	PIDsCurrent   int64  `json:"pidsCurrent"`
	PIDsMax       int64  `json:"pidsMax"`
}

type LogsParams struct {
	ID string `json:"id"`
}

type JailLogs struct {
	ID     string       `json:"id"`
	Events []ledger.Log `json:"events,omitempty"`
}

type ImageParams struct {
	Ref string `json:"ref"`
}

type ImageList struct {
	Images []image.Image `json:"images"`
}

type NetworkParams struct {
	Name    string   `json:"name,omitempty"`
	Subnet  string   `json:"subnet,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
	IPv6    string   `json:"ipv6,omitempty"`
	DNS     []string `json:"dns,omitempty"`
}

type NetworkResult struct {
	Network  network.Network   `json:"network,omitempty"`
	Networks []network.Network `json:"networks,omitempty"`
	Allocs   []string          `json:"allocations,omitempty"`
	Count    int               `json:"count,omitempty"`
}

type Event struct {
	Version int            `json:"version"`
	Type    string         `json:"type"`
	JailID  string         `json:"jailId,omitempty"`
	Message string         `json:"msg,omitempty"`
	Fields  map[string]any `json:"fields,omitempty"`
}

const (
	EventJailCreated   = "jail.created"
	EventJailStarted   = "jail.started"
	EventJailStopped   = "jail.stopped"
	EventJailKilled    = "jail.killed"
	EventJailRemoved   = "jail.removed"
	EventJailExited    = "jail.exited"
	EventJailRecovered = "jail.recovered"
	EventDaemonStarted = "daemon.started"
	EventDaemonStopped = "daemon.stopped"
	EventSubscribed    = "events.subscribed"
)

type ShutdownOk struct {
	Stopped bool `json:"stopped"`
}

func parsedConfig(raw json.RawMessage) (*config.Config, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var c config.Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
