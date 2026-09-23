package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"jailor/internal/config"
	"jailor/internal/runtimecore"
	"jailor/internal/security"
)

type Record struct {
	ID        string    `json:"id"`
	Command   string    `json:"command,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Rootfs    string    `json:"rootfs,omitempty"`
	Image     string    `json:"image,omitempty"`
	Args      []string  `json:"args,omitempty"`
	State     string    `json:"state"`
	Pid       int       `json:"pid"`
	ExitCode  int       `json:"exitCode"`
	Result    string    `json:"result,omitempty"`
	CreatedAt time.Time `json:"createdAt"`

	Restarts int `json:"restarts,omitempty"`

	Failures int `json:"failures,omitempty"`

	PrisonerPID int `json:"prisonerPid,omitempty"`

	WorkDir string `json:"workDir,omitempty"`

	Network string `json:"network,omitempty"`

	NetworkName string `json:"networkName,omitempty"`

	Bridge string `json:"bridge,omitempty"`

	Ports []string `json:"ports,omitempty"`

	DNS []string `json:"dns,omitempty"`

	Userns string `json:"userns,omitempty"`

	ReadOnly bool `json:"readOnly,omitempty"`

	Seccomp bool `json:"seccomp,omitempty"`

	Capabilities []string `json:"capabilities,omitempty"`

	Env []string `json:"env,omitempty"`

	VethHost string `json:"vethHost,omitempty"`

	GateIP string `json:"gateIP,omitempty"`

	Gateway string `json:"gateway,omitempty"`

	Memory int64   `json:"memory,omitempty"`
	CPUs   float64 `json:"cpus,omitempty"`
	Pids   int64   `json:"pids,omitempty"`

	Config *config.Config `json:"config,omitempty"`

	Policy *security.AppliedReport `json:"policy,omitempty"`
}

const DefaultRoot = "/var/lib/jailor"

func DefaultDir() string {
	if d := os.Getenv("JAILOR_LEDGER"); d != "" {
		return d
	}
	if os.Geteuid() == 0 {
		return DefaultRoot
	}
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "jailor")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "jailor")
	}
	return DefaultRoot
}

type Ledger struct {
	Root string
	mu   sync.Mutex
}

func New(dir string) (*Ledger, error) {
	if dir == "" {
		dir = DefaultRoot
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ledger: create root %s: %w", dir, err)
	}
	return &Ledger{Root: dir}, nil
}

func (l *Ledger) Set(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.ID == "" {
		return errors.New("ledger: record has no id")
	}
	if !ValidID(r.ID) {
		return fmt.Errorf("ledger: invalid jail id %q", r.ID)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("ledger: encode %s: %w", r.ID, err)
	}
	path := collection(l.Root, r.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (l *Ledger) Get(id string) (*Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := os.ReadFile(collection(l.Root, id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("ledger: no record for jail %s", id)
		}
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("ledger: decode %s: %w", id, err)
	}
	return &r, nil
}

func (l *Ledger) List() ([]Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entries, err := os.ReadDir(l.Root)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(collection(l.Root, e.Name()))
		if err != nil {
			continue
		}
		var r Record
		if json.Unmarshal(data, &r) == nil {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (l *Ledger) Delete(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	path := collection(l.Root, id)
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("ledger: no record for jail %s", id)
	}
	if err == nil {

		_ = os.Remove(filepath.Dir(path))
	}
	return err
}

func (l *Ledger) Recover() (int, error) {
	recs, err := l.List()
	if err != nil {
		return 0, err
	}
	recovered := 0
	for _, r := range recs {
		if r.State != StateRunning {
			continue
		}
		if processAlive(r.Pid) {
			continue
		}
		r.State = StateStopped
		r.Result = "recovered: prisoner no longer running"
		if r.ExitCode == 0 {
			r.ExitCode = -1
		}
		if err := l.Set(r); err != nil {
			return recovered, err
		}
		recovered++
	}
	return recovered, nil
}

func processAlive(pid int) bool {
	return runtimecore.Alive(pid)
}

func ProcessAlive(pid int) bool {
	return processAlive(pid)
}

const (
	StateCreated = "CREATED"
	StateRunning = "RUNNING"
	StateStopped = "STOPPED"
	StateDeleted = "DELETED"
)

func IsValidState(s string) bool {
	switch s {
	case StateCreated, StateRunning, StateStopped, StateDeleted:
		return true
	}
	return false
}

func Short(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

func (l *Ledger) Usage(id string) int64 {
	base := filepath.Join(l.Root, id)
	entries, err := os.ReadDir(base)
	if err != nil {
		return 0
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if info, err := e.Info(); err == nil {
			total += info.Size()
		}
	}
	return total
}

func (l *Ledger) Find(id string) (*Record, error) {
	if id == "" {
		return nil, fmt.Errorf("ledger: no jail id given")
	}
	if r, err := l.Get(id); err == nil {
		return r, nil
	}
	recs, err := l.List()
	if err != nil {
		return nil, err
	}
	var match *Record
	for i := range recs {
		if strings.HasPrefix(recs[i].ID, id) {
			if match != nil {
				return nil, fmt.Errorf("ledger: jail id %s is ambiguous", id)
			}
			match = &recs[i]
		}
	}
	if match == nil {
		return nil, fmt.Errorf("ledger: no record for jail %s", id)
	}
	return match, nil
}

func collection(root, id string) string {
	return filepath.Join(root, id, "jail.json")
}

func ValidID(id string) bool {
	if id == "" || id == "." || id == ".." {
		return false
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return false
	}
	if id[0] == '.' || id[0] == '-' {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

type Level string

const (
	LevelInfo Level = "info"

	LevelDebug Level = "debug"

	LevelError Level = "error"
)

type Log struct {
	Time    time.Time      `json:"time"`
	Level   Level          `json:"level"`
	Event   string         `json:"event"`
	JailID  string         `json:"jailId,omitempty"`
	Message string         `json:"msg,omitempty"`
	Fields  map[string]any `json:"fields,omitempty"`
}

func logFile(root, id string) string {
	return filepath.Join(root, id, "log.jsonl")
}

func (l *Ledger) AppendLog(id string, event Log) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	path := logFile(l.Root, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("ledger: create log dir for %s: %w", id, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("ledger: open log for %s: %w", id, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	return enc.Encode(event)
}

func (l *Ledger) Logs(id string) ([]Log, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := os.ReadFile(logFile(l.Root, id))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Log
	dec := json.NewDecoder(strings.NewReader(string(data)))
	for {
		var e Log
		if err := dec.Decode(&e); err != nil {
			break
		}
		out = append(out, e)
	}
	return out, nil
}
