package rations

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Rations struct {
	MemoryLimitBytes int64

	CPUQuotaMicros int64

	PIDsLimit int64

	Enabled bool
}

func ParseMemory(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	upper := strings.ToUpper(s)
	mult := int64(1)
	switch {
	case strings.HasSuffix(upper, "G"):
		mult, upper = 1<<30, strings.TrimSuffix(upper, "G")
	case strings.HasSuffix(upper, "M"):
		mult, upper = 1<<20, strings.TrimSuffix(upper, "M")
	case strings.HasSuffix(upper, "K"):
		mult, upper = 1<<10, strings.TrimSuffix(upper, "K")
	}
	n, err := strconv.ParseInt(upper, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("rations: invalid memory value %q", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("rations: memory limit cannot be negative")
	}
	return n * mult, nil
}

func HumanBytes(b int64) string {
	if b < 0 {
		return "unlimited"
	}
	const (
		kib = 1 << 10
		mib = 1 << 20
		gib = 1 << 30
	)
	switch {
	case b >= gib:
		return fmt.Sprintf("%.2f GiB", float64(b)/gib)
	case b >= mib:
		return fmt.Sprintf("%.2f MiB", float64(b)/mib)
	case b >= kib:
		return fmt.Sprintf("%.1f KiB", float64(b)/kib)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

type Cgroup struct {
	Path string
}

func FindCgroupV2Mount() (string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		if fields[8] == "cgroup2" {
			return fields[4], nil
		}
	}
	return "", errors.New("rations: cgroup v2 not found; is it mounted at /sys/fs/cgroup?")
}

func Create(mount, jailID string, r Rations) (*Cgroup, error) {
	path := filepath.Join(mount, "jailor", jailID)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, fmt.Errorf("rations: create cgroup %s: %w", path, err)
	}
	c := &Cgroup{Path: path}
	if err := c.Apply(r); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cgroup) Apply(r Rations) error {
	if r.MemoryLimitBytes > 0 {
		if err := c.write("memory.max", strconv.FormatInt(r.MemoryLimitBytes, 10)); err != nil {
			return err
		}
	}
	if r.CPUQuotaMicros > 0 {
		if err := c.write("cpu.max", fmt.Sprintf("%d %d", r.CPUQuotaMicros, 100000)); err != nil {
			return err
		}
	}
	if r.PIDsLimit > 0 {
		if err := c.write("pids.max", strconv.FormatInt(r.PIDsLimit, 10)); err != nil {
			return err
		}
	}
	return nil
}

func (c *Cgroup) AddPid(pid int) error {
	data := []byte(strconv.Itoa(pid) + "\n")
	path := filepath.Join(c.Path, "cgroup.procs")
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("rations: open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("rations: add pid %d: %w", pid, err)
	}
	return nil
}

func (c *Cgroup) Remove() error {
	if c == nil {
		return nil
	}
	err := os.Remove(c.Path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func FindJailCgroup(jailID string) (*Cgroup, error) {
	mount, err := FindCgroupV2Mount()
	if err != nil {
		return nil, err
	}
	return &Cgroup{Path: filepath.Join(mount, "jailor", jailID)}, nil
}

func (c *Cgroup) Exists() bool {
	if c == nil {
		return false
	}
	info, err := os.Stat(c.Path)
	return err == nil && info.IsDir()
}

type Stats struct {
	MemoryCurrent int64
	MemoryMax     int64
	CPUQuotaUsec  int64
	CPUPeriodUsec int64
	CPUUsageUsec  int64
	PIDsCurrent   int64
	PIDsMax       int64
}

func (c *Cgroup) Stats() (*Stats, error) {
	if c == nil {
		return nil, errors.New("rations: no cgroup")
	}
	s := &Stats{}
	var err error
	if s.MemoryCurrent, err = readInt(c.Path, "memory.current"); err != nil {
		return nil, err
	}
	if s.MemoryMax, err = readInt(c.Path, "memory.max"); err != nil {
		return nil, err
	}
	if s.CPUQuotaUsec, s.CPUPeriodUsec, err = readCPUMax(c.Path); err != nil {
		return nil, err
	}
	if s.CPUUsageUsec, err = readCPUUsage(c.Path); err != nil {
		return nil, err
	}
	if s.PIDsCurrent, err = readInt(c.Path, "pids.current"); err != nil {
		return nil, err
	}
	if s.PIDsMax, err = readInt(c.Path, "pids.max"); err != nil {
		return nil, err
	}
	return s, nil
}

func readInt(dir, name string) (int64, error) {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return 0, fmt.Errorf("rations: read %s: %w", name, err)
	}
	f := strings.Fields(string(data))
	if len(f) < 1 {
		return 0, fmt.Errorf("rations: empty %s", name)
	}
	if f[0] == "max" {
		return -1, nil
	}
	n, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("rations: parse %s=%q: %w", name, f[0], err)
	}
	return n, nil
}

func readCPUMax(dir string) (quota, period int64, err error) {
	data, err := os.ReadFile(filepath.Join(dir, "cpu.max"))
	if err != nil {
		return 0, 0, fmt.Errorf("rations: read cpu.max: %w", err)
	}
	f := strings.Fields(string(data))
	if len(f) < 2 {
		return 0, 0, fmt.Errorf("rations: malformed cpu.max %q", string(data))
	}
	if f[0] != "max" {
		quota, err = strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("rations: parse cpu.max quota: %w", err)
		}
	}
	period, err = strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("rations: parse cpu.max period: %w", err)
	}
	return quota, period, nil
}

func readCPUUsage(dir string) (int64, error) {
	data, err := os.ReadFile(filepath.Join(dir, "cpu.stat"))
	if err != nil {
		return 0, fmt.Errorf("rations: read cpu.stat: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "usage_usec" {
			n, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("rations: parse cpu.stat usage_usec: %w", err)
			}
			return n, nil
		}
	}
	return 0, fmt.Errorf("rations: cpu.stat has no usage_usec")
}

func (c *Cgroup) write(name, value string) error {
	path := filepath.Join(c.Path, name)
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("rations: write %s=%s: %w", name, value, err)
	}
	return nil
}
