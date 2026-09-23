package warden

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"jailor/internal/bars"
	"jailor/internal/cell"
	"jailor/internal/config"
	"jailor/internal/gate"
	"jailor/internal/image"
	"jailor/internal/jail"
	"jailor/internal/ledger"
	"jailor/internal/network"
	"jailor/internal/security"
)

type Options struct {
	Args []string

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	Env []string

	Dir string

	Signals []os.Signal

	Hostname string

	Rootfs string

	Image string

	WorkDir string

	ReadOnly bool

	Bars []bars.Kind

	Network string

	Ports []string

	DNS []string

	Userns string

	MountProc bool
	MountTmp  bool
	MountDev  bool

	Capabilities []string

	NoNewPrivs bool

	Seccomp bool

	Security *security.Policy

	Memory int64

	CPUs float64

	PIDs int64

	Debug bool

	Config *config.Config

	LedgerDir string

	ID string
}

type Warden struct {
	opts Options
	log  *Logger
}

func New(opts Options) *Warden {
	return &Warden{opts: opts}
}

var defaultBars = []bars.Kind{bars.PID, bars.UTS, bars.Mount}

func (w *Warden) bars() []bars.Kind {
	b := w.opts.Bars
	if len(b) == 0 {
		b = append([]bars.Kind(nil), defaultBars...)
	}
	if w.networkIsolated() {
		b = append(b, bars.Network)
	}
	return b
}

func (w *Warden) networkIsolated() bool {

	return w.opts.Network != ""
}

func (w *Warden) useUserns() bool {
	switch w.opts.Userns {
	case "on":
		return true
	case "off":
		return false
	default:
		return os.Geteuid() != 0
	}
}

func (w *Warden) buildInit() *jail.InitConfig {
	init := &jail.InitConfig{
		Rootfs:       w.opts.Rootfs,
		WorkDir:      w.opts.WorkDir,
		MountProc:    w.opts.MountProc,
		MountTmp:     w.opts.MountTmp,
		MountDev:     w.opts.MountDev,
		Hostname:     w.opts.Hostname,
		ReadOnly:     w.opts.ReadOnly,
		Args:         w.opts.Args,
		Env:          w.opts.Env,
		NoNewPrivs:   w.opts.NoNewPrivs,
		Capabilities: w.opts.Capabilities,
		Seccomp:      w.opts.Seccomp,
	}
	if !init.MountProc && !init.MountTmp && !init.MountDev {

		init.MountProc, init.MountTmp, init.MountDev = true, true, true
	}
	return init
}

func (w *Warden) compileSecurity(init *jail.InitConfig) (*security.AppliedReport, error) {
	if w.opts.Security == nil {
		return nil, nil
	}
	host, err := security.ProbeHost()
	if err != nil {
		return nil, fmt.Errorf("warden: probe host: %w", err)
	}
	report, err := security.Compile(*w.opts.Security, security.Context{
		RequireMounts: init.MountProc || init.MountTmp || init.MountDev,
	}, host)
	if err != nil {
		return report, err
	}
	init.NoNewPrivs = report.NoNewPrivsApplied || w.opts.NoNewPrivs
	if len(report.Capabilities) > 0 {
		init.Capabilities = report.Capabilities
	}
	if report.SeccompProfile != "" {
		init.SeccompProfile = report.SeccompProfile
		init.Seccomp = report.SeccompApplied
	}
	if report.LSM != "" {
		init.LSM = report.LSM
	}
	if report.ReadOnlyApplied {
		init.ReadOnly = true
	}
	return report, nil
}

func (w *Warden) Run(ctx context.Context) int {
	if len(w.opts.Args) == 0 {
		fmt.Fprintln(os.Stderr, "warden: no command specified")
		return 127
	}

	id := w.jailID()
	init, c, err := w.prepareCell(id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 127
	}
	if c != nil {
		defer func() { _ = c.Cleanup() }()
	}
	if w.opts.Image != "" {

		defer w.releaseImageContainer(id)
	}

	rec := w.newRecord(init, id)
	le := w.openLedger()
	w.log = newLogger(w.opts.Debug, os.Stderr, le)
	w.save(le, rec)
	w.log.info("jail.create", rec.ID, "jail created", map[string]any{
		"command": strings.Join(init.Args, " "),
		"rootfs":  init.Rootfs,
		"image":   w.opts.Image,
		"network": w.opts.Network,
	})

	return w.supervise(ctx, init, rec, le)
}

func (w *Warden) jailID() string {
	if w.opts.ID != "" {
		return w.opts.ID
	}
	return string(jail.NewID())
}

func (w *Warden) prepareCell(id string) (*jail.InitConfig, *cell.Cell, error) {
	init := w.buildInit()
	if w.opts.Image != "" {
		if init.Rootfs != "" {
			return nil, nil, fmt.Errorf("warden: rootfs and image are mutually exclusive")
		}
		is, err := image.Open(w.ledgerDir())
		if err != nil {
			return nil, nil, fmt.Errorf("warden: open image store: %w", err)
		}
		m, _, err := is.Assemble(id, w.opts.Image, init.ReadOnly)
		if err != nil {
			return nil, nil, err
		}
		init.Rootfs = m.Rootfs
		return init, nil, nil
	}
	var c *cell.Cell
	if init.Rootfs != "" {
		cc, err := cell.New(init.Rootfs, init.ReadOnly)
		if err == nil {
			err = cc.Validate()
		}
		if err != nil {
			return nil, nil, err
		}
		init.Rootfs = cc.Root
		c = cc
	}
	return init, c, nil
}

func (w *Warden) releaseImageContainer(id string) {
	is, err := image.Open(w.ledgerDir())
	if err != nil {
		if w.opts.Debug {
			fmt.Fprintf(os.Stderr, "warden: open image store for cleanup: %v\n", err)
		}
		return
	}
	_ = is.Disassemble(id)
	if err := is.Delete(id); err != nil && w.opts.Debug {
		fmt.Fprintf(os.Stderr, "warden: release image container %s: %v\n", id, err)
	}
}

func (w *Warden) newRecord(init *jail.InitConfig, ident string) *ledger.Record {
	rec := &ledger.Record{
		ID:           ident,
		CreatedAt:    time.Now(),
		State:        ledger.StateCreated,
		WorkDir:      w.opts.WorkDir,
		Network:      w.opts.Network,
		Userns:       w.opts.Userns,
		ReadOnly:     init.ReadOnly,
		Seccomp:      init.Seccomp,
		Capabilities: append([]string(nil), init.Capabilities...),
		Env:          append([]string(nil), w.opts.Env...),
		Memory:       w.opts.Memory,
		CPUs:         w.opts.CPUs,
		Pids:         w.opts.PIDs,
	}
	if len(init.Args) > 0 {
		rec.Command = init.Args[0]
		rec.Args = append([]string(nil), init.Args...)
	}
	rec.Hostname = init.Hostname
	rec.Rootfs = init.Rootfs
	rec.Image = w.opts.Image
	if w.opts.Config != nil {
		cp := *w.opts.Config
		rec.Config = &cp
	}
	return rec
}

func (w *Warden) supervise(ctx context.Context, init *jail.InitConfig, rec *ledger.Record, le *ledger.Ledger) int {
	if report, err := w.compileSecurity(init); err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		w.log.err("policy.failed", rec.ID, "security policy could not be admitted", map[string]any{"error": err.Error()})
		if report != nil {
			rec.Policy = report
			w.save(le, rec)
		}
		w.finish(le, rec, 127, "policy unavailable")
		return 127
	} else if report != nil {
		rec.Policy = report
		w.save(le, rec)
	}

	opts := jail.SpawnOpts{
		Init:       *init,
		Namespaces: w.bars(),
		Cwd:        w.opts.Dir,
		Stdin:      w.opts.Stdin,
		Stdout:     w.opts.Stdout,
		Stderr:     w.opts.Stderr,
		Env:        w.opts.Env,
	}

	if w.useUserns() {
		opts.Userns = true
		opts.UidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Geteuid(), Size: 1},
		}
		opts.GidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getegid(), Size: 1},
		}
	}

	child, err := jail.Spawn(opts, init)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		w.log.err("spawn.failed", rec.ID, "prisoner spawn failed", map[string]any{"error": err.Error()})
		w.finish(le, rec, 127, "spawn failed")
		return 127
	}
	defer child.Close()

	if err := child.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		w.log.err("start.failed", rec.ID, "prisoner start failed", map[string]any{"error": err.Error()})
		w.finish(le, rec, 127, "start failed")
		return 127
	}
	rec.Pid = child.PID()
	rec.State = ledger.StateRunning
	rec.ExitCode = 0
	rec.Result = ""
	w.save(le, rec)
	for _, b := range w.bars() {
		w.log.info("bars.install", rec.ID, "installed namespace bar", map[string]any{"bar": b.String()})
	}
	w.log.info("prisoner.init", rec.ID, "jail init admitted", map[string]any{"pid": rec.Pid})

	cg, rErr := w.installRations(rec)
	if rErr != nil {
		fmt.Fprintln(os.Stderr, rErr)
		w.log.err("rations.failed", rec.ID, "rations could not be installed", map[string]any{"error": rErr.Error()})

		child.Kill()
		child.Wait()
		w.finish(le, rec, 127, "rations failed")
		return 127
	}
	if cg != nil {
		defer func() {
			if err := cg.Remove(); err != nil && w.opts.Debug {
				fmt.Fprintf(os.Stderr, "warden: release rations: %v\n", err)
			}
		}()
		w.log.info("rations.install", rec.ID, "rations installed", map[string]any{
			"path": cg.Path, "memory": rec.Memory, "cpu": rec.CPUs, "pids": rec.Pids,
		})
	}

	gt, err := w.buildGate(rec.ID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		w.log.err("gate.failed", rec.ID, "gate could not be configured", map[string]any{"error": err.Error()})
		child.Kill()
		child.Wait()
		w.finish(le, rec, 127, "gate failed")
		return 127
	}
	if gt != nil {
		if err := gt.Setup(rec.ID, child.PID()); err != nil {
			fmt.Fprintln(os.Stderr, "warden:", err)
			w.log.err("gate.failed", rec.ID, "gate could not be installed", map[string]any{"error": err.Error()})
			child.Kill()
			child.Wait()
			w.finish(le, rec, 127, "gate failed")
			return 127
		}
		rec.VethHost = gt.VethHost
		rec.GateIP = gt.IP
		rec.Gateway = gt.Gateway
		rec.Bridge = gt.Bridge
		rec.NetworkName = gt.Name
		rec.Ports = hostPortSpecs(gt.Ports)
		w.configureDNS(le, rec, gt)
		w.save(le, rec)
		w.log.info("gate.install", rec.ID, "gate installed", map[string]any{
			"mode": w.opts.Network, "ip": gt.IP, "veth": gt.VethHost, "ports": rec.Ports,
		})

		defer func() {
			gt.Teardown(rec.ID)
			w.releaseGateIP(gt)
			w.log.info("gate.release", rec.ID, "gate released", nil)
		}()
	}

	if init.ReadOnly {
		w.log.info("cell.readonly", rec.ID, "cell mounted read-only", nil)
	}
	if init.Seccomp {
		w.log.info("security.seccomp", rec.ID, "seccomp filter enabled", nil)
	}
	if len(init.Capabilities) > 0 {
		w.log.info("security.caps", rec.ID, "capabilities applied", map[string]any{
			"caps": strings.Join(init.Capabilities, ","),
		})
	}

	if err := child.Release(); err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		w.log.err("release.failed", rec.ID, "prisoner release failed", map[string]any{"error": err.Error()})
		child.Wait()
		w.finish(le, rec, 1, "release failed")
		return 1
	}
	w.log.debug("prisoner.release", rec.ID, "prisoner released to exec", nil)

	sigs := w.opts.Signals
	if len(sigs) == 0 {
		sigs = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP}
	}
	sigCh := make(chan os.Signal, 16)
	signal.Notify(sigCh, sigs...)
	defer signal.Stop(sigCh)

	stopForwarding := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigCh:
				if sig == nil || child.Signal(sig) != nil {
					return
				}
			case <-stopForwarding:
				return
			}
		}
	}()

	result := make(chan int, 1)
	go func() { result <- child.Wait() }()

	readyCh := make(chan error, 1)
	go func() { readyCh <- child.ReadReady() }()

	if err := <-readyCh; err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		w.log.err("init.failed", rec.ID, "jail init failed", map[string]any{"error": err.Error()})
		signal.Stop(sigCh)
		close(stopForwarding)
		code := <-result
		w.finish(le, rec, code, "init failed")
		return code
	}
	w.log.info("cell.prepare", rec.ID, "cell prepared", nil)

	rec.PrisonerPID = jail.FindPrisonerHostPID(child.PID())
	if rec.PrisonerPID > 0 {
		w.save(le, rec)
	}
	w.log.info("prisoner.admit", rec.ID, "prisoner admitted", map[string]any{
		"pid": rec.PrisonerPID, "init": child.PID(),
	})

	select {
	case code := <-result:
		signal.Stop(sigCh)
		close(stopForwarding)
		w.finish(le, rec, code, resultReason(code))
		w.log.info("prisoner.exit", rec.ID, "prisoner sentence ended", map[string]any{
			"code": code, "reason": resultReason(code),
		})
		return code
	case <-ctx.Done():
		_ = child.Signal(syscall.SIGKILL)
		signal.Stop(sigCh)
		close(stopForwarding)
		code := <-result
		w.finish(le, rec, code, "interrupted")
		w.log.info("prisoner.terminate", rec.ID, "prisoner terminated", map[string]any{"code": code})
		return code
	}
}

func (w *Warden) ledgerDir() string {
	if w.opts.LedgerDir != "" {
		return w.opts.LedgerDir
	}
	return ledger.DefaultDir()
}

func (w *Warden) openLedger() *ledger.Ledger {
	l, err := ledger.New(w.ledgerDir())
	if err != nil {
		if w.opts.Debug {
			fmt.Fprintf(os.Stderr, "warden: ledger unavailable: %v\n", err)
		}
		return nil
	}
	return l
}

func (w *Warden) save(le *ledger.Ledger, rec *ledger.Record) {
	if le == nil || rec == nil {
		return
	}
	_ = le.Set(*rec)
}

func (w *Warden) finish(le *ledger.Ledger, rec *ledger.Record, code int, result string) {
	if rec == nil {
		return
	}
	rec.State = ledger.StateStopped
	rec.ExitCode = code
	rec.Result = result
	w.save(le, rec)
}

func resultReason(code int) string {
	if code == 0 {
		return "completed"
	}
	if code > 128 {
		return fmt.Sprintf("signal (%d)", code-128)
	}
	return fmt.Sprintf("exit (%d)", code)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return ws.ExitStatus()
		}
		return ee.ExitCode()
	}
	return 1
}

func (w *Warden) buildGate(id string) (*gate.Gate, error) {
	mode := w.opts.Network
	if mode == "" || mode == "none" {
		return nil, nil
	}
	name := mode
	if name == "bridge" {
		name = network.DefaultName
	}
	nm, err := network.Open(w.ledgerDir())
	if err != nil {
		return nil, fmt.Errorf("network: %w", err)
	}
	n, err := nm.Get(name)
	if errors.Is(err, os.ErrNotExist) && name == network.DefaultName {
		n, err = nm.Default()
	}
	if err != nil {
		return nil, fmt.Errorf("network %q: %w", mode, err)
	}
	host, err := nm.Allocate(name)
	if err != nil {
		return nil, fmt.Errorf("network %q: %w", name, err)
	}
	ports, perr := parseHostPorts(w.opts.Ports)
	if perr != nil {
		_ = nm.Release(name, host)
		return nil, perr
	}
	gt := &gate.Gate{
		Mode:   gate.ModeBridge,
		Bridge: n.Bridge,
		Name:   n.Name,
		Ports:  ports,
	}
	if err := gt.Assign(n.CIDR(host), n.GatewayCIDR()); err != nil {
		_ = nm.Release(name, host)
		return nil, err
	}
	_ = id
	return gt, nil
}

func (w *Warden) releaseGateIP(gt *gate.Gate) {
	if gt == nil || !gt.Managed || gt.Name == "" {
		return
	}
	addr, _, err := net.ParseCIDR(gt.IP)
	if err != nil {
		return
	}
	nm, err := network.Open(w.ledgerDir())
	if err != nil {
		return
	}
	_ = nm.Release(gt.Name, addr.String())
}

func (w *Warden) configureDNS(le *ledger.Ledger, rec *ledger.Record, gt *gate.Gate) {
	if gt == nil || gt.Mode != gate.ModeBridge {
		return
	}
	servers := w.opts.DNS
	if len(servers) == 0 {
		servers = hostNameservers()
	}
	rec.DNS = servers
	if rec.Rootfs != "" && rec.Rootfs != "/" {
		var buf strings.Builder
		for _, s := range servers {
			if net.ParseIP(s) == nil {
				continue
			}
			buf.WriteString("nameserver " + s + "\n")
		}
		if buf.Len() > 0 {
			dir := filepath.Join(rec.Rootfs, "etc")
			if err := os.MkdirAll(dir, 0o755); err == nil {
				_ = os.WriteFile(filepath.Join(dir, "resolv.conf"), []byte(buf.String()), 0o644)
			}
		}
	}
}

func hostNameservers() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if f := strings.Fields(line); len(f) == 2 && f[0] == "nameserver" {
			if net.ParseIP(f[1]) != nil {
				out = append(out, f[1])
			}
		}
	}
	return out
}

func parseHostPorts(specs []string) ([]gate.Port, error) {
	var out []gate.Port
	for _, spec := range specs {
		host, guest, ok := strings.Cut(spec, ":")
		if !ok {
			return nil, fmt.Errorf("port %q: want HOST:GUEST", spec)
		}
		hp, err := strconv.Atoi(host)
		if err != nil {
			return nil, fmt.Errorf("port %q: host: %w", spec, err)
		}
		gp, err := strconv.Atoi(guest)
		if err != nil {
			return nil, fmt.Errorf("port %q: guest: %w", spec, err)
		}
		out = append(out, gate.Port{Host: hp, Guest: gp})
	}
	return out, nil
}

func hostPortSpecs(ps []gate.Port) []string {
	if len(ps) == 0 {
		return nil
	}
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%d:%d", p.Host, p.Guest))
	}
	return out
}
