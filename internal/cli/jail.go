package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"jailor/internal/api"
	jailorcfg "jailor/internal/config"
	"jailor/internal/gate"
	"jailor/internal/jail"
	"jailor/internal/ledger"
	"jailor/internal/prisoner"
	"jailor/internal/rations"
	"jailor/internal/warden"
)

func (r *Root) jail(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(r.Err, "Usage: jailor jail <create|run|start|stop|kill|delete|list|inspect> [flags] [id] [command]")
		return 1
	}
	switch args[0] {
	case "create":
		return r.jailCreate(args[1:])
	case "run":
		return r.run(args[1:])
	case "start":
		return r.jailStart(args[1:])
	case "stop":
		return r.jailStop(args[1:])
	case "kill":
		return r.jailKill(args[1:])
	case "delete":
		return r.jailDelete(args[1:])
	case "list":
		return r.jailList(args[1:])
	case "inspect":
		return r.jailInspect(args[1:])
	case "stats":
		return r.jailStats(args[1:])
	default:
		fmt.Fprintln(r.Err, "jailor: unknown jail subcommand", args[0])
		fmt.Fprintln(r.Err, "Usage: jailor jail <create|run|start|stop|kill|delete|list|inspect|stats>")
		return 1
	}
}

func (r *Root) openLedger(dir string) (*ledger.Ledger, error) {
	if dir == "" {
		dir = ledger.DefaultDir()
	}
	return ledger.New(dir)
}

func (r *Root) resolveRecord(dir, id string) (*ledger.Record, error) {
	l, err := r.openLedger(dir)
	if err != nil {
		return nil, err
	}
	return l.Find(id)
}

func (r *Root) listRecords(dir string) ([]ledger.Record, error) {
	l, err := r.openLedger(dir)
	if err != nil {
		return nil, err
	}
	if _, err := l.Recover(); err != nil {
		return nil, err
	}
	return l.List()
}

func (r *Root) jailList(args []string) int {
	fs := flagSet("jailor jail list", r.Err)
	ledgerDir := fs.String("ledger", "", "ledger directory (default: JAILOR_LEDGER or per-user)")
	socket := fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		out, aerr := c.List()
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		renderJailTable(r, out.Records)
		return 0
	}
	l, err := r.openLedger(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	recovered, err := l.Recover()
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	recs, err := l.List()
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	w := warden.New(warden.Options{LedgerDir: *ledgerDir})
	orphans := w.SweepCgroups(recs)
	runningIDs := make(map[string]bool, len(recs))
	for i := range recs {
		if recs[i].State == ledger.StateRunning {
			runningIDs[recs[i].ID] = true
		}
	}
	vethCleaned := gate.Sweep(runningIDs)
	renderJailTable(r, recs)
	if recovered > 0 {
		fmt.Fprintf(r.Out, "%d stale jail record(s) recovered to STOPPED\n", recovered)
	}
	if orphans > 0 {
		fmt.Fprintf(r.Out, "%d orphaned Rations cgroup(s) released\n", orphans)
	}
	if vethCleaned > 0 {
		fmt.Fprintf(r.Out, "%d orphaned Gate veth(s) released\n", vethCleaned)
	}
	return 0
}

func renderJailTable(r *Root, recs []ledger.Record) {
	tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATE\tPID\tHOSTNAME\tCOMMAND\tRESTARTS\tFAILURES\tCREATED")
	fmt.Fprintln(tw, "-\t-----\t---\t--------\t-------\t--------\t--------\t-------")
	for _, rec := range recs {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%d\t%d\t%s\n",
			ledger.Short(rec.ID), rec.State, rec.Pid, rec.Hostname, rec.Command,
			rec.Restarts, rec.Failures, rec.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	tw.Flush()
}

func (r *Root) jailInspect(args []string) int {
	fs := flagSet("jailor jail inspect", r.Err)
	ledgerDir := fs.String("ledger", "", "ledger directory (default: JAILOR_LEDGER or per-user)")
	socket := fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(r.Err, "Usage: jailor jail inspect [--ledger <dir>] <id>")
		return 1
	}
	id := rest[0]
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		out, aerr := c.Inspect(id)
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		renderInspect(r, &out.Record, out.StorageBytes)
		return 0
	}
	l, err := r.openLedger(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	rec, err := l.Find(id)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}

	if rec.State == ledger.StateRunning && !ledger.ProcessAlive(rec.Pid) {
		rec.State = ledger.StateStopped
		rec.Result = "recovered: prisoner no longer running"
		if rec.ExitCode == 0 {
			rec.ExitCode = -1
		}
		_ = l.Set(*rec)
	}
	renderInspect(r, rec, l.Usage(rec.ID))
	return 0
}

func renderInspect(r *Root, rec *ledger.Record, storageBytes int64) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "ID             %s\n", rec.ID)
	fmt.Fprintf(&sb, "State          %s\n", rec.State)
	fmt.Fprintf(&sb, "Init PID       %d\n", rec.Pid)
	if rec.PrisonerPID > 0 {
		fmt.Fprintf(&sb, "Prisoner PID   %d\n", rec.PrisonerPID)
	}
	fmt.Fprintf(&sb, "Command        %s\n", rec.Command)
	if len(rec.Args) > 1 {
		fmt.Fprintf(&sb, "Args           %s\n", strings.Join(rec.Args[1:], " "))
	}
	if rec.Hostname != "" {
		fmt.Fprintf(&sb, "Hostname       %s\n", rec.Hostname)
	}
	if rec.Rootfs != "" {
		fmt.Fprintf(&sb, "Rootfs         %s\n", rec.Rootfs)
	}
	if rec.Image != "" {
		fmt.Fprintf(&sb, "Image          %s\n", rec.Image)
	}
	if len(rec.Env) > 0 {
		fmt.Fprintf(&sb, "Env            %s\n", strings.Join(rec.Env, " "))
	}
	fmt.Fprintf(&sb, "Exit Code      %d\n", rec.ExitCode)
	if rec.Result != "" {
		fmt.Fprintf(&sb, "Result         %s\n", rec.Result)
	}
	if rec.Restarts > 0 {
		fmt.Fprintf(&sb, "Restarts       %d\n", rec.Restarts)
	}
	if rec.Failures > 0 {
		fmt.Fprintf(&sb, "Failures       %d\n", rec.Failures)
	}
	if storageBytes > 0 {
		fmt.Fprintf(&sb, "Storage        %s\n", rations.HumanBytes(storageBytes))
	}
	if rec.Memory > 0 {
		fmt.Fprintf(&sb, "Memory Rations %s\n", rations.HumanBytes(rec.Memory))
	}
	if rec.CPUs > 0 {
		fmt.Fprintf(&sb, "CPU Rations    %.2f CPUs\n", rec.CPUs)
	}
	if rec.Pids > 0 {
		fmt.Fprintf(&sb, "PIDs Rations   %d\n", rec.Pids)
	}
	if rec.Network != "" {
		fmt.Fprintf(&sb, "Gate Mode      %s\n", rec.Network)
	}
	if rec.GateIP != "" {
		fmt.Fprintf(&sb, "Gate IP        %s\n", rec.GateIP)
	}
	if rec.Gateway != "" {
		fmt.Fprintf(&sb, "Gateway        %s\n", rec.Gateway)
	}
	if rec.VethHost != "" {
		fmt.Fprintf(&sb, "Veth Host      %s\n", rec.VethHost)
	}
	fmt.Fprintf(&sb, "Created        %s\n", rec.CreatedAt.Format(time.RFC3339))
	if rec.Config != nil {
		fmt.Fprintf(&sb, "Config Version %d\n", rec.Config.Version)
	}
	if rec.Policy != nil {
		p := rec.Policy
		if p.Unavailable != nil {
			fmt.Fprintf(&sb, "Policy         unavailable: %s\n", p.Unavailable)
		} else if p.AllApplied() {
			fmt.Fprintf(&sb, "Policy         applied\n")
		} else {
			fmt.Fprintf(&sb, "Policy         partial\n")
		}
		if p.UsernsMode != "" {
			fmt.Fprintf(&sb, "Userns         %s (applied=%v)\n", p.UsernsMode, p.UsernsApplied)
		}
		if p.SeccompProfile != "" {
			fmt.Fprintf(&sb, "Seccomp        %s (applied=%v)\n", p.SeccompProfile, p.SeccompApplied)
		}
		if p.NoNewPrivsApplied {
			fmt.Fprintf(&sb, "NoNewPrivs     on\n")
		}
		if len(p.Capabilities) > 0 {
			fmt.Fprintf(&sb, "Capabilities   %s\n", strings.Join(p.Capabilities, ","))
		}
		if p.ReadOnlyApplied {
			fmt.Fprintf(&sb, "ReadOnly       on\n")
		}
		if p.LSM != "" {
			fmt.Fprintf(&sb, "LSM            %s (applied=%v)\n", p.LSM, p.LsmApplied)
		}
	}
	fmt.Fprint(r.Out, sb.String())
}

func (r *Root) jailCreate(args []string) int {
	fs := flagSet("jailor jail create", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor jail create [flags] <command> [args...]

Create a Jail without admitting a Prisoner. Start it later with
"jailor jail start <id>".

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		hostname  = fs.String("hostname", "", "set the Jail UTS hostname")
		rootfs    = fs.String("rootfs", "", "root filesystem for the Cell")
		image     = fs.String("image", "", "local image to assemble the Cell rootfs from (mutually exclusive with --rootfs)")
		workdir   = fs.String("workdir", "/", "working directory inside the Cell")
		network   = fs.String("network", "none", "network isolation: none or bridge")
		userns    = fs.String("userns", "auto", "user namespace: auto, on, off")
		readOnly  = fs.Bool("read-only", false, "make the Cell read-only")
		seccomp   = fs.Bool("seccomp", false, "enable the default seccomp syscall filter")
		caps      = fs.String("caps", "", "comma-separated capabilities to keep (default: conservative shell set)")
		env       = fs.String("env", "", "comma-separated environment KEY=VALUE entries")
		memory    = fs.String("memory", "", "memory rations: bytes or 512K/256M/1G (0 = unlimited)")
		cpu       = fs.Float64("cpu", 0, "CPU rations in CPUs (fractional allowed, 0 = unlimited)")
		pids      = fs.Int64("pids", 0, "process count rations (0 = unlimited)")
		config    = fs.String("config", "", "path to a versioned Jail configuration file")
		ledgerDir = fs.String("ledger", "", "ledger directory for Jail records (default: JAILOR_LEDGER or per-user)")
		socket    = fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
		debug     = fs.Bool("debug", false, "verbose Warden logging on stderr")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()

	base, err := loadConfig(r, *config)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 2
	}
	if len(rest) == 0 && (base == nil || len(base.Command) == 0) {
		fs.Usage()
		return 2
	}
	opts, err := configOptions(base)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 2
	}
	opts.LedgerDir = *ledgerDir
	opts.Debug = *debug

	set := changedFlags(fs)
	var validErr error
	opt(set, "network", func() { opts.Network = *network })
	opt(set, "hostname", func() { opts.Hostname = *hostname })
	opt(set, "rootfs", func() { opts.Rootfs = *rootfs })
	opt(set, "image", func() { opts.Image = *image })
	opt(set, "workdir", func() { opts.WorkDir = *workdir })
	opt(set, "userns", func() { opts.Userns = *userns })
	opt(set, "read-only", func() { opts.ReadOnly = *readOnly })
	opt(set, "seccomp", func() { opts.Seccomp = *seccomp })
	opt(set, "caps", func() { opts.Capabilities = jailorcfg.ResolveCaps(*caps) })
	opt(set, "env", func() { opts.Env = splitList(*env) })
	if set["env"] {
		for _, e := range opts.Env {
			k, _, ok := strings.Cut(e, "=")
			if !ok || k == "" {
				validErr = fmt.Errorf("--env: %q is not KEY=VALUE", e)
				break
			}
		}
	}
	opt(set, "memory", func() {
		if mem, e := rations.ParseMemory(*memory); e != nil {
			validErr = fmt.Errorf("--memory: %w", e)
		} else {
			opts.Memory = mem
		}
	})
	opt(set, "cpu", func() {
		if *cpu < 0 {
			validErr = fmt.Errorf("--cpu cannot be negative")
		} else {
			opts.CPUs = *cpu
		}
	})
	opt(set, "pids", func() {
		if *pids < 0 {
			validErr = fmt.Errorf("--pids cannot be negative")
		} else {
			opts.PIDs = *pids
		}
	})
	if validErr != nil {
		fmt.Fprintln(r.Err, "jailor:", validErr)
		return 2
	}
	if _, err = gate.New(opts.Network); err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 2
	}

	if base != nil && len(base.Command) > 0 && len(rest) == 0 {
		opts.Args = base.Command
	} else if len(rest) > 0 {
		opts.Args = rest
	}

	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		id, aerr := c.Create(jailSpecFromOptions(opts))
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		fmt.Fprintln(r.Out, id)
		return 0
	}

	w := warden.New(opts)
	rec, err := w.Create()
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 127
	}
	fmt.Fprintln(r.Out, rec.ID)
	return 0
}

func (r *Root) jailStart(args []string) int {
	fs := flagSet("jailor jail start", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor jail start [flags] <id>

Admit the Prisoner of an existing Jail and supervise its Sentence.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		ledgerDir = fs.String("ledger", "", "ledger directory for Jail records (default: JAILOR_LEDGER or per-user)")
		socket    = fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
		debug     = fs.Bool("debug", false, "verbose Warden logging on stderr")
		stdin     = fs.String("stdin", "inherit", "stdin source: inherit, /dev/null, or a file path")
		stdout    = fs.String("stdout", "inherit", "stdout destination: inherit, /dev/null, or a file path")
		stderr    = fs.String("stderr", "inherit", "stderr destination: inherit, /dev/null, or a file path")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 1
	}
	id := rest[0]

	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		code, aerr := c.Start(id)
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		return code
	}

	in, out, errOut, err := streams(*stdin, *stdout, *stderr)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 2
	}
	w := warden.New(warden.Options{
		Stdin:     in,
		Stdout:    out,
		Stderr:    errOut,
		LedgerDir: *ledgerDir,
		Debug:     *debug,
	})
	return w.Start(context.Background(), id)
}

func (r *Root) jailStop(args []string) int {
	fs := flagSet("jailor jail stop", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor jail stop [flags] <id>

Stop a RUNNING Jail by forwarding SIGTERM to its Prisoner.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		ledgerDir = fs.String("ledger", "", "ledger directory for Jail records (default: JAILOR_LEDGER or per-user)")
		socket    = fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
		debug     = fs.Bool("debug", false, "verbose Warden logging on stderr")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 1
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		code, aerr := c.Stop(rest[0])
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		return code
	}
	w := warden.New(warden.Options{LedgerDir: *ledgerDir, Debug: *debug})
	return w.Stop(rest[0])
}

func (r *Root) jailKill(args []string) int {
	fs := flagSet("jailor jail kill", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor jail kill [flags] <id>

Force a RUNNING Jail to end by sending SIGKILL to its Prisoner.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		ledgerDir = fs.String("ledger", "", "ledger directory for Jail records (default: JAILOR_LEDGER or per-user)")
		socket    = fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
		debug     = fs.Bool("debug", false, "verbose Warden logging on stderr")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 1
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		code, aerr := c.Kill(rest[0])
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		return code
	}
	w := warden.New(warden.Options{LedgerDir: *ledgerDir, Debug: *debug})
	return w.Kill(rest[0])
}

func (r *Root) jailDelete(args []string) int {
	fs := flagSet("jailor jail delete", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor jail delete [flags] <id>

Delete a Jail (CREATED or STOPPED) and release its Ledger record. A RUNNING
Jail must be stopped or killed first.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		ledgerDir = fs.String("ledger", "", "ledger directory for Jail records (default: JAILOR_LEDGER or per-user)")
		socket    = fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
		debug     = fs.Bool("debug", false, "verbose Warden logging on stderr")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 1
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		if aerr := c.Remove(rest[0]); aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		return 0
	}
	w := warden.New(warden.Options{LedgerDir: *ledgerDir, Debug: *debug})
	return w.Delete(rest[0])
}

func (r *Root) jailStats(args []string) int {
	fs := flagSet("jailor jail stats", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor jail stats [flags] <id>

Report a Jail's Rations from its cgroup: memory usage, CPU usage, and the
process count. Rations are released when the Sentence ends, so stats are only
available while a Prisoner is RUNNING.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		ledgerDir = fs.String("ledger", "", "ledger directory for Jail records (default: JAILOR_LEDGER or per-user)")
		socket    = fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 1
	}
	id := rest[0]
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		out, aerr := c.Stats(id)
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		renderStats(r, id, out)
		return 0
	}

	l, err := r.openLedger(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	rec, err := l.Find(id)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}

	cg, err := rations.FindJailCgroup(rec.ID)
	if err != nil || !cg.Exists() {
		fmt.Fprintf(r.Out, "jail %s has no Rations allocated (no cgroup; limits are released when the Sentence ends)\n", ledger.Short(id))
		return 0
	}
	st, err := cg.Stats()
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	renderRations(r, id, rec.State, st.MemoryCurrent, st.MemoryMax, st.CPUUsageUsec, st.CPUQuotaUsec, st.CPUPeriodUsec, st.PIDsCurrent, st.PIDsMax)
	return 0
}

func renderRations(r *Root, id, state string, memCur, memMax, cpuUsec, cpuQuota, cpuPeriod, pidsCur, pidsMax int64) {
	fmt.Fprintf(r.Out, "Jail           %s\n", ledger.Short(id))
	fmt.Fprintf(r.Out, "State          %s\n", state)
	fmt.Fprintf(r.Out, "Memory         %s / %s\n", rations.HumanBytes(memCur), rations.HumanBytes(memMax))
	fmt.Fprintf(r.Out, "CPU used       %.3f s\n", float64(cpuUsec)/1e6)
	if cpuQuota > 0 {
		fmt.Fprintf(r.Out, "CPU limit      %.2f CPUs (%d/%d usec)\n",
			float64(cpuQuota)/float64(cpuPeriod), cpuQuota, cpuPeriod)
	} else {
		fmt.Fprintln(r.Out, "CPU limit      unlimited")
	}
	fmt.Fprintf(r.Out, "Prisoners      %d / %d\n", pidsCur, pidsMax)
}

func renderStats(r *Root, id string, out api.RationsStats) {
	renderRations(r, id, out.State, out.MemoryCurrent, out.MemoryMax, out.CPUUsageUsec, out.CPUQuotaUsec, out.CPUPeriodUsec, out.PIDsCurrent, out.PIDsMax)
}

func (r *Root) prisoner(args []string) int {
	if len(args) == 0 {
		return r.prisonerUsage()
	}
	switch args[0] {
	case "exec", "e":
		return r.prisonerExec(args[1:])
	case "attach", "a":
		return r.prisonerAttach(args[1:])
	case "list", "l":
		return r.prisonerList(args[1:])
	case "logs":
		return r.prisonerLogs(args[1:])
	case "stats":
		return r.prisonerStats(args[1:])
	default:
		fmt.Fprintf(r.Err, "jailor: unknown prisoner command %q\n", args[0])
		return r.prisonerUsage()
	}
}

func (r *Root) prisonerExec(args []string) int {
	fs := flagSet("prisoner exec", r.Err)
	ledgerDir := fs.String("ledger", "", "ledger directory (default: JAILOR_LEDGER or per-user)")
	fs.Usage = func() {
		fmt.Fprint(r.Err, "Usage: jailor prisoner exec [flags] <id> <command> [args...]\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) < 2 {
		fs.Usage()
		return 2
	}
	rec, err := r.resolveRecord(*ledgerDir, rest[0])
	if err != nil {
		fmt.Fprintf(r.Err, "prisoner: %v\n", err)
		return 1
	}
	if rec.State != ledger.StateRunning || rec.Pid <= 0 {
		fmt.Fprintf(r.Err, "prisoner: jail %s is not running; cannot exec\n", ledger.Short(rec.ID))
		return 1
	}

	cfg := jail.InitConfig{
		Rootfs:       rec.Rootfs,
		WorkDir:      rec.WorkDir,
		Hostname:     rec.Hostname,
		Args:         rest[1:],
		MountProc:    true,
		MountTmp:     true,
		MountDev:     true,
		Seccomp:      rec.Seccomp,
		Capabilities: append([]string(nil), rec.Capabilities...),
	}
	if err := prisoner.Enter(prisoner.SpawnOptions{
		Pid:    rec.Pid,
		Init:   cfg,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}); err != nil {
		fmt.Fprintf(r.Err, "prisoner: %v\n", err)
		return 1
	}
	return 0
}

func (r *Root) prisonerAttach(args []string) int {
	fs := flagSet("prisoner attach", r.Err)
	ledgerDir := fs.String("ledger", "", "ledger directory (default: JAILOR_LEDGER or per-user)")
	fs.Usage = func() {
		fmt.Fprint(r.Err, "Usage: jailor prisoner attach [flags] <id> [command] [args...]\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fs.Usage()
		return 2
	}
	rec, err := r.resolveRecord(*ledgerDir, rest[0])
	if err != nil {
		fmt.Fprintf(r.Err, "prisoner: %v\n", err)
		return 1
	}
	if rec.State != ledger.StateRunning || rec.Pid <= 0 {
		fmt.Fprintf(r.Err, "prisoner: jail %s is not running; cannot attach\n", ledger.Short(rec.ID))
		return 1
	}

	cmd := rest[1:]
	if len(cmd) == 0 {
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		cmd = []string{shell}
	}

	cfg := jail.InitConfig{
		Rootfs:       rec.Rootfs,
		WorkDir:      rec.WorkDir,
		Hostname:     rec.Hostname,
		Args:         cmd,
		MountProc:    true,
		MountTmp:     true,
		MountDev:     true,
		Seccomp:      rec.Seccomp,
		Capabilities: append([]string(nil), rec.Capabilities...),
	}
	if err := prisoner.Enter(prisoner.SpawnOptions{
		Pid:    rec.Pid,
		Init:   cfg,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}); err != nil {
		fmt.Fprintf(r.Err, "prisoner: %v\n", err)
		return 1
	}
	return 0
}

func (r *Root) prisonerList(args []string) int {
	fs := flagSet("prisoner list", r.Err)
	ledgerDir := fs.String("ledger", "", "ledger directory (default: JAILOR_LEDGER or per-user)")
	fs.Usage = func() {
		fmt.Fprint(r.Err, "Usage: jailor prisoner list [flags]\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	w := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintln(w, "JAIL\tPID\tSTATE\tCOMMAND")
	recs, err := r.listRecords(*ledgerDir)
	if err != nil {
		fmt.Fprintf(r.Err, "prisoner: %v\n", err)
		return 1
	}
	for _, rec := range recs {
		if rec.State != ledger.StateRunning {
			continue
		}
		cmd := strings.Join(rec.Args, " ")
		pid := rec.Pid
		if rec.PrisonerPID > 0 {
			pid = rec.PrisonerPID
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", ledger.Short(rec.ID), pid, rec.State, cmd)
	}
	return 0
}

func (r *Root) prisonerUsage() int {
	fmt.Fprint(r.Out, `Prisoner operations:
  jailor prisoner exec <id> <command> [args...]  Exec a command inside a running Jail
  jailor prisoner attach <id> [command] [args...] Attach an interactive shell to a running Jail
  jailor prisoner list                             List running Prisoners
  jailor prisoner logs <id>                        Show the Warden's structured log for a Jail
  jailor prisoner stats <id>                       Show a RUNNING Jail's Rations stats

Run "jailor prisoner <command> --help" for details.
`)
	return 0
}

func (r *Root) prisonerLogs(args []string) int {
	fs := flagSet("prisoner logs", r.Err)
	ledgerDir := fs.String("ledger", "", "ledger directory (default: JAILOR_LEDGER or per-user)")
	socket := fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
	fs.Usage = func() {
		fmt.Fprint(r.Err, "Usage: jailor prisoner logs [flags] <id>\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 2
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		out, aerr := c.Logs(rest[0])
		if aerr != nil {
			fmt.Fprintf(r.Err, "prisoner: %v\n", aerr.Message)
			return exitCodeForError(aerr)
		}
		renderLogs(r, out.ID, out.Events)
		return 0
	}
	rec, err := r.resolveRecord(*ledgerDir, rest[0])
	if err != nil {
		fmt.Fprintf(r.Err, "prisoner: %v\n", err)
		return 1
	}
	l, err := r.openLedger(*ledgerDir)
	if err != nil {
		fmt.Fprintf(r.Err, "prisoner: %v\n", err)
		return 1
	}
	logs, err := l.Logs(rec.ID)
	if err != nil {
		fmt.Fprintf(r.Err, "prisoner: %v\n", err)
		return 1
	}
	renderLogs(r, rec.ID, logs)
	return 0
}

func renderLogs(r *Root, id string, logs []ledger.Log) {
	if len(logs) == 0 {
		fmt.Fprintf(r.Out, "no Warden events recorded for jail %s\n", ledger.Short(id))
		return
	}
	for _, e := range logs {
		fields := ""
		for k, v := range e.Fields {
			fields += fmt.Sprintf(" %s=%v", k, v)
		}
		fmt.Fprintf(r.Out, "%s %s %-9s %s %s%s\n",
			e.Time.Format(time.RFC3339), ledger.Short(e.JailID), e.Level, e.Event, e.Message, fields)
	}
}

func (r *Root) prisonerStats(args []string) int {
	fs := flagSet("prisoner stats", r.Err)
	ledgerDir := fs.String("ledger", "", "ledger directory (default: JAILOR_LEDGER or per-user)")
	socket := fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
	fs.Usage = func() {
		fmt.Fprint(r.Err, "Usage: jailor prisoner stats [flags] <id>\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 2
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		out, aerr := c.Stats(rest[0])
		if aerr != nil {
			fmt.Fprintf(r.Err, "prisoner: %v\n", aerr.Message)
			return exitCodeForError(aerr)
		}
		renderStats(r, rest[0], out)
		return 0
	}
	rec, err := r.resolveRecord(*ledgerDir, rest[0])
	if err != nil {
		fmt.Fprintf(r.Err, "prisoner: %v\n", err)
		return 1
	}

	cg, err := rations.FindJailCgroup(rec.ID)
	if err != nil || !cg.Exists() {
		fmt.Fprintf(r.Out, "jail %s has no Rations allocated (no cgroup)\n", ledger.Short(rec.ID))
		return 0
	}
	st, err := cg.Stats()
	if err != nil {
		fmt.Fprintf(r.Err, "prisoner: %v\n", err)
		return 1
	}
	renderRations(r, rec.ID, rec.State, st.MemoryCurrent, st.MemoryMax, st.CPUUsageUsec, st.CPUQuotaUsec, st.CPUPeriodUsec, st.PIDsCurrent, st.PIDsMax)
	return 0
}
