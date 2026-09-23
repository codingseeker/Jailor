package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	jailorcfg "jailor/internal/config"
	"jailor/internal/gate"
	"jailor/internal/rations"
	"jailor/internal/warden"
)

func (r *Root) run(args []string) int {
	fs := flagSet("jailor run", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor run [flags] <command> [args...]

Run a Prisoner and supervise it until it finishes.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		stdin     = fs.String("stdin", "inherit", "stdin source: inherit, /dev/null, or a file path")
		stdout    = fs.String("stdout", "inherit", "stdout destination: inherit, /dev/null, or a file path")
		stderr    = fs.String("stderr", "inherit", "stderr destination: inherit, /dev/null, or a file path")
		hostname  = fs.String("hostname", "", "set the Jail UTS hostname")
		rootfs    = fs.String("rootfs", "", "root filesystem for the Cell")
		image     = fs.String("image", "", "local image to assemble the Cell rootfs from (mutually exclusive with --rootfs)")
		workdir   = fs.String("workdir", "/", "working directory inside the Cell")
		userns    = fs.String("userns", "auto", "user namespace: auto, on, off")
		network   = fs.String("network", "none", "network isolation: none, bridge, or a named network")
		publish   = fs.String("publish", "", "publish host TCP ports to the Jail (HOST:GUEST[,HOST:GUEST])")
		dns       = fs.String("dns", "", "nameservers for the Jail's resolv.conf (comma-separated)")
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
	opt(set, "publish", func() { opts.Ports = splitList(*publish) })
	opt(set, "dns", func() { opts.DNS = splitList(*dns) })
	opt(set, "hostname", func() { opts.Hostname = *hostname })
	opt(set, "rootfs", func() { opts.Rootfs = *rootfs })
	opt(set, "image", func() { opts.Image = *image })
	opt(set, "workdir", func() { opts.WorkDir = *workdir })
	opt(set, "userns", func() { opts.Userns = *userns })
	opt(set, "read-only", func() { opts.ReadOnly = *readOnly })
	opt(set, "seccomp", func() { opts.Seccomp = *seccomp })
	opt(set, "caps", func() { opts.Capabilities = jailorcfg.ResolveCaps(*caps) })
	opt(set, "env", func() { opts.Env = splitList(*env) })
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
	if set["env"] {
		for _, e := range opts.Env {
			k, _, ok := strings.Cut(e, "=")
			if !ok || k == "" {
				validErr = fmt.Errorf("--env: %q is not KEY=VALUE", e)
				break
			}
		}
	}
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

	in, out, errOut, err := streams(*stdin, *stdout, *stderr)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 2
	}
	opts.Stdin, opts.Stdout, opts.Stderr = in, out, errOut

	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		spec := jailSpecFromOptions(opts)
		spec.WithLogs = true
		res, aerr := c.Run(spec)
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		if res.Result != "" {
			fmt.Fprintln(r.Err, "jailor: "+res.Result)
		}
		return res.ExitCode
	}

	return warden.New(opts).Run(context.Background())
}
func streams(stdin, stdout, stderr string) (in ioReader, out, errOut ioWriter, err error) {
	in = os.Stdin
	out = os.Stdout
	errOut = os.Stderr

	if stdin != "" && stdin != "inherit" {
		var f *os.File
		if stdin == "/dev/null" {
			f, err = os.Open(os.DevNull)
		} else {
			f, err = os.Open(stdin)
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("stdin: %w", err)
		}
		in = f
	}
	if stdout != "" && stdout != "inherit" {
		var f *os.File
		if stdout == "/dev/null" {
			f, err = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		} else {
			f, err = os.Create(stdout)
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("stdout: %w", err)
		}
		out = f
	}
	if stderr != "" && stderr != "inherit" {
		var f *os.File
		if stderr == "/dev/null" {
			f, err = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		} else {
			f, err = os.Create(stderr)
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("stderr: %w", err)
		}
		errOut = f
	}
	return in, out, errOut, nil
}

type ioReader = interface{ Read([]byte) (int, error) }
type ioWriter = interface{ Write([]byte) (int, error) }
