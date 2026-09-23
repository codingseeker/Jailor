package cli

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"jailor/internal/oci"
	"jailor/internal/warden"
)

func (r *Root) oci(args []string) int {
	if len(args) == 0 {
		r.ociUsage()
		return 0
	}
	switch args[0] {
	case "create", "create_jail":
		return r.ociCreate(args[1:])
	case "start":
		return r.ociStart(args[1:])
	case "delete":
		return r.ociDelete(args[1:])
	case "export":
		return r.ociExport(args[1:])
	case "help", "--help", "-h":
		r.ociUsage()
		return 0
	default:
		fmt.Fprintf(r.Err, "jailor oci: unknown command %q\n", args[0])
		r.ociUsage()
		return 1
	}
}

func (r *Root) ociUsage() {
	fmt.Fprint(r.Out, `OCI runtime-compatibility Jail lifecycle:

A bundle is a directory containing an OCI-shaped config.json plus an optional
rootfs directory. Jailor translates it onto its own Warden model, strictly
rejecting OCI configuration it does not implement rather than ignoring it.

Usage:
  jailor oci create [--bundle DIR]       Create a Jail from a bundle (state CREATED)
  jailor oci start [--bundle DIR] <id>   Admit its Prisoner and supervise the Sentence
  jailor oci delete <id>                 Release a CREATED or STOPPED Jail
  jailor oci export <id>                 Print a Jail's record as an OCI-shaped config.json

The started Jail serves a single Sentence, mirroring OCI create/start/delete.
See docs/compat.md for the compatibility matrix.
`)
}

func (r *Root) ociCreate(args []string) int {
	fs := flagSet("jailor oci create", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor oci create [--bundle DIR] [--id ID]

Create a Jail from an OCI-inspired bundle (config.json + optional rootfs),
leaving it in state CREATED. Start it later with "jailor oci start".
`)
		fs.PrintDefaults()
	}
	var (
		bundle    = fs.String("bundle", ".", "bundle directory")
		id        = fs.String("id", "", "request a specific Jail ID")
		ledgerDir = fs.String("ledger", "", "ledger directory (default: JAILOR_LEDGER or per-user)")
		debug     = fs.Bool("debug", false, "verbose Warden logging on stderr")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	b, err := oci.LoadBundle(*bundle)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor oci:", err)
		return 2
	}

	opts, err := configOptions(b.Config)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor oci:", err)
		return 2
	}
	opts.LedgerDir = *ledgerDir
	opts.Debug = *debug
	if *id != "" {
		opts.ID = *id
	}

	w := warden.New(opts)
	rec, err := w.Create()
	if err != nil {
		fmt.Fprintln(r.Err, "jailor oci:", err)
		return 127
	}
	fmt.Fprintln(r.Out, rec.ID)
	return 0
}

func (r *Root) ociStart(args []string) int {
	fs := flagSet("jailor oci start", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor oci start [flags] <id>

Admit the Prisoner of a CREATED Jail and supervise its Sentence.
`)
		fs.PrintDefaults()
	}
	var (
		ledgerDir = fs.String("ledger", "", "ledger directory (default: JAILOR_LEDGER or per-user)")
		debug     = fs.Bool("debug", false, "verbose Warden logging on stderr")
		stdin     = fs.String("stdin", "inherit", "stdin source: inherit, /dev/null, or a file path")
		stdout    = fs.String("stdout", "inherit", "stdout destination: inherit, /dev/null, or a file path")
		stderr    = fs.String("stderr", "inherit", "stderr destination: inherit, /dev/null, or a file path")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fs.Usage()
		return 2
	}
	in, out, errOut, sErr := streams(*stdin, *stdout, *stderr)
	if sErr != nil {
		fmt.Fprintln(r.Err, "jailor oci:", sErr)
		return 2
	}
	opts := warden.Options{LedgerDir: *ledgerDir, Debug: *debug, Stdin: in, Stdout: out, Stderr: errOut}
	w := warden.New(opts)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return w.Start(ctx, rest[0])
}

func (r *Root) ociDelete(args []string) int {
	fs := flagSet("jailor oci delete", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor oci delete [--ledger DIR] <id>

Release a CREATED or STOPPED Jail.
`)
		fs.PrintDefaults()
	}
	var (
		ledgerDir = fs.String("ledger", "", "ledger directory (default: JAILOR_LEDGER or per-user)")
		debug     = fs.Bool("debug", false, "verbose Warden logging on stderr")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fs.Usage()
		return 2
	}
	opts := warden.Options{LedgerDir: *ledgerDir, Debug: *debug}
	w := warden.New(opts)
	return w.Delete(rest[0])
}

func (r *Root) ociExport(args []string) int {
	fs := flagSet("jailor oci export", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor oci export [--ledger DIR] <id>

Print a Jail's persisted record as an OCI-shaped config.json to stdout.
`)
		fs.PrintDefaults()
	}
	var (
		ledgerDir = fs.String("ledger", "", "ledger directory (default: JAILOR_LEDGER or per-user)")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fs.Usage()
		return 2
	}
	l, err := r.openLedger(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor oci:", err)
		return 127
	}
	rec, err := l.Find(rest[0])
	if err != nil {
		fmt.Fprintln(r.Err, "jailor oci:", err)
		return 127
	}
	if rec.Config == nil {
		fmt.Fprintln(r.Err, "jailor oci: jail has no resolved config to export")
		return 127
	}
	data, err := oci.Export(rec.Config)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor oci:", err)
		return 127
	}
	fmt.Fprint(r.Out, string(data))
	return 0
}
