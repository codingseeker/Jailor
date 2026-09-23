package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func (r *Root) events(args []string) int {
	fs := flagSet("jailor events", r.Err)
	ledgerDir := fs.String("ledger", "", "ledger directory (default: JAILOR_LEDGER or per-user)")
	socket := fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor events [flags]

Stream the engine's lifecycle events (jail.created, jail.started,
jail.stopped, jail.killed, jail.removed, jail.exited, ...) as
newline-delimited JSON. Requires a running jailord daemon: the
events hub lives in the daemon, which is the authoritative owner
of running Jail state.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) > 0 {
		fs.Usage()
		return 2
	}

	c := r.daemonClient(*ledgerDir, *socket)
	if c == nil {
		fmt.Fprintln(r.Err, "jailor: no jailord daemon reachable; lifecycle events require the daemon")
		return 1
	}
	stream, aerr := c.Events()
	if aerr != nil {
		fmt.Fprintln(r.Err, "jailor:", aerr.Message)
		return exitCodeForError(aerr)
	}
	defer stream.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	enc := json.NewEncoder(r.Out)
	for {
		ev, err := stream.Next()
		if err != nil {

			return 0
		}
		if err := enc.Encode(ev); err != nil {
			return 1
		}
		select {
		case <-ctx.Done():
			return 0
		default:
		}
	}
}
