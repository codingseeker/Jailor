package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"jailor/internal/jail"
)

type Root struct {
	Out io.Writer
	Err io.Writer
}

func New() *Root {
	return &Root{Out: os.Stdout, Err: os.Stderr}
}

func (r *Root) Run(args []string) int {
	if len(args) == 0 {
		r.usage()
		return 0
	}

	switch args[0] {
	case "run":
		return r.run(args[1:])
	case jail.InitArg:
		return runInit()
	case jail.StagerArg:
		return jail.RunStager()
	case "__nsenter":
		return jail.RunNSEnter()
	case "__visitor":
		return jail.RunVisitor()
	case "jail", "j":
		return r.jail(args[1:])
	case "image", "img":
		return r.imageCommand(args[1:])
	case "images":
		return r.images(args[1:])
	case "pull":
		return r.pull(args[1:])
	case "push":
		return r.push(args[1:])
	case "network", "net":
		return r.network(args[1:])
	case "inspect", "inspect-image":
		return r.inspect(args[1:])
	case "stats":
		return r.jailStats(args[1:])
	case "oci":
		return r.oci(args[1:])
	case "prisoner", "p":
		return r.prisoner(args[1:])
	case "events":
		return r.events(args[1:])
	case "version", "--version":
		fmt.Fprintln(r.Out, "jailor 0.0.0")
		return 0
	case "help", "--help", "-h":
		r.usage()
		return 0
	default:
		fmt.Fprintf(r.Err, "jailor: unknown command %q\n", args[0])
		r.usage()
		return 1
	}
}
func runInit() int {
	return jail.RunInit()
}

func (r *Root) usage() {
	fmt.Fprint(r.Out, `Jailor - a minimal Linux container runtime

Usage:
  jailor run [flags] <command> [args...]   Create and supervise a Jail in one shot
  jailor jail <subcommand> <id>            Manage Jails (create, start, stop, ...)
  jailor prisoner <subcommand> <id>        Interact with Prisoners (exec, ...)

Commands:
  run       Execute a command inside a Jail
  jail      Jail lifecycle management (create, run, start, stop, kill, delete, list, inspect, stats)
  prisoner  Prisoner operations (exec, attach, list, logs, stats)
  images    List locally stored images
  image     Manage locally stored images (ls, inspect, rm, tag, import, gc)
  pull      Download an image from a registry and store it locally
  push      Upload a local image to a registry
  network   Manage persistent networks (create, ls, inspect, rm)
  inspect   Inspect an image (image <name>) or a Jail (<id>)
  stats     Show a RUNNING Jail's Rations usage (cpu, memory, pids)
  events    Stream lifecycle events as JSON from a running jailord daemon
  version   Print version information

Jail lifecycle:
  jailor jail create <command> [args...]   Define a Jail in state CREATED
  jailor jail start <id>                   Admit its Prisoner and supervise the Sentence
  jailor jail stop <id>                    SIGTERM a RUNNING Prisoner
  jailor jail kill <id>                    SIGKILL a RUNNING Prisoner
  jailor jail delete <id>                  Release a CREATED or STOPPED Jail
  jailor jail list                         List Jails from the Ledger
  jailor jail inspect <id>                 Show one Jail's record
  jailor jail stats <id>                   Show a RUNNING Jail's Rations usage

Observe:
  jailor events                            Stream engine lifecycle events as JSON

Configuration:
  jailor run --config <file> <command>     Run a Jail from a versioned JSON config
  jailor jail create --config <file>       Create a Jail from a versioned JSON config
                                          (explicit CLI flags override the config file)

Images:
  jailor images                            List locally stored images
  jailor image ls                          List locally stored images
  jailor image inspect <name>              Show one image's metadata
  jailor image rm <name>...                Untag and release an image
  jailor image tag <source> <target>       Alias an image under a new tag
  jailor image import [--tag <name>] <dir> Import an OCI image layout
  jailor image gc                          Reclaim unreferenced blobs and layers
  jailor pull [flags] IMAGE                Pull an image from a registry
  jailor push [flags] IMAGE                Push a local image to a registry

Networks:
  jailor network create <name>             Create a persistent network
  jailor network ls                        List persistent networks
  jailor network inspect <name>            Show one network and its allocations
  jailor network rm <name>...              Remove a persistent network

Run "jailor <command> --help" for command details.
`)
}
func (r *Root) usageErr(usage string) {
	fmt.Fprint(r.Err, usage)
}
func flagSet(name string, out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(out)
	return fs
}

func parseArgs(args []string) (flags []string, positional []string) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else {
			positional = append(positional, a)
		}
	}
	return
}
