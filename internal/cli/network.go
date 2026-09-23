package cli

import (
	"fmt"
	"text/tabwriter"

	"jailor/internal/api"
	"jailor/internal/ledger"
	"jailor/internal/network"
)

func (r *Root) openNetworks(ledgerDir string) (*network.Manager, error) {
	if ledgerDir == "" {
		ledgerDir = ledger.DefaultDir()
	}
	return network.Open(ledgerDir)
}

func (r *Root) network(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(r.Err, `Usage: jailor network <command>

Manage persistent networks. A Jail joins one with
"jailor run --network <name>" or "jailor jail create --network <name>".

Commands:
  create   Define a persistent network (subnet, gateway, bridge)
  ls       List persistent networks
  inspect  Show one network's configuration and allocations
  rm       Remove a persistent network

Run "jailor network <command> --help" for command details.
`)
		return 0
	}
	switch args[0] {
	case "create":
		return r.networkCreate(args[1:])
	case "ls", "list":
		return r.networkList(args[1:])
	case "inspect":
		return r.networkInspect(args[1:])
	case "rm", "remove", "delete":
		return r.networkRemove(args[1:])
	}
	fmt.Fprintf(r.Err, "jailor: unknown network command %q\n", args[0])
	return 2
}

func (r *Root) networkCreate(args []string) int {
	fs := flagSet("jailor network create", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor network create [flags] <name>

Define a persistent, named network that Jails attach to with
"jailor run --network <name>". Address allocation is persisted under the
state root so concurrent Warden processes cannot collide.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		ledgerDir = fs.String("ledger", "", "state root (default: JAILOR_LEDGER or per-user)")
		socket    = fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
		subnet    = fs.String("subnet", "", "IPv4 subnet (CIDR, default 10.66.0.0/24)")
		gateway   = fs.String("gateway", "", "gateway address (default: first usable host of the subnet)")
		ipv6      = fs.String("ipv6", "", "optional IPv6 subnet (CIDR, modeled but deferred)")
		dns       = fs.String("dns", "", "comma-separated nameservers for Jails on this network")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fs.Usage()
		return 2
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		res, aerr := c.NetworkCreate(api.NetworkParams{Name: rest[0], Subnet: *subnet, Gateway: *gateway, IPv6: *ipv6, DNS: splitList(*dns)})
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		fmt.Fprintf(r.Out, "%s\n", res.Network.ID)
		return 0
	}
	nm, err := r.openNetworks(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	n, err := nm.Create(rest[0], *subnet, *gateway, *ipv6, splitList(*dns))
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	fmt.Fprintf(r.Out, "%s\n", n.ID)
	return 0
}

func (r *Root) networkList(args []string) int {
	fs := flagSet("jailor network ls", r.Err)
	ledgerDir := fs.String("ledger", "", "state root (default: JAILOR_LEDGER or per-user)")
	socket := fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		res, aerr := c.NetworkList()
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		if len(res.Networks) == 0 {
			fmt.Fprintln(r.Out, "no networks yet; create one with 'jailor network create <name>'")
			return 0
		}
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tID\tSUBNET\tGATEWAY\tBRIDGE\tALLOCATED")
		fmt.Fprintln(tw, "----\t--\t------\t-------\t------\t---------")
		for _, n := range res.Networks {
			info, aerr := c.NetworkInspect(n.Name)
			if aerr != nil {
				fmt.Fprintln(r.Err, "jailor:", aerr.Message)
				return exitCodeForError(aerr)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n",
				n.Name, n.ID, n.Subnet, n.Gateway, n.Bridge, len(info.Allocs))
		}
		tw.Flush()
		return 0
	}
	nm, err := r.openNetworks(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	networks, err := nm.List()
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	if len(networks) == 0 {
		fmt.Fprintln(r.Out, "no networks yet; create one with 'jailor network create <name>'")
		return 0
	}
	tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tID\tSUBNET\tGATEWAY\tBRIDGE\tALLOCATED")
	fmt.Fprintln(tw, "----\t--\t------\t-------\t------\t---------")
	for _, n := range networks {
		allocs, err := nm.Allocations(n.Name)
		if err != nil {
			return 1
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n",
			n.Name, n.ID, n.Subnet, n.Gateway, n.Bridge, len(allocs))
	}
	tw.Flush()
	return 0
}

func (r *Root) networkInspect(args []string) int {
	fs := flagSet("jailor network inspect", r.Err)
	ledgerDir := fs.String("ledger", "", "state root (default: JAILOR_LEDGER or per-user)")
	socket := fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(r.Err, "Usage: jailor network inspect [--ledger <dir>] <name>")
		return 1
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		res, aerr := c.NetworkInspect(rest[0])
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		renderNetworkInspect(r, res.Network, res.Allocs)
		return 0
	}
	nm, err := r.openNetworks(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	n, err := nm.Get(rest[0])
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	allocs, err := nm.Allocations(n.Name)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	renderNetworkInspect(r, *n, allocs)
	return 0
}

func renderNetworkInspect(r *Root, n network.Network, allocs []string) {
	fmt.Fprintf(r.Out, "Name        %s\n", n.Name)
	fmt.Fprintf(r.Out, "ID          %s\n", n.ID)
	fmt.Fprintf(r.Out, "Subnet      %s\n", n.Subnet)
	fmt.Fprintf(r.Out, "Gateway     %s\n", n.Gateway)
	if n.IPv6 != "" {
		fmt.Fprintf(r.Out, "IPv6        %s\n", n.IPv6)
	}
	if len(n.DNS) > 0 {
		fmt.Fprintf(r.Out, "DNS         %s\n", joinList(n.DNS))
	}
	fmt.Fprintf(r.Out, "Bridge      %s\n", n.Bridge)
	fmt.Fprintf(r.Out, "Allocated   %d\n", len(allocs))
	for _, a := range allocs {
		fmt.Fprintf(r.Out, "  %s\n", a)
	}
	fmt.Fprintf(r.Out, "Created     %s\n", formatCreated(n.CreatedAt))
}

func (r *Root) networkRemove(args []string) int {
	fs := flagSet("jailor network rm", r.Err)
	ledgerDir := fs.String("ledger", "", "state root (default: JAILOR_LEDGER or per-user)")
	socket := fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(r.Err, "Usage: jailor network rm [--ledger <dir>] <name>...")
		return 1
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		for _, name := range rest {
			if _, aerr := c.NetworkRemove(name); aerr != nil {
				fmt.Fprintln(r.Err, "jailor:", aerr.Message)
				return exitCodeForError(aerr)
			}
			fmt.Fprintf(r.Out, "removed %s\n", name)
		}
		return 0
	}
	nm, err := r.openNetworks(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	for _, name := range rest {
		if err := nm.Remove(name); err != nil {
			fmt.Fprintln(r.Err, "jailor:", err)
			return 1
		}
		fmt.Fprintf(r.Out, "removed %s\n", name)
	}
	return 0
}

func joinList(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
