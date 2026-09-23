package cli

import (
	"fmt"
	"text/tabwriter"
	"time"

	"jailor/internal/image"
	"jailor/internal/ledger"
	"jailor/internal/rations"
)

func (r *Root) openImageStore(ledgerDir string) (*image.ImageStore, error) {
	if ledgerDir == "" {
		ledgerDir = ledger.DefaultDir()
	}
	return image.Open(ledgerDir)
}

func (r *Root) images(args []string) int {
	fs := flagSet("jailor images", r.Err)
	ledgerDir := fs.String("ledger", "", "state root (default: JAILOR_LEDGER or per-user)")
	socket := fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		list, aerr := c.Images()
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		if len(list.Images) == 0 {
			fmt.Fprintln(r.Out, "no images yet; import an OCI layout with 'jailor image import <dir>'")
			return 0
		}
		return r.renderImageList(list.Images)
	}
	is, err := r.openImageStore(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	list, err := is.List()
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	if len(list) == 0 {
		fmt.Fprintln(r.Out, "no images yet; import an OCI layout with 'jailor image import <dir>'")
		return 0
	}
	return r.renderImageList(list)
}

func (r *Root) renderImageList(list []image.Image) int {
	tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tDIGEST\tSIZE\tARCH/OS\tCREATED")
	fmt.Fprintln(tw, "----\t------\t----\t-------\t-------")
	for _, img := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s/%s\t%s\n",
			img.Name, shortDigest(img.Digest.String()), rations.HumanBytes(img.Size),
			img.Architecture, img.OS, formatCreated(img.Created))
	}
	tw.Flush()
	return 0
}
func (r *Root) imageCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(r.Err, "Usage: jailor image <ls|inspect|rm|tag|import|gc> [flags]")
		return 1
	}
	switch args[0] {
	case "ls", "list":
		return r.images(args[1:])
	case "inspect":
		return r.imageInspect(args[1:])
	case "rm", "remove":
		return r.imageRemove(args[1:])
	case "tag":
		return r.imageTag(args[1:])
	case "import":
		return r.imageImport(args[1:])
	case "gc", "prune":
		return r.imageGC(args[1:])
	default:
		fmt.Fprintf(r.Err, "jailor: unknown image command %q\n", args[0])
		fmt.Fprintln(r.Err, "Usage: jailor image <ls|inspect|rm|tag|import|gc>")
		return 1
	}
}

func (r *Root) inspect(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(r.Err, "Usage: jailor inspect image <name> | <jail-id>")
		return 1
	}
	if args[0] == "image" {
		return r.imageInspect(args[1:])
	}
	return r.jailInspect(args)
}

func (r *Root) imageInspect(args []string) int {
	fs := flagSet("jailor image inspect", r.Err)
	ledgerDir := fs.String("ledger", "", "state root (default: JAILOR_LEDGER or per-user)")
	socket := fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(r.Err, "Usage: jailor image inspect [--ledger <dir>] <name>")
		return 1
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		img, aerr := c.ImageInspect(rest[0])
		if aerr != nil {
			fmt.Fprintln(r.Err, "jailor:", aerr.Message)
			return exitCodeForError(aerr)
		}
		return renderImageInspect(r, img)
	}
	is, err := r.openImageStore(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	img, err := is.Inspect(rest[0])
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	return renderImageInspect(r, *img)
}

func renderImageInspect(r *Root, img image.Image) int {
	fmt.Fprintf(r.Out, "Name          %s\n", img.Name)
	fmt.Fprintf(r.Out, "Digest        %s\n", img.Digest)
	fmt.Fprintf(r.Out, "Size          %s\n", rations.HumanBytes(img.Size))
	fmt.Fprintf(r.Out, "Architecture  %s\n", img.Architecture)
	fmt.Fprintf(r.Out, "OS            %s\n", img.OS)
	fmt.Fprintf(r.Out, "Created       %s\n", formatCreated(img.Created))
	if cur := imageCmdString(img.Config.Config.Cmd); cur != "" {
		fmt.Fprintf(r.Out, "CMD           %s\n", cur)
	}
	if e := imageCmdString(img.Config.Config.Entrypoint); e != "" {
		fmt.Fprintf(r.Out, "Entrypoint    %s\n", e)
	}
	for _, env := range img.Config.Config.Env {
		fmt.Fprintf(r.Out, "Env           %s\n", env)
	}
	for i, d := range img.Layers {
		fmt.Fprintf(r.Out, "Layer %d       %s\n", i, d)
	}
	return 0
}

func (r *Root) imageRemove(args []string) int {
	fs := flagSet("jailor image rm", r.Err)
	ledgerDir := fs.String("ledger", "", "state root (default: JAILOR_LEDGER or per-user)")
	socket := fs.String("socket", "", "jailord unix socket (default: <ledger>/jailord.sock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(r.Err, "Usage: jailor image rm [--ledger <dir>] <name>...")
		return 1
	}
	if c := r.daemonClient(*ledgerDir, *socket); c != nil {
		for _, name := range rest {
			if _, aerr := c.ImageRemove(name); aerr != nil {
				fmt.Fprintln(r.Err, "jailor:", aerr.Message)
				return exitCodeForError(aerr)
			}
			fmt.Fprintf(r.Out, "removed %s\n", name)
		}
		return 0
	}
	is, err := r.openImageStore(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	for _, name := range rest {
		if err := is.Remove(name); err != nil {
			fmt.Fprintln(r.Err, "jailor:", err)
			return 1
		}
		fmt.Fprintf(r.Out, "removed %s\n", name)
	}
	return 0
}

func (r *Root) imageTag(args []string) int {
	fs := flagSet("jailor image tag", r.Err)
	ledgerDir := fs.String("ledger", "", "state root (default: JAILOR_LEDGER or per-user)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fmt.Fprintln(r.Err, "Usage: jailor image tag [--ledger <dir>] <source> <target>")
		return 1
	}
	is, err := r.openImageStore(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	if err := is.Tag(rest[0], rest[1]); err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	fmt.Fprintf(r.Out, "tagged %s as %s\n", rest[0], rest[1])
	return 0
}

func (r *Root) imageImport(args []string) int {
	fs := flagSet("jailor image import", r.Err)
	ledgerDir := fs.String("ledger", "", "state root (default: JAILOR_LEDGER or per-user)")
	tag := fs.String("tag", "", "local tag to import under (derived from the layout or 'latest' otherwise)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(r.Err, "Usage: jailor image import [--ledger <dir>] [--tag <name>] <layout-dir>")
		return 1
	}
	is, err := r.openImageStore(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	img, err := is.ImportLayout(rest[0], image.ImportOptions{Tag: *tag})
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	fmt.Fprintf(r.Out, "imported %s (%d layers, %s)\n", img.Name, len(img.Layers), rations.HumanBytes(img.Size))
	return 0
}

func (r *Root) imageGC(args []string) int {
	fs := flagSet("jailor image gc", r.Err)
	ledgerDir := fs.String("ledger", "", "state root (default: JAILOR_LEDGER or per-user)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	is, err := r.openImageStore(*ledgerDir)
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	gc, err := is.GC()
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	fmt.Fprintf(r.Out, "reclaimed %d unreferenced blob(s), %d layer tree(s), %d broken tag(s)\n", gc.Blobs, gc.Layers, gc.Tags)
	return 0
}

func shortDigest(d string) string {
	if len(d) > 7+12 {
		return d[:7+12]
	}
	return d
}

func formatCreated(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func imageCmdString(args []string) string {
	if len(args) == 0 {
		return ""
	}
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
