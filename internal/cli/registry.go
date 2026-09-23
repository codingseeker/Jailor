package cli

import (
	"fmt"

	"jailor/internal/image"
	"jailor/internal/ledger"
	"jailor/internal/registry"
)

func (r *Root) registryClient(insecure bool, concurrency int) *registry.Client {
	c := registry.New()
	c.Insecure = insecure
	if concurrency > 0 {
		c.MaxConcurrent = concurrency
	}
	return c
}
func (r *Root) pull(args []string) int {
	fs := flagSet("jailor pull", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor pull [flags] IMAGE

Download an image from an OCI registry into the local store. IMAGE is
[host/]repository[:tag] (bare names default to Docker Hub). Layers already
stored locally are reused; every downloaded layer is digest-verified.
Credentials come from the auth file (JAILOR_REGISTRY_AUTH) or
JAILOR_REGISTRY_USERNAME / JAILOR_REGISTRY_PASSWORD (Docker Hub).

Flags:
`)
		fs.PrintDefaults()
	}
	ledgerDir := fs.String("ledger", "", "state root (default: JAILOR_LEDGER or per-user)")
	tag := fs.String("tag", "", "local tag to store the image under (default: derived from the reference)")
	insecure := fs.Bool("insecure", false, "allow plain-http for non-local registries")
	concurrency := fs.Int("concurrency", 4, "maximum concurrent layer downloads")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fs.Usage()
		return 2
	}
	is, err := image.Open(r.ledgerRoot(*ledgerDir))
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	c := r.registryClient(*insecure, *concurrency)
	res, err := c.Pull(is, rest[0], registry.PullOptions{Tag: *tag, MaxConcurrent: *concurrency})
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	fmt.Fprintf(r.Out, "pulled %s (%d layers, %d new, %d reused)\n",
		res.Image.Name, len(res.Image.Layers), res.LayersDownloaded, res.LayersReused)
	return 0
}
func (r *Root) push(args []string) int {
	fs := flagSet("jailor push", r.Err)
	fs.Usage = func() {
		fmt.Fprint(r.Err, `Usage: jailor push [flags] IMAGE

Upload a locally stored image to an OCI registry. The local image is looked up
by repository:tag (registry portion dropped): "jailor push host/team/app:v1"
pushes the local image "team/app:v1". Blobs the registry already has are
skipped.

Flags:
`)
		fs.PrintDefaults()
	}
	ledgerDir := fs.String("ledger", "", "state root (default: JAILOR_LEDGER or per-user)")
	insecure := fs.Bool("insecure", false, "allow plain-http for non-local registries")
	concurrency := fs.Int("concurrency", 4, "maximum concurrent blob uploads")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fs.Usage()
		return 2
	}
	is, err := image.Open(r.ledgerRoot(*ledgerDir))
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	c := r.registryClient(*insecure, *concurrency)
	res, err := c.Push(is, rest[0], registry.PushOptions{MaxConcurrent: *concurrency})
	if err != nil {
		fmt.Fprintln(r.Err, "jailor:", err)
		return 1
	}
	fmt.Fprintf(r.Out, "pushed %s@%s (%d blobs uploaded, %d skipped)\n",
		rest[0], shortDigest(res.Digest.String()), res.BlobsUploaded, res.BlobsSkipped)
	return 0
}
func (r *Root) ledgerRoot(dir string) string {
	if dir == "" {
		return ledger.DefaultDir()
	}
	return dir
}
