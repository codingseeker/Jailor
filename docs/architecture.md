# Architecture

Jailor is a minimal Linux container runtime written in Go. It separates the
**Warden** (host-side manager) from the **Prisoner** (the jailed process) around a
small set of Linux primitives.

## Layered model

Jailor names its concepts after a prison metaphor. Every concept maps to a
familiar container-runtime notion:

| Jailor term     | Container analogy      | Linux primitive                          |
|-----------------|------------------------|------------------------------------------|
| Jail            | Container (runtime)    | A named, recorded namespace + cgroup set |
| Prisoner        | Process                | A forked/`clone(2)`d child               |
| Cell            | Root filesystem        | `pivot_root`/`chroot`                    |
| Bar             | Namespace              | `clone(CLONE_NEW*)` namespace            |
| Ration          | Resource limit         | `cgroup`                                  |
| Gate            | Network namespace/Veth | netns + `veth` pair                      |
| Ledger          | State directory        | JSON records + `log.jsonl`               |
| Sentence        | Container lifecycle    | The Prisoner's execution period          |

## Component map

```
+------------------------------------------+
   `jailor` CLI ---| internal/cli   argument parsing, --config |
                    +------------------------------------------+
                               | warden.Options
                               v
                    +------------------------------------------+
                    | internal/warden  orchestration, logs,    |
                    |                  signal handling         |
                    +------------------------------------------+
               admission |            |            |            |
                         v            v            v            v
               +-----------+  +-----------+  +----------+  +-----------+
               | jail      |  | cell      |  | rations  |  | gate      |
               | spawn/init|  | rootfs    |  | cgroup   |  | netns/veth|
               +-----------+  +-----------+  +----------+  +-----------+
                         |            |
                         v            v
               +------------------------------+
               | prisoner   config  privileges|
               | exec/visit  schema  caps     |
               +------------------------------+
                         |
                         v
               +------------------------------+
               | runtimecore  process boundary |
               | 7-state supervisor, reaping  |
               +------------------------------+
                         |
                         v
               +------------------+      +------------------+
               | image            | ---> | store            |
               | refs, manifest,  |      | CAS blobs,       |
               | import, tag/rm/  |      | layers, overlay, |
               | GC, containers   |      | containers, FS   |
               +------------------+      +------------------+
                         |
                         v
               +--------------+
               | ledger       |  persistence + logs
               +--------------+
```

## Storage & images

Jailor's image and storage layers follow a content-addressed model with no
external dependencies:

```
OCI layout / registry blob
        |
        v                    immutable
internal/image  ->  internal/store  (blobs/, layers/, containers/, volumes/)
        |                    |   |
        |                    |   +-- extraction into immutable layer trees
        |                    +-- dedup by sha256, digest-verified writes
        v
container rootfs (overlayfs upper/lower, or copy-up fallback) -> Cell
```

- **`internal/store`** is the persistent content-addressed store: blobs (digest
  verified, deduplicated, crash-safe via temp-file + rename), extracted immutable
  layer trees identified by digest, and per-container filesystems assembled from
  ordered lower layers (`overlayfs` when supported, copy-up otherwise). Writable
  container state never modifies shared lower layers; a read-only rootfs gives the
  Cell no upper layer.
- **`internal/image`** owns OCI metadata (manifest/index/config parsing with strict
  validation of every referenced digest), local tags, reference counting, garbage
  collection of unreferenced Content, and importing OCI image layouts. A container
  assembled from an image pins its layers until released.
- The Warden assembles a Cell rootfs from an image when `--image` (or
  `cell.image`) is configured; the assembled filesystem is released on Jail
  deletion and the layers become garbage-collectable.
- **`internal/oci`** is the OCI runtime-configuration translation layer (Phase
  25): it turns a bundle's `config.json` into a `config.Config` (`LoadBundle`)
  and back (`Export`, used by `jailor oci export`). The translation is a
  **strict subset** — unsupported OCI configuration that would change security
  or runtime behavior is explicitly rejected at load, never silently ignored.
  See `docs/oci.md` and `docs/compat.md`.

## Networking

Networking is split into a durable state model and the Linux plumbing behind it:

- **`internal/network`** is the persistent model: named `Network` objects
  (subnet, gateway, optional IPv6 subnet, DNS servers, host bridge device) kept
  as JSON under the Ledger root, plus content-free IP allocation. Allocation
  state is re-read from disk under a file lock, so concurrent Warden processes
  cannot collide. The default network is the well-known `bridge`
  (`10.66.0.0/24` on `jailor0`) and cannot be removed; a network refuses
  deletion while any address is allocated.
- **`internal/gate`** is the Linux implementation a Warden drives at Jail start:
  a network namespace, a veth pair wired onto a bridge, address and route
  configuration, DNS, and (where configured) port forwarding, torn down on
  release.
- The **CLI** (`jailor network create|ls|inspect|rm`) manages Network objects
  so `jailor run`/`jail create --network <name>` can attach Jails to isolated
  networks. The Gate/network backends are covered by their own tests; the CLI
  surface and IPAM invariants are tested in `internal/cli` and
  `internal/network`.

## Remote image distribution

`internal/registry` is the OCI-distribution (registry v2) client wired to
`jailor pull` and `jailor push`:

- **Pull** resolves a reference (bare names → Docker Hub), fetches a manifest
  (multi-arch indexes resolved by platform), pins every blob's digest while
  downloading with bounded concurrency and transient retries, reuses layers
  already in the content-addressed store, and imports through the same
  digest-validating `ImageStore.ImportLayout` path local layouts use.
- **Push** looks up the local image by repository:tag, skips blobs the registry
  already has (HEAD), uploads the rest bounded-concurrently (resumable POST +
  PUT), then the manifest under the tag. Digest references are rejected.
- **Credentials** never live in source: an auth file
  (`~/.config/jailor/auth.json` / `JAILOR_REGISTRY_AUTH`) or a Docker Hub-only
  env fallback feeds Bearer/Basic challenge negotiation; tokens are cached in
  memory only. Localhost/loopback registries use plain HTTP; everything else
  HTTPS unless `--insecure`.

The registry client is tested against a mocked registry server
(`internal/registry`), and the CLI is exercised against an in-process HTTP
registry (`internal/cli`). See `docs/oci.md` for details.

## Runtime flow

1. The Warden builds a resolved `InitConfig` (from CLI flags or a versioned
   `config.Config`).
2. A `Cell` is validated when a root filesystem is configured
   (`internal/cell` rejects path traversal and the host root).
3. The Jail init (`/proc/self/exe __init`) is `clone(2)`d with the requested
   namespace flags (Bars).
4. The Warden streams the `InitConfig` over a pipe, then (optionally) allocates
   Rations (moves the init into a cgroup) and installs a Gate (creates the veth).
5. The Warden releases the init, which applies restrictions (hostname, mounts,
   `pivot_root` into the Cell, `no_new_privs`, seccomp, capability drop) and then
   `execve(2)`s the Prisoner command.
6. The Warden forwards signals and reaps the child; every state change is logged
   to the Ledger.

## Why each primitive exists

- **`internal/runtimecore`** is the process-supervision boundary layer: the
  syscall mappings (exit codes, `/proc` facts) and a 7-state supervisor model
  used by the engine and validated without root in its own tests. It keeps
  the Warden and Ledger policy-free of raw syscall shapes.
- **Namespaces (Bars)** isolate global kernel state per-prisoner (`pid`, `mount`,
  `uts`, `net`, `user`, `ipc`). Without them the Prisoner shares the host's PIDs,
  filesystems, and network.
- **`pivot_root`/`chroot`** confines the Prisoner's view of the filesystem to the
  Cell so it cannot read host paths not present below the root.
- **`mount(MS_PRIVATE)`** makes the Jail's mount tree private so the Prisoner's
  mounts cannot propagate a change back to the host.
- **`no_new_privs` + seccomp** (a deny-list filter) block dangerous syscalls
  (`mount`, `pivot_root`, `ptrace`, …) even before capability drop.
- **Capability bounding-set shrink + effective drop** ensures a Prisoner cannot
  regain a privilege it never needed.
- **cgroup** lets the Warden cap the Prisoner's memory, CPU, and process count and
  clean them up even if the Prisoner dies abnormally.
- **`read-only` Cell remount** prevents the Prisoner from modifying its own root
  filesystem.