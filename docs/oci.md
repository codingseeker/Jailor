# OCI runtime compatibility (Phase 25)

Jailor implements a **strict subset** of the OCI runtime-spec and shares the
OCI image data model. Unsupported OCI configuration is **explicitly rejected
at bundle-validation time — never silently ignored**. **Jailor does not claim
Docker- or Podman-compatibility**; it is its own engine with its own model.
See `docs/compat.md` for the full status matrix.

## A bundle

A **bundle** is a directory containing an OCI-shaped `config.json` plus an
optional `rootfs` directory relative to the bundle:

```text
bundle/
  config.json
  rootfs/            # optional; the Cell root filesystem
```

```jsonc
{
  "ociVersion": "1.0",
  "process": {
    "args": ["/bin/echo", "hello"],
    "cwd": "/",
    "noNewPrivileges": true,
    "capabilities": { "bounding": ["CAP_CHOWN"], "effective": ["CAP_CHOWN"] }
  },
  "root": { "path": "rootfs", "readonly": false },
  "hostname": "myjail",
  "linux": {
    "namespaces": [ {"type":"pid"}, {"type":"mount"}, {"type":"network"} ],
    "resources": {
      "memory": { "limit": 268435456 },
      "cpu":     { "quota": 50000, "period": 100000 },
      "pids":    { "limit": 100 }
    },
    "seccomp": true
  },
  "jailor": { "network": "none", "userns": "auto" }
}
```

## Image model

Jailor also understands OCI **image layouts** (`oci-layout`, `index.json`,
manifest/config blobs) and stores them content-addressed:

- **`internal/image`** parses and validates OCI manifests, indexes, and image
  configurations. Every referenced blob is verified by its digest on import,
  and malformed metadata is rejected outright.
- **`internal/store`** is the persistent backing store: deduplicated, digest-
  verified blobs; immutable extracted layer trees; and per-container
  filesystems built from ordered layers (overlayfs upper/lower when supported,
  copy-up otherwise). Writes are crash-safe (temp file + rename), so an
  interrupted write can never appear as a valid blob or layer.
- `jailor image import PATH` ingests an OCI image layout; `jailor image ls`,
  `inspect`, `rm`, `tag`, and `gc` manage tags, reference counts, and
  unreferenced content. `jailor run --image REF` / `jail create --image REF`
  assemble a Cell rootfs from an image without needing a host root filesystem.
- Containers pin their manifest and layer trees until the Jail is deleted, so
  shared layers survive tag removal and are only reclaimed by `image gc`.

See `docs/architecture.md` for the storage layout and `docs/lifecycle.md` for
the runtime state machine.

## Concept mapping

| OCI runtime-spec          | Jailor                      |
|---------------------------|-----------------------------|
| bundle                    | bundle directory            |
| `config.json`             | translated to `config.Config` |
| `process.args`/`cwd`      | Prisoner command / work dir |
| `process.env`             | Prisoner/`Cell.Env`         |
| `process.noNewPrivileges` | `no_new_privs`              |
| `process.capabilities`    | capability keep-set (all four CSets merged) |
| `root.path`/`root.readonly` | Cell rootfs / read-only   |
| `linux.namespaces`        | Bars (PID, Mount, UTS, Net, User, IPC) |
| `linux.resources`         | Rations (memory, cpu, pids) |
| `linux.seccomp: true`     | Jailor default seccomp filter (`SeccompEnabled`) |
| `hostname`                | Jail UTS hostname           |
| create/start/delete/export| Jail CREATED/RUNNING/deleted lifecycle + config re-emission |
| image layout / registry   | `internal/image` + `store`  |

Namespaces use OCI type names (`network`, `mount`) and are translated to Jailor
bar kinds (`net`, `mnt`). `process.env` entries map directly onto
`config.Cell.Env` (each must be `KEY=VALUE`), and environment round-trips
through the Ledger and across `engine.Restart`.

## Remote distribution (registry)

`internal/registry` speaks the OCI-distribution (registry v2) protocol for
`jailor pull` and `jailor push`:

- **Pull.** A reference `[host/]repository[:tag|@digest]` (bare names resolve to
  `registry-1.docker.io` with the `library/` namespace; a missing tag defaults
  to `latest`) is fetched as a manifest list or concrete manifest. Multi-arch
  indexes are resolved to a manifest for the current OS/architecture. Config
  and layer blobs are streamed with per-blob digest verification, downloads are
  bounded by a worker pool, and transient responses (429/5xx) are retried with
  backoff. Layers already present in the local store are reused without a
  network round-trip; the result is imported through the same validated
  `ImageStore.ImportLayout` path local layouts use, then tagged (`--tag`, or a
  local name derived from the reference). Digest references are pinned end to
  end (reference digest + `Docker-Content-Digest` header + blob digests).
- **Push.** The local image is looked up by its repository:tag (registry
  portion dropped), then config and layer blobs are uploaded with bounded
  concurrency — blobs the registry already has (HEAD) are skipped — followed by
  the manifest under the tag. Pushing by digest is rejected. Blobs stream
  straight from the store with digest verification.
- **Authentication.** No credentials live in source. `jailor` reads
  `~/.config/jailor/auth.json` (or `JAILOR_REGISTRY_AUTH`) with per-host
  entries (`username`/`password` or `identitytoken`), honoring the
  `docker.io` / `registry.hub.docker.com` aliases for the canonical host.
  `JAILOR_REGISTRY_USERNAME`/`JAILOR_REGISTRY_PASSWORD` apply to Docker Hub
  only. Bearer challenge negotiation caches tokens in memory; Basic challenges
  are supported; missing or rejected credentials surface `ErrAuthRequired`.
- **Transport.** Registries on `localhost`/loopback use plain HTTP; anything
  else requires HTTPS unless `--insecure` is given.

## Translation and validation

`internal/oci` is the translation layer. `oci.LoadBundle` parses a bundle's
`config.json` into a `Schema`, validates it, and produces a `config.Config`;
`oci.Export` performs the reverse translation (Jailor config → OCI
`config.json`, used by `jailor oci export <id>`). The rule of Phase 25 is
**explicit rejection**: a bundle that would change security or runtime
behavior in a way Jailor does not implement fails validation with a concrete
error. It is never silently dropped. See `docs/compat.md` for exactly what is
accepted, absorbed with deviations, or rejected.

## Documented deviations from OCI runtime-spec

1. **Strict-subset validation.** Unsupported OCI configuration (hooks,
   `mounts`, seccomp filter objects, `terminal`/`consoleSize`, non-zero
   `process.user` uid/gid/umask/additionalGids, `uidMappings`/`gidMappings`,
   `sysctl`, `maskedPaths`/`readonlyPaths`, unknown/cgroup namespace types,
   non-zero `cpu.shares`) is rejected at bundle load with a descriptive error,
   not ignored.
2. **`jailor` extension object** carries Jailor-only fields (`network` Gate
   mode, `userns` policy) that OCI has no analogue for.
3. **Seccomp is Jailor's own deny-list.** An OCI `linux.seccomp` **filter**
   object is rejected; `"seccomp": true` selects Jailor's default
   deny-list/strict policy (`SeccompEnabled`).
4. **Capabilities** are treated as one keep-set: the bounding, effective,
   permitted, and inheritable OCI sets are **merged** into a single keep-list
   for the Warden's uniform drop + bounding shrink.
5. **Terminal / console** (`process.terminal`, `process.consoleSize`) is not
   implemented and is rejected; `oci start` attaches inheriting stdio instead.
6. **No hooks** (`hooks.*`, rejected) and no runtime state JSON (`runtime-spec`
   state file). Jailor uses its own `internal/ledger` for state.
7. **CPU shares** are not implemented; a non-zero `cpu.shares` is rejected.
   Quota/period → fractional CPU is honored by the Cgroup Ration.
8. **`cgroup` namespace** type is rejected (Jailor does not model it as a Bar).
9. **`mounts`** section is rejected; Jailor mounts proc/tmp/dev on the Cell as
   configured by the Warden, not by an arbitrary OCI `mounts` list.
10. **Registry support is implemented but the OCI-distribution surface is
    minimal** — manifest/index/config/fetch-and-push only, with bearer/basic
    auth and digest pinning; no referrers API, upload resumption, or Docker Hub
    catalog/search.

## Lifecycle semantics

- `oci create --bundle <dir>` parses and validates the bundle and produces a
  `CREATED` Jail (no Prisoner yet).
- `oci start <id>` admits the Prisoner and supervises its Sentence to
  completion — mirroring OCI's create/start split.
- `oci delete <id>` removes a `CREATED`/`STOPPED` Jail.
- `oci export <id>` re-emits the Jail's persisted definition as an OCI
  `config.json` on stdout (reverse translation, errors on unrepresentable
  state).
- A Jail serves a **single Sentence**: a STOPPED Jail cannot be restarted
  (matching OCI's immutable container-then-single-process model).

See `docs/lifecycle.md` for the full state machine and `docs/compat.md` for the
status matrix.