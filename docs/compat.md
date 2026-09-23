# OCI compatibility matrix

Jailor implements a **strict subset** of the OCI runtime-spec and OCI image
specs. This matrix records exactly what is implemented and tested. Jailor does
**not** claim Docker- or Podman-compatibility: it shares the OCI data model so
bundles, images, and registry protocols are interoperable, but it is its own
engine with its own model (Warden/Jail/Prisoner/Bars/Rations/Gate/Cell/Ledger).

Legend: ✅ implemented and tested · ⚠️ implemented with documented deviations ·
❌ explicitly rejected (never silently ignored) · ➖ not modeled/absent.

## Runtime configuration (`config.json`)

| OCI field                    | Status | Notes |
|------------------------------|--------|-------|
| `ociVersion`                 | ✅ | accepts `1.0`, `1.1`; anything else rejected |
| `process.args`               | ✅ | required; maps to Command |
| `process.env`                | ✅ | maps to Prisoner env (`KEY=VALUE`, validated) |
| `process.cwd`                | ✅ | maps to WorkDir (default `/`) |
| `process.noNewPrivileges`    | ✅ | maps to `no_new_privs` |
| `process.capabilities.*`     | ⚠️ | merged into one keep-set; uniform drop (see deviations) |
| `process.terminal`           | ❌ | rejected; no pty |
| `process.consoleSize`        | ❌ | rejected |
| `process.user.uid/gid`       | ❌ | non-zero rejected; Prisoner runs as mapped root |
| `process.user.umask`         | ❌ | rejected |
| `process.user.additionalGids`| ❌ | rejected |
| `root.path`                  | ✅ | resolved relative to bundle; Cell rootfs |
| `root.readonly`              | ✅ | ReadOnly Cell mount |
| `hostname`                   | ✅ | UTS hostname (≤63 bytes, no NUL) |
| `linux.namespaces`           | ⚠️ | pid/net/mount/uts/user/ipc mapped; `cgroup` and unknown rejected |
| `linux.resources.memory.limit` | ✅ | Ration memory |
| `linux.resources.cpu.quota`/`period` | ✅ | fractional CPUs |
| `linux.resources.cpu.shares` | ❌ | rejected (Jailor does not implement shares weighting) |
| `linux.resources.pids.limit` | ✅ | Ration pids |
| `linux.seccomp` (object)     | ❌ | rejected; Jailor uses its own deny-list |
| `linux.seccomp` (`true`)     | ✅ | Jailor default deny-list (extension form) |
| `linux.uidMappings`/`gidMappings` | ❌ | rejected; Jailor builds subordinate-range maps |
| `linux.sysctl`               | ❌ | rejected |
| `linux.maskedPaths`/`readonlyPaths` | ❌ | rejected |
| `mounts`                     | ❌ | rejected; Cell mounts are Warden-managed |
| `hooks.*`                    | ❌ | rejected; no hook phases |
| `annotations`                | ➖ | parsed into no Jailor model; not behavior-affecting |

## Jailor extension (`jailor` object)

| Field       | Status | Notes |
|-------------|--------|-------|
| `jailor.network` | ✅ | `none` or `bridge` Gate mode |
| `jailor.userns`  | ✅ | `auto`/`on`/`off` user-namespace policy |

Jailor extension fields are Jailor-only; OCI has no analogue for them.

## Namespaces

| Namespace | Status | Notes |
|-----------|--------|-------|
| PID     | ✅ | Bar |
| Mount   | ✅ | Bar; private propagation + pivot_root |
| UTS     | ✅ | Bar |
| Network | ✅ | Bar |
| User    | ✅ | Bar; subordinate-range maps when rootless |
| IPC     | ✅ | Bar |
| cgroup  | ❌ | not modeled; rejected in bundles |

## Isolation features

| Feature            | Status | Notes |
|--------------------|--------|-------|
| Capabilities       | ✅ | allow-list keep-set; drop + bounding shrink |
| Seccomp            | ⚠️ | Jailor deny-list/strict policy; not OCI filter objects |
| Read-Only rootfs   | ✅ | Cell read-only, /proc,/dev,/tmp writable |
| cgroups (Rations)  | ✅ | memory/CPU/pids limits |
| NoNewPrivs         | ✅ | |
| Rootless exec      | ✅ | user-namespace pid1; idmap |
| AppArmor/SELinux   | ⚠️ | LSM exec transition (not a full OCI LSM model) |
| Overlayfs          | ✅ | container rootfs via overlayfs upper/lower (copy-up fallback) |

## Rootless

| Concern            | Status | Notes |
|--------------------|--------|-------|
| Non-root Warden    | ✅ | default: user namespace installed |
| mount/pivot rootfs | ⚠️ | requires userns (`Userns: off` with rootfs rejected) |
| cgroup delegation  | ⚠️ | requires host delegation; fails closed if absent |
| veth/bridge gate   | ⚠️ | needs unprivileged network rights |

## Lifecycle

| OCI lifecycle | Jailor | Status |
|---------------|--------|--------|
| create → CREATED | `oci create` | ✅ |
| start → RUNNING | `oci start` | ✅ |
| delete | `oci delete` | ✅ |
| state file | Ledger record | ✅ (internal/ledger, not OCI runtime-spec state JSON) |
| single Sentence | one Prisoner per Jail | ✅ |

## OCI images

| Image concern            | Status | Notes |
|--------------------------|--------|-------|
| OCI image layout import  | ✅ | `image import`; digest-verified, content-addressed |
| manifest/index/config    | ✅ | parsed + validated |
| digest pinning           | ✅ | reference/header/blob digests checked |
| multi-arch index resolve | ✅ | resolved to current OS/arch |
| registry v2 pull/push    | ✅ | `pull`/`push`, bearer/basic auth |
| volumes                 | ⚠️ | store volumes dir exists; no generic OCI volume mount spec |
| OCI image config → Jail | ⚠️ | entrypoint/cmd/env/user of an image used via `--image` (subset) |

## Not claimed

- No Docker/Podman command compatibility.
- No OCI runtime `create`/`start` state communication protocol (`$XDG_RUNTIME_DIR/oci` file, `--pid-file` contract).
- No OCI hook execution or `runc`-style notify sockets.
- No full OCI seccomp (syscall arg filters, `SCMP_ACT_*`).
- No OCI `annotations` handling.

See `docs/oci.md` for the field-by-field mapping and the full deviations list,
`docs/security.md` for the security model, and `docs/architecture.md` for the
storage model.