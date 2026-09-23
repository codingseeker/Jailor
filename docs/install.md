# Installation

Jailor is static and dependency-free at runtime (CGo is not required; seccomp
filters are hand-rolled).

## Build

```text
go build -o jailor ./cmd/jailor
```

## Install to PATH

```text
install -m 0755 jailor /usr/local/bin/jailor
```

## Requirements

- Linux with namespace and cgroup v2 support (any modern distro/kernel).
- For **full isolation** (a Cell rootfs, Rations, a bridged Gate) Jailor needs to
  create namespaces, cgroups, and veth pairs: run it as **root** or grant the
  relevant capabilities.
- Running **without root** works for plain Jails (default PID/UTS/Mount bars + a
  user namespace), e.g. `jailor run /bin/echo hi`.

## Verify

```text
jailor version
jailor run /bin/echo hello
```

## Usage examples

Run a command in a default Jail:

```text
jailor run -- /bin/sh -c 'echo pid=$$; hostname'
```

Run with a custom hostname, a read-only Cell, seccomp, and a memory/cpu ration:

```text
jailor run --hostname web \
    --rootfs /srv/rootfs --read-only \
    --seccomp --memory 256M --cpu 0.5 -- /bin/nginx -g 'daemon off;'
```

> The exact flag set is subject to the current CLI. Run `jailor run --help` for
> the authoritative list.

Create then start a Jail from a versioned configuration:

```text
jailor jail create --config jail.json
jailor jail start <id>
```

Consult the Ledger and logs:

```text
jailor jail list
jailor jail inspect <id>
jailor prisoner logs <id>
jailor prisoner stats <id>
```

OCI-inspired lifecycle from a bundle (see `docs/oci.md`):

```text
jailor oci create --bundle ./bundle
jailor oci start <id>
jailor oci delete <id>
```

## Troubleshooting

| Symptom                                        | Likely cause / fix                                       |
|------------------------------------------------|----------------------------------------------------------|
| `jailor run /bin/echo hi` fails off   | No user namespace available (`/bin/echo` needs no ns) — pass `--userns off` for a trivial jailed command. Problem persists? See next row.            |
| `operation not permitted` on fork/namespace    | No privilege for the requested Bars. Run as root or narrow to PID/UTS/Mount. |
| `pivot_root: operation not permitted`          | not running as root.                                   |
| `mkdir /sys/fs/cgroup/...: permission denied`  | Not root (or cgroup v2 not writable). Rations need root. |
| `nsenter: setns into /proc/<pid>/ns/user`      | Visiting another namespace's user ns is restricted to child namespaces. |
| `no space left on device` on spawn             | Host fork/pid exhaustion (common in constrained sandboxes). Close Jails or raise limits. |
| `jail: init failed before exec`                | A requested bare PID/Network namespace without the Mount bar was rejected. Real Jails always install PID+UTS+MNT together. |
| Prisoner output gone after `oci start`         | `start` detaches; pass `--stdout inherit` (the default) or a file path. |