# Performance and architectural trade-offs

Host-side (non-privileged) benchmark numbers measured on this host:

```
cpu: 13th Gen Intel(R) Core(TM) i5-1334U
goos: linux  goarch: amd64

BenchmarkPrepareCell-12      50    487.8 ns/op    160 B/op    1 allocs/op
BenchmarkBuildInit-12        50    172.1 ns/op      0 B/op    0 allocs/op
BenchmarkNewRecord-12        50   1689 ns/op     592 B/op    4 allocs/op
BenchmarkBundleTranslate-12  138631  8899 ns/op  2152 B/op   38 allocs/op
BenchmarkExport-12           243690  6299 ns/op  1954 B/op    9 allocs/op
```

`go test -bench=. -run=NONE ./internal/warden/ ./internal/oci/`

## What these measure

- `PrepareCell` — resolving and validating the Cell root filesystem.
- `BuildInit` — translating Warden options into the Jail's `InitConfig`.
- `NewRecord` — building and copying the Ledger record.
- `BundleTranslate` — OCI `config.json` → Jailor config (validation included).
- `Export` — reverse translation, Jailor config → OCI `config.json`.

These cover the constant host-side work every Jail pays irrespective of the
target (echo, a shell, or an application). Translation cost is single-digit
microseconds: negligible next to the kernel work of an actual run.

## What is deliberately NOT auto-benchmarked in the sandbox

The privileged, fork-bound steps — `clone(CLONE_NEW*)`, cgroup allocation, veth
setup, and `pivot_root` — require root and are dominated by kernel cost, not
Jailor code. Forking dozens of Jail inits in this non-root sandbox exhausts
fork capacity and is unstable. The cost of a full supervised run is therefore
measured manually on a capable host, not in the unit benchmark:

- The dominant cost of **Jail creation** is `pivot_root` + mount setup (a few
  ms on modern kernels).
- The dominant cost of **Prisoner startup** is `clone(2)` with namespace flags,
  which is dominated by kernel namespace creation.
- **Memory/CPU/network overhead** of an idle Jail is essentially that of a bare
  process: one PID, its namespace structs, and optionally one veth pair. On a
  modern kernel this is a few MB of kernel memory, negligible CPU until work is
  done.

## Comparison with runc

- runc implements the full **OCI Runtime Spec** (bundle, `config.json`, a
  runtime-state JSON, hooks, seccomp via libseccomp, full capability and uid/gid
  mapping, terminal handling).
- **Jailor is deliberately smaller**: it supports the subset most containers
  need — namespaces, a rootfs, mounts, cgroups, capabilities, seccomp, and a
  simple network bridge. Unsupported OCI configuration is **explicitly
  rejected**, not ignored. It does not claim Docker/Podman compatibility. See
  `docs/oci.md` and `docs/compat.md`.
- That smaller surface means Jailor's create path does less validation and setup,
  so for the same narrow feature set it is generally **equal or faster** than
  runc, whose spec-conformance machinery dominates.

## Trade-offs chosen

| Decision                    | Why                                       | Cost                         |
|-----------------------------|-------------------------------------------|------------------------------|
| Go, no CGo, no libseccomp   | static, easy to audit, no cgo toolchain    | must hand-roll BPF          |
| Hand-rolled seccomp filters | no libseccomp dependency                   | smaller filter vocabulary    |
| CLI + versioned config      | reproducible Jails                         | JSON replaces DMTF/hooks     |
| In-process Ledger           | single binary, no daemon/state API         | no multi-client locking      |
| Minimal Gate                | predictable networking                     | no NAT/masquerade            |

## When to use Jailor / when not to

Use Jailor when you want a small, auditable, spec-light container runtime for a
single process under namespaces, cgroups, and a rootfs. Prefer runc (or Docker)
when you need the full OCI feature surface, hooks, a terminal implementation, or
the huge ecosystem of OCI tooling.