# Security model

Jailor applies containment in a strict order so no single step can be bypassed.
The design is **fail-closed**: an invalid capability name, an over-long hostname,
or a path that escapes the Cell is rejected before a Prisoner is admitted.

## Unified security policy (Phase 22)

Jailor consolidates its per-switch security options into one coerced posture,
captured by `internal/security.Policy` and executed by the Warden at admission:

    Capabilities  — the ordered allowlist the Prisoner keeps (default: a
                    conservative set, fewer than the host grants)
    NoNewPrivs    — sets the no_new_privs bit; implied by any seccomp filter
    Seccomp       — "none", "default" (deny-list) or "strict" (allow-list);
                    "custom" is reserved and refused at Compile
    Userns        — "auto", "on" or "off"
    ReadOnly      — mounts the Cell read-only
    LSM           — optional "apparmor:<profile>" / "selinux:<context>" exec
                    transition

`security.Compile(policy, context, host)` produces the `AppliedReport` — the
honest, per-feature account of what the host actually granted. A feature the
host cannot grant (an unknown capability, an unknown profile, `Userns: on`
without subordinate ranges, `Userns: off` for a rootless Warden that must mount
a Cell) becomes a typed `*security.Unavailable`, and the Warden **refuses to
admit** that Jail (exit 127) rather than run a weaker one. The report is
recorded in the Ledger (`policy`) and shown by `jailor jail inspect`, so a
claimed posture can always be audited against what was installed.

## Which boundaries are always provided

These are enforced by Jailor itself and hold for any privileged or fully
rootless-capable host:

- PID, mount, UTS and network namespace isolation of the Cell.
- Private mount propagation; nothing the Jail mounts leaks back to the host.
- `pivot_root`, so the Prisoner's visible root is the Cell, never the host.
- `no_new_privs` before the Prisoner executes (setuid binaries cannot escalate).
- `Capabilities` dropped to the requested allowlist; the dropped sets cannot be
  restored on `exec`.
- Read-only Cell roots when requested.
- Seccomp filters installed before the Prisoner executes.
- Strict input validation (unknown bars, gate modes, userns policies,
  capability names, over-long hostnames, cell-escape paths).

## Which boundaries depend on host configuration

These cannot be guaranteed by Jailor alone; they hinge on how the host is set
up, and the policy engine fails explicitly when they are missing:

- **User namespaces**: `Userns: on` for a non-root Warden requires
  `kernel.unprivileged_userns_clone=1` (or equivalents) plus a
  `/etc/subuid`/`/etc/subgid` entry for the invoking user **and** the setuid
  `newuidmap`/`newgidmap` helpers on `PATH`. Missing any of these is reported
  as `userns.rootless` unavailable and the Jail is refused. With no subordinate
  ranges the rootless map is a single `0 → EUID` projection; with them, real
  subordinate-range maps are installed (see `idmap.BuildMappings`).
- **Mount namespace for rootless**: a rootless Warden without a user namespace
  cannot install the Cell's mounts; `Userns: off` with a rootfs/read-only
  request is refused.
- **Rations (cgroups)**: memory/CPU/pids limits need a writable cgroup
  hierarchy for the user (managed delegation). On hosts without delegation the
  limits fail, not silently no-op.
- **Gate networking**: the bridge gate needs host privileges to create veth
  pairs and a bridge. rootless Jails get network namespace isolation but not a
  host bridge unless the host grants the needed interfaces (see limitations).
- **AppArmor/SELinux**: an LSM transition is honored only when the requested
  profile exists in the host's active LSM; an unknown profile fails the Jail at
  admission rather than being skipped.

## Defense in depth

1. **Namespaces (Bars)** isolate PID, mount, UTS, network, and IPC state.
2. **Mount propagation is made private** so nothing the Jail does can leak mounts
   back to the host.
3. **`pivot_root` into the Cell** confines the visible filesystem; path traversal
   and the host root are rejected at creation.
4. **`no_new_privs`** is set so exec-time privilege escalations (e.g. setuid
   binaries) cannot occur.
5. **Seccomp deny-list** blocks `mount`, `umount2`, `pivot_root`, `reboot`,
   `swapon`, `swapoff`, `init_module`, `kexec_load`, `acct`, and `ptrace`.
6. **Capabilities are dropped** — the bounding set is shrunk while `CAP_SETPCAP`
   is still held, then the effective/permitted/inheritable sets are cleared, so a
   dropped capability cannot be regained via `exec`.
7. **cgroup Rations** cap memory, CPU, and process count.

## Privilege transitions

- The Warden runs with the user's privileges (it is not `setuid` root).
- A **user namespace** is installed by default for non-root users so a Prisoner
  may be given a usable environment without real host privileges.
- Inside the Jail, the init **only ever drops** privileges; it never escalates.

## Input/path validation

- `config.Validate` rejects unknown namespace bars, gate modes, userns policies,
  unknown capability names, and hostnames longer than the 63-byte UTS limit or
  containing a NUL byte.
- `cell.New` resolves symlinks and rejects any Cell root that resolves to the host
  `/` (including via `..` traversal or a symlink loop).

## Cleanup guarantees

- Every failure path in the Warden/un init tears down what it created:
  mounts are unmounted (`MNT_DETACH`) before a failed init exits; Rations and the
  Gate are released in `defer` on the success path.
- All cleanup is **idempotent** — running a cleanup twice is safe.
- The Ledger `Recover` operation reclaims abandoned Jails: live Prisoners are
  preserved, dead ones are swept and their cgroups removed.

## Known limitations

- The default seccomp policy is a small **deny-list**; it is not a permissive
  allow-list and is not a full hardening profile. A conservative deploy should
  also run the Prisoner under an unprivileged user inside the Cell.
- Capability handling is namespace-scoped: it can only constrain what the kernel
  grants in the Prisoner's user namespace.
- The Gate is deliberately minimal (none/bridge). It does not implement iptables
  DNAT or outbound masquerade.

## Production hardening (Phase 24)

### Security assumptions

- The Warden is **not** `setuid`; it runs with the invoking user's privileges and
  gains nothing it could not already do. Jailor never escalates privileges.
- A Jail is a boundary for the *workload*, not a trust boundary for the host
  kernel. A real deployment should add an LSM profile and seccomp allow-list on
  top of the default policy.
- The Unix daemon socket is `0600`, owned by the ledger owner, and the daemon
  refuses clients whose `SO_PEERCRED` UID differs from the socket owner. Only the
  owning user can talk to `jailord`.
- Jails are identified only by validated, conservative names. `ledger.ValidID`
  rejects separators, dot-dot segments, control characters, and leading `.`/`-`,
  so an identity can never escape the ledger root or collide with a hidden file.
  The same rule is enforced at the engine `Create` boundary and at image/network
  name validation (which already existed).
- Reports of what was installed (`AppliedReport`) are recorded in the Ledger and
  inspectable; a claimed posture is always auditable against what the host gave.

### Reliability guarantees

- **Leak-free Sentences:** every Sentence in daemon mode closes its Stdin,
  Stdout and Stderr descriptors after the Prisoner exits; the regression tests
  (`TestEngineStartDoesNotLeakFDs`, `TestEngineSoakDetectsLeaks`) assert the
  engine's descriptor and goroutine counts stay flat across many lifecycles.
- **No ghost runners:** a Sentence whose supervision fails (setup failure, signal
  kill, crash) is removed from the active set, its failure is counted, and the
  Ledger is never left with a stale `RUNNING` record. `Recover` reclassifies dead
  runners and preserves live ones on daemon restart.
- **Restart/failure accounting:** `Restarts` survives the internal recreate, and
  operator kills (SIGKILL/SIGTERM) are excluded from `Failures` so the counters
  reflect faults, not administrative actions.
- **Concurrent lifecycle safety:** `create`/`start`/`stop`/`inspect`/`delete`
  are safe under concurrent clients; the hub disconnects are idempotent and
  per-connection serve is isolated. Concurrency tests (100 concurrent creates,
  50 concurrent lifecycles) verify the Ledger stays consistent.
- **Idempotent cleanup:** all teardown is idempotent (`MNT_DETACH`, cgroup and
  gate release, mount-sweep) and safe to run twice.

### Kernel requirements

- Linux 5.x+ with user namespaces (`kernel.unprivileged_userns_clone=1` or
  equivalent), a cgroup v2 delegation for the user, and unprivileged veth/bridge
  rights are needed for the full feature set. Missing prerequisites are refused
  explicitly (`*security.Unavailable`), never silently downgraded.
- `newuidmap`/`newgidmap` plus `/etc/subuid`/`/etc/subgid` for the invoking user
  are required for subordinate-range ID maps in rootless mode.
- Seccomp filters require `CAP_SYS_ADMIN` in the user namespace (or a filter-all
  grant); on kernels/hosts that reject `TIOCSTI`-class filters the Jail is
  refused rather than admitted unconstrained.

### Known limitations (debt)

- The default seccomp posture is a small deny-list; a production posture should
  supply a permissive-but-principled allow-list of its own.
- `jailor exec`/`attach` and image `tag`/`import`/`gc` remain direct-prisoner /
  local-only paths; they are not streamed over the daemon API.
- `jailor stats` reports live rations only while a Prisoner is RUNNING — resource
  counters are released with the cgroup at the end of a Sentence.
- Namespace-dependent leak detection (mounts, network, cgroups) requires running
  real Jails, so the automated suite can only probe process-level signals
  (fds/goroutines) plus engine/ledger accounting in the sandbox.
- Startup/shutdown latency, per-namespace teardown timing, and IP-allocation
  recovery after a crash are validated by design/accounting rather than by an
  automated soak harness (full jail creation is a privileged operation).

## OCI translation boundary (Phase 25)

- `internal/oci` is the only door through which OCI bundles become Jailor
  configs. Validation is **explicit-rejection**: any OCI field that would
  change security or runtime behavior but is not implemented — hooks, arbitrary
  `mounts`, seccomp filter objects, `terminal`/`consoleSize`, non-zero
  `process.user` uid/gid/umask/additionalGids, `uidMappings`/`gidMappings`,
  `sysctl`, `maskedPaths`/`readonlyPaths`, unknown/cgroup namespaces, non-zero
  `cpu.shares` — fails `Schema.validate()` with a descriptive error. A bundle
  is never admitted with parts of its policy silently dropped.
- Capabilities are merged from all four OCI capability sets (bounding,
  effective, permitted, inheritable) into a single keep-set, so a bundle that
  grants a capability in any set is never admitted weaker than it asked.
- `SeccompEnabled` treats `"seccomp": true` as "Jailor default policy" and a
  filter object as unsupported; there is no path where a requested seccomp
  object is accepted but not applied.
- `oci.Export` refuses to emit an unrepresentable configuration (invalid CPU
  quota/period, memory below a page, malformed caps) rather than emitting a
  `config.json` that would not round-trip.

See `docs/oci.md` and `docs/compat.md` for the matrix and full deviations.