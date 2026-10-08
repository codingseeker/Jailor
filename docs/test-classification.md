# Jailor test classification

Jailor tests are split into three compile-time tiers. The tier is a Go build
tag, so a test that belongs to a different tier is not merely skipped, it is not
even compiled into that tier's test binary. There is no `-run` exclusion and no
runtime skip that hides a missing capability check.

| Build tag | Job | Command |
| --- | --- | --- |
| *(none)* | `verify` | `go test ./...` |
| `jailor_priv` | `rootful` | `sudo -E go test -tags jailor_priv ./...` |
| `jailor_rootless` | `rootless` | `go test -tags jailor_rootless ./...` |

`internal/jail/harness_linux_test.go` and `internal/prisoner/visit_test.go`
carry the shared harness (`TestMain`, the in-jail `probe` program, `syncBuf`,
`parseKV`) with no privilege tag, so each tier builds exactly one test binary.
The probe program contains `mount`, `unshare`, `chroot` and `clone` calls
because it runs *inside* a jail to prove those are denied. It is never executed
in a tier that does not spawn a jail.

## Why every jail spawn is privileged

`internal/jail/init.go` calls `makeMountsPrivate()` as the first thing the jail
stager does, before any device, tmpfs or Cell work:

```go
func makeMountsPrivate() error {
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("jail: make mount tree private: %w", err)
	}
	return nil
}
```

That is `mount(2)` with `MS_REC|MS_PRIVATE`, which requires `CAP_SYS_ADMIN` over
the user namespace that owns the mount namespace. There is no configuration in
which a jail is created without it, so **any test that spawns a jail is
ROOTFUL-REQUIRED**. That is a property of the kernel, not of Jailor's
configuration, and it is deliberately not worked around: weakening the
propagation step would let a jail's mounts escape into the host, which is
exactly the isolation Jailor exists to provide.

## Why the unprivileged CI runner fails that call

On `ubuntu-24.04`, `kernel.apparmor_restrict_unprivileged_userns=1` is enabled
by default. An unconfined process that creates a user namespace is moved into
the AppArmor `unprivileged_userns` profile, which denies `mount`, `umount`,
`pivot_root` and `capable`. The `mount(2)` above therefore returns `EACCES`
(Go renders this as `permission denied`; `EPERM` renders as `operation not
permitted`), and the failure surfaces as:

```text
jail stager: jail: make mount tree private: permission denied
```

before the prisoner is ever executed. The runtime is correct; the environment is
restricted. Running the same suite as real root through `sudo` places the
process outside the `unprivileged_userns` restriction and the call succeeds, so
the suite belongs in the rootful job.

## Fail-closed policy for the privileged tier

No test in the `jailor_priv` tier contains `t.Skip`. Every precondition that the
rootful job verifies in its preflight (host root, namespace creation, cgroup v2,
`sleep`, `python3`, `iptables`, a prepared Cell rootfs) is asserted with
`t.Fatalf` instead. A regression in the runner's privileges therefore fails the
suite loudly rather than silently reducing coverage.

## Classification

`Host root` is whether the test needs euid 0. `Mount` is whether it needs
`CAP_SYS_ADMIN` over its mount namespace. `NS` is whether it needs an
unprivileged user namespace. `Cgroup` is whether it writes to the cgroup v2
hierarchy. `Netns` is whether it configures network namespaces or interfaces.

### internal/jail unit tier (no tag, `verify`)

All of these exercise pure in-process logic: capability mask arithmetic, seccomp
BPF construction interpreted in userspace, prisoner environment filtering,
`fcntl(F_SETFD)` flags. No namespace, mount, cgroup, `setns` or device syscall.

| Test | Host root | Required kernel feature | Job |
| --- | --- | --- | --- |
| `TestCapMaskForNoCapabilities` | no | none (bitmask arithmetic) | verify |
| `TestCapMaskForSingleCapability` | no | none | verify |
| `TestCapMaskForMultipleCapabilities` | no | none | verify |
| `TestCapMaskForHighestCapability` | no | none | verify |
| `TestCapMaskForInvalidCapability` | no | none | verify |
| `TestCapMaskRejectsInvalidAlongsideValid` | no | none | verify |
| `TestCapMaskForDuplicateCapabilities` | no | none | verify |
| `TestCapMaskCoversEveryKnownCapability` | no | none | verify |
| `TestCapNameLookup` | no | none | verify |
| `TestCapNumberUnknown` | no | none | verify |
| `TestApplyCapabilityPolicyRejectsUnknown` | no | none | verify |
| `TestApplyCapabilityPolicyRejectsInvalidTransition` | no | none | verify |
| `TestDenyFilterShape` | no | none (BPF program shape) | verify |
| `TestDefaultProfileDeniesForbiddenSyscalls` | no | none | verify |
| `TestDefaultProfileAllowsOrdinarySyscalls` | no | none | verify |
| `TestDefaultProfileAllowsThreadCreation` | no | none | verify |
| `TestDefaultProfileDeniesNamespaceCreation` | no | none | verify |
| `TestProfileRejectsForeignArchitecture` | no | none | verify |
| `TestStrictProfileAllowsOnlyListedSyscalls` | no | none | verify |
| `TestBuildSeccompFilterProfiles` | no | none | verify |
| `TestSeccompProfileNameResolution` | no | none | verify |
| `TestSeccompRequested` | no | none | verify |
| `TestPrisonerEnvironmentDropsCredentials` | no | none | verify |
| `TestPrisonerEnvironmentDropsSecretShapedVariables` | no | none | verify |
| `TestPrisonerEnvironmentKeepsOrdinaryVariables` | no | none | verify |
| `TestPrisonerEnvironmentControlsPath` | no | none | verify |
| `TestPrisonerEnvironmentControlsIdentity` | no | none | verify |
| `TestPrisonerEnvironmentHonoursConfiguredPath` | no | none | verify |
| `TestPrisonerEnvironmentStripsCredentialsEvenWhenExplicitlyListed` | no | none | verify |
| `TestPrisonerEnvironmentStripsRuntimeInternals` | no | none | verify |
| `TestJailInitEnvironmentCarriesInternals` | no | none | verify |
| `TestCloseInheritedDescriptorsMarksDescriptors` | no | none (`fcntl(F_SETFD)` only) | verify |

### internal/jail rootless tier (`jailor_rootless`, `rootless`)

These exercise Jailor on the real filesystem and issue no namespace, mount,
`pivot_root`, device, cgroup or `setns` syscall, so they run unprivileged.

| Test | Host root | Mount | NS | Cgroup | Netns | Job |
| --- | --- | --- | --- | --- | --- | --- |
| `TestPathTraversalCellRejected` | no | no | no | no | no | rootless |
| `TestCellRootIsHostRejected` | no | no | no | no | no | rootless |
| `TestCellSymlinkToRootRejected` | no | no | no | no | no | rootless |

### internal/jail privileged tier (`jailor_priv`, `rootful`)

Every test below spawns a jail, so every one of them needs
`mount(MS_REC|MS_PRIVATE)` and therefore `CAP_SYS_ADMIN` in its mount namespace.
The extra columns list the *additional* kernel features the test exercises.

| Test | Host root | Mount | NS | Cgroup | Netns | Required kernel feature | Job |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `TestPIDIsolation` | no | yes | user + pid | no | no | `CLONE_NEWUSER`, `CLONE_NEWPID`, `mount` | rootful |
| `TestPIDDiffersFromHost` | no | yes | user + pid | no | no | `CLONE_NEWUSER`, `CLONE_NEWPID`, `mount` | rootful |
| `TestUTSIsolation` | no | yes | user + uts | no | no | `sethostname`, `CLONE_NEWUTS`, `mount` | rootful |
| `TestNetworkIsolation` | no | yes | user + net | no | yes | `CLONE_NEWNET`, `mount` | rootful |
| `TestUserNamespaceMapping` | no | yes | user | no | no | `CLONE_NEWUSER` plus `uid_map`, `mount` | rootful |
| `TestProcShowsJailPID1` | no | yes | user + pid | no | no | `mount` of `proc`, `pivot_root` | rootful |
| `TestInitIsJailPID1` | no | yes | user + pid | no | no | `pivot_root`, `mount` of `proc` | rootful |
| `TestExitCodeSignal` | no | yes | user | no | no | `mount`, signal delivery across `CLONE_NEWPID` | rootful |
| `TestOrphanReaping` | no | yes | user + pid | no | no | pid 1 reaping semantics | rootful |
| `TestPrisonerIsChildOfInit` | no | yes | user + pid | no | no | pidfd plus `mount` | rootful |
| `TestTerminateEscalatesToKill` | no | yes | user + pid | no | no | signal escalation, `mount` | rootful |
| `TestTmpDirCreated` | no | yes | user | no | no | `mount` of `tmpfs` | rootful |
| `TestDevMinimal` | no | yes | user | no | no | `mknod`, `mount` of `tmpfs`, bind mounts | rootful |
| `TestPsCountsOnlyJailProcesses` | no | yes | user + pid | no | no | `pivot_root`, `mount` of `proc` | rootful |
| `TestCapabilitiesDropped` | no | yes | user | no | no | `capset` inside the jail, `mount` | rootful |
| `TestSeccompDeniesForbiddenSyscall` | no | yes | user | no | no | `seccomp(SET_MODE_FILTER)`, `mount` | rootful |
| `TestUnknownSeccompProfileFailsClosed` | no | yes | user | no | no | `seccomp`, `mount` | rootful |
| `TestUnknownLSMFailsClosed` | no | yes | user | no | no | AppArmor profile transition, `mount` | rootful |
| `TestNamespaceLeakage` | no | yes | user + pid + uts | no | no | `mount` of `proc`, `sethostname` | rootful |
| `TestNetworkBarIsolates` | no | yes | user + net | no | yes | `CLONE_NEWNET`, `mount` | rootful |
| `TestCapabilitySetsAfterPolicy` | no | yes | user | no | no | `capset`/`prctl`, `mount` | rootful |
| `TestNoCapabilitiesYieldsEmptySet` | no | yes | user | no | no | `capset`, `mount` | rootful |
| `TestUnknownCapabilityFailsClosed` | no | yes | user | no | no | capability parsing failure path, `mount` | rootful |
| `TestPrisonerDoesNotSeeCredentials` | no | yes | user | no | no | `execve` environment, `mount` | rootful |
| `TestStdoutForwarding` | no | yes | user | no | no | `mount`, fd inheritance | rootful |
| `TestStderrForwarding` | no | yes | user | no | no | `mount`, fd inheritance | rootful |
| `TestStdinForwarding` | no | yes | user | no | no | `mount`, fd inheritance | rootful |
| `TestEnvironmentPropagation` | no | yes | user | no | no | `execve` environment, `mount` | rootful |
| `TestExitCodeZero` | no | yes | user | no | no | `mount` | rootful |
| `TestNonZeroExitCode` | no | yes | user | no | no | `mount` | rootful |
| `TestCommandNotFound` | no | yes | user | no | no | `mount` | rootful |
| `TestSigtermHandling` | no | yes | user + pid | no | no | signal delivery across `CLONE_NEWPID`, `mount` | rootful |
| `TestSigintHandling` | no | yes | user + pid | no | no | signal delivery across `CLONE_NEWPID`, `mount` | rootful |
| `TestKillHandling` | no | yes | user + pid | no | no | signal delivery across `CLONE_NEWPID`, `mount` | rootful |
| `TestChildCleanup` | no | yes | user + pid | no | no | pid namespace teardown, `mount` | rootful |
| `TestSpaceInArgs` | no | yes | user | no | no | `execve` argv, `mount` | rootful |
| `TestEscapeUnauthorizedMountIsDenied` | no | yes | user | no | no | `mount` denied by capability mask | rootful |
| `TestEscapeUnshareIsDeniedWithoutSysAdmin` | no | yes | user | no | no | `unshare` denied by capability mask | rootful |
| `TestEscapeNamespaceCloneIsDeniedWithoutSysAdmin` | no | yes | user | no | no | `clone` with `CLONE_NEWNS` denied | rootful |
| `TestEscapeSeccompDeniesUnshare` | no | yes | user | no | no | `seccomp`, `mount` | rootful |
| `TestEscapeSeccompDeniesPtrace` | no | yes | user | no | no | `seccomp`, `ptrace` denial, `mount` | rootful |
| `TestEscapeSeccompAllowsOrdinaryWork` | no | yes | user | no | no | `seccomp`, `mount` | rootful |
| `TestEscapeSetuidCannotRaisePrivileges` | no | yes | user | no | no | `setresuid` in the jail, `no_new_privs`, `mount` | rootful |
| `TestEscapeDeviceAccessToHostDevicesDenied` | no | yes | user | no | no | `mknod`, device masking, `mount` | rootful |
| `TestEscapeMountPropagationStaysPrivate` | no | yes | user | no | no | `MS_REC|MS_PRIVATE` propagation privatization | rootful |
| `TestEscapeNetworkNamespaceIsIsolated` | no | yes | user + net | no | yes | `CLONE_NEWNET`, `mount` | rootful |
| `TestEscapeFDLeakage` | no | yes | user | no | no | CLOEXEC across `execve`, `mount` | rootful |
| `TestReadOnlyCellRejectsHostRoot` | no | yes | user | no | no | `pivot_root` plus `MS_REMOUNT` refusal path | rootful |
| `TestReadOnlyCell` | yes | yes | user | no | no | `pivot_root` plus `MS_REMOUNT|MS_RDONLY` | rootful |
| `TestReadOnlyCellUserNamespace` | yes | yes | user | no | no | `pivot_root`, `MS_REMOUNT|MS_RDONLY`, `mknod` | rootful |
| `TestReadOnlyCellKeepsCellReadable` | yes | yes | user | no | no | `pivot_root`, `MS_REMOUNT|MS_RDONLY` | rootful |
| `TestEscapeOldRootIsInaccessible` | yes | yes | user + pid | no | no | `pivot_root`, `MNT_DETACH` of the old root | rootful |
| `TestEscapeOldRootMountPointRemoved` | yes | yes | user + pid | no | no | `pivot_root`, `umount2(MNT_DETACH)` | rootful |
| `TestEscapeHostRootNotVisibleInCell` | yes | yes | user | no | no | `pivot_root` filesystem isolation | rootful |
| `TestEscapeParentTraversalIsContained` | yes | yes | user | no | no | `pivot_root` path containment | rootful |
| `TestEscapeSymlinkTraversalIsContained` | yes | yes | user | no | no | `pivot_root` path containment | rootful |
| `TestCellRootFilesAreReachable` | yes | yes | user | no | no | `pivot_root`, Cell contents | rootful |
| `TestEscapeHostProcIsNotVisibleInCell` | yes | yes | user + pid | no | no | `pivot_root`, `mount` of `proc` | rootful |
| `TestEscapeSecretFileNotReachableInCell` | yes | yes | user | no | no | `pivot_root` filesystem isolation | rootful |
| `TestEscapeSysIsNotVisibleInCell` | yes | yes | user | no | no | `pivot_root` filesystem isolation | rootful |

### internal/prisoner

| Test | Privilege | Host root | Mount | NS | Required kernel feature | Job |
| --- | --- | --- | --- | --- | --- | --- |
| `TestEnterFailsForStalePid` | rootless | no | no | no | none; `setns` on a dead pid must fail | rootless |
| `TestExecEntersSameUTS` | rootful | yes | yes | user + uts | `setns` into another process's UTS namespace | rootful |
| `TestExecSharesNamespaces` | rootful | yes | yes | user + mnt + uts + ipc + pid + net | `setns` into every jail namespace | rootful |

### internal/rations

| Test | Privilege | Host root | Cgroup | Required kernel feature | Job |
| --- | --- | --- | --- | --- | --- |
| `TestParseMemory`, `TestHumanBytes` | rootless | no | no | none (string parsing) | verify |
| `TestCgroupRoundTrip` | rootful | yes | yes | cgroup v2 `memory.max` / `pids.max` | rootful |
| `TestMemoryLimitEnforced` | rootful | yes | yes | cgroup v2 `memory.max` / `memory.events` | rootful |
| `TestPIDLimitEnforced` | rootful | yes | yes | cgroup v2 `pids.max` / `pids.current` | rootful |
| `TestCPULimitRestricts` | rootful | yes | yes | cgroup v2 `cpu.max` / `cpu.stat` | rootful |

### internal/gate

| Test | Privilege | Host root | Netns | Required kernel feature | Job |
| --- | --- | --- | --- | --- | --- |
| `TestNew`, `TestValidate`, `TestAllocate*`, `TestHostVethName`, `TestBaseIP`, `TestGatewayOf`, `TestTeardownNilSafe`, … | rootless | no | no | none (name and IP allocation arithmetic) | verify |
| `TestBridgeCreateAndDelete` | rootful | yes | yes | `CAP_NET_ADMIN`, bridge netlink | rootful |
| `TestVethPairCreateAndDelete` | rootful | yes | yes | `CAP_NET_ADMIN`, veth netlink | rootful |
| `TestBridgeIdempotentCreate` | rootful | yes | yes | `CAP_NET_ADMIN` | rootful |
| `TestSetLinkMaster` | rootful | yes | yes | `RTM_SETLINK` | rootful |
| `TestAddAddrToInterface` | rootful | yes | yes | address netlink | rootful |
| `TestSweepRemovesOrphans`, `TestSweepPreservesRunning` | rootful | yes | yes | netlink enumeration | rootful |
| `TestTeardownRemovesVeth`, `TestTeardownAllRemovesEverything`, `TestEnsureBridgeAddrIdempotent` | rootful | yes | yes | netlink deletion | rootful |
| `TestDefaultEgressIface`, `TestIptablesRules` | rootful | yes | yes | route lookup, `iptables` | rootful |
| `TestGateBridgeSetupAndConnectivity` | rootful | yes | yes | bridge, veth, routing, `ping` | rootful |
| `TestGateSetupMissingPid`, `TestGateSetupNone`, `TestGateTeardownIdempotent` | rootful | yes | yes | `CLONE_NEWNET`, netlink | rootful |

### internal/warden

| Test | Privilege | Host root | Cgroup | Required kernel feature | Job |
| --- | --- | --- | --- | --- | --- |
| `TestRecoverIdempotent`, `TestRecoverSkipsLivePrisoner`, `TestDeleteIsIdempotentAfterRecordGone` | rootless | no | no | none (ledger files) | verify |
| `TestSweepCgroupsKeepsRunning` | rootful | yes | yes | write access to cgroup v2 | rootful |

## Known defect in the Cell path

Twelve privileged tests drive a jail with `Rootfs` set, that is
`pivot_root` into a Cell. They currently fail with:

```text
jail: locate self: readlink /proc/self/exe: no such file or directory
```

Cause, in `internal/jail/init.go`: `stagerLaunch` calls `enterCell(cfg)` at line
127, which `pivot_root`s the stager into the Cell and detaches the old root,
and only then calls `os.Executable()` at line 173 to build the jail-init exec
spec. After `pivot_root` the Cell's `/proc` is an empty directory, so
`readlink /proc/self/exe` fails with `ENOENT`. Resolving the path earlier is not
sufficient on its own: the resolved host path is outside the Cell, so the
`execve` of the jail init performed by the raw child in `internal/jail/raw_linux.go`
would then fail with `ENOENT` instead. Either the jail init must be staged into
the Cell before `pivot_root`, or it must be exec'd through a descriptor that was
opened before `pivot_root`. Both are runtime design decisions, so they are
recorded here rather than changed.

The tests are left in the privileged tier with no skip, so the failure is
reported by name instead of being silently hidden.

## Adding a test

Pick the tier from what the test actually does, then give it the matching build
tag and add it to the table above. Do not add a `t.Skip` for an unavailable
privilege: if the test needs a privileged kernel operation it belongs in the
`jailor_priv` tier and the rootful job, and the rootful job fails outright when
the privilege is missing rather than skipping the test.