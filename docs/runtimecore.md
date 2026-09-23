# Runtimecore: the process-supervision boundary layer

`internal/runtimecore` is the thin, testable slab that separates Jailor's
policies (Warden, Ledger, lifecycle) from the raw Linux syscalls beneath
them. It owns three things:

1. **Syscall mappings** — turning `wait(2)` statuses into Jailor's exit-code
   convention, reading `/proc` for alive/zombie/parent/namespace-pid facts.
2. **A 7-state supervisor** — a deterministic lifecycle model for one
   supervised process, with a fixed set of allowed transitions.
3. **Lifecycle events** — every transition publishes a typed `Event` on a
   buffered channel so peers (a Warden, a logger) can observe the process
   without coupling to the supervisor internals.

## The seven states

| State          | Meaning                                                            |
|----------------|--------------------------------------------------------------------|
| `CREATED`      | A supervisor exists; nothing has started.                         |
| `STARTING`     | `Start` was called; the process is being stood up.                |
| `RUNNING`      | `Admit` succeeded; the process is being supervised.               |
| `TERMINATING`  | The first termination signal was forwarded; grace period running. |
| `KILLING`      | SIGKILL was sent (grace expired, or a second signal arrived).     |
| `EXITED`       | The process was reaped; its exit code is captured. (terminal)     |
| `RECOVERED`    | The process was found already dead at admission. (terminal)       |

The allowed transitions are enforced by the pure function
`Transition(state, action)`, so both the supervisor and any external caller
validate against the same table.

## Escalation policy

The supervisor implements the two-step termination Jailor already uses in
production (`internal/jail/pid1_linux.go`):

1. `Terminate(sig)` forwards the signal and arms a grace timer
   (`DefaultEscalateAfter`, 3s).
2. The grace timer firing, a second `Terminate`, or an explicit `Kill`
   upgrades to SIGKILL.

The process is reaped exactly once; the supervisor exits its loop as soon as
it reaches a terminal state.

## Testability

The supervisor only ever touches the process through a tiny `Proc` interface
(`Pid`, `Signal`, `Exited`). Tests drive the *same* supervisor with a fake
process, so the whole state machine (grace escalation, second-signal
escalation, natural exit, recovered-at-admission, detach) is verified without
a namespace, a fork, or root. The race detector runs over it cleanly.

## Wiring

Today the boundary layer is actually used by the running system:

- `internal/jail` resolves the Prisoner's host PID via
  `runtimecore.ChildHostPID` (`FindPrisonerHostPID`).
- `internal/jail` maps wait statuses to exit codes via `runtimecore.ExitCode`.
- `internal/ledger` answers "is this record alive?" via
  `runtimecore.Alive` during recovery.

`runtimecore.Takeover` can adopt an already-running host process after a
Warden restart: it wraps the pid in a `Live` handle that signals it directly
and "reaps" it by watching `/proc` (a zombie counts as finished via
`IsZombie`). `Admit` then lands the supervisor in `RUNNING`, or `RECOVERED`
if the process is gone.