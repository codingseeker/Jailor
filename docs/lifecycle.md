# Jail lifecycle

A Jail moves through a small, explicit state machine that Jailor records in the
Ledger. State transitions are validated before they are applied, so a Jail can
never be started twice, stopped if it has no Prisoner, or deleted while it is
running.

```
             create()
   +---------------------+
   |                     |
   v                     |
 CREATED ----------> RUNNING -----> STOPPED
             start()        \          |
                             \         | delete() (CREATED only)
                              \        v
                               \      (removed)
                                \--> STOPPED --delete()--> (removed)
```

| Action | From          | To      | Effect                                   |
|--------|---------------|---------|------------------------------------------|
| create | —             | CREATED | Jail defined, no Prisoner, PID 0         |
| start  | CREATED       | RUNNING | Prisoner admitted and supervised        |
| stop   | RUNNING       | STOPPED | SIGTERM forwarded, waited for           |
| kill   | RUNNING       | STOPPED | SIGKILL forwarded, waited for           |
| delete | CREATED/STOPPED| —      | Ledger record removed (refuses RUNNING) |

## Lifecycle commands

```text
jailor jail create <command> [args...]    # -> CREATED
jailor jail start <id>                    # -> RUNNING, supervise to STOPPED
jailor jail stop <id>                     # SIGTERM -> STOPPED
jailor jail kill <id>                     # SIGKILL -> STOPPED
jailor jail delete <id>                   # CREATED/STOPPED -> (removed)
```

## Signal handling

The Warden installs no default signal handlers except those required to forward
the process-supervision signals (`SIGINT`, `SIGTERM`, `SIGQUIT`, `SIGHUP`) to the
Prisoner. Once the Prisoner is reaped, the forwarding channel is closed so a late
signal can never reach a process that no longer exists.

The timeout/context path sends `SIGKILL`, stops forwarding, and reaps the child.

## Failure scenarios

- **Bang before admission (spawn/start error):** the init never begins Jail setup;
  the Jail is marked STOPPED with a `spawn.failed`/`start.failed` log entry.
- **Rations or Gate allocation fails:** the init is blocked awaiting release and
  has not exec'd; the Warden kills and reaps it, logs `rations.failed`/
  `gate.failed`, and leaves the Jail STOPPED. The Jail is never admitted without
  its promised resources.
- **Init fails mid-setup:** the init tears down its mounts and signals an error;
  the Warden records `init.failed` and the actual exit code.
- **Prisoner exits:** the Warden reaps it and records the exit code and reason.
- **Idempotent recovery:** if a Box/Jail is found abandoned (no live Prisoner) the
  Ledger `Recover` sweeps cgroups and returns it to a clean state. See
  `docs/security.md` for cleanup guarantees.