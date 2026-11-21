# compute-backend-landlock

Confining backend for [compute-protocol](https://github.com/egao1980/compute-protocol) 0.3.0 on Linux: one command and everything it starts, kernel-enforced: the area read-write, a read policy for the rest, network off, a scrubbed environment, a private `TMPDIR`.

**Status:** 0.1.0 **contract** (R4d-2; stubs `%r4d2-pending`, failing tests). Decisions locked in [cl-stack confinement.md § R4d-2](https://github.com/egao1980/cl-stack/blob/main/docs/capabilities/confinement.md).

```lisp
(asdf:load-system "compute-backend-landlock")
(compute-protocol:run-confined (compute-backend-landlock:make-landlock-backend)
                               (compute-protocol:make-confinement :writable '("/work/area/"))
                               '("/bin/sh" "-c" "make test"))
```

`confine-command` never runs anything: the launch argv starts with the mechanism.

| Mechanism | Rank | When | How |
|-----------|------|------|-----|
| `:bwrap` | 20 | `bwrap` on PATH and usable (user namespaces allowed) | `bwrap --unshare-user --unshare-pid --die-with-parent --new-session [--unshare-net] --ro-bind / /` (or the read set), `--bind` the area and tmp, a mode-0000 read-only tmpfs / `/dev/null` over deny-read entries; the trampoline chained inside for limits and port rules |
| `:landlock` | 10 | Landlock ABI ≥ 1 | this SBCL runs `src/landlock-exec.lisp` with `--script`: namespaces when allowed, setrlimit, `no_new_privs`, seccomp, the Landlock ruleset for the running ABI, `restrict_self`, then `execvp` the command (no compiled helper, `sb-alien` only) |

Features depend on the host (`probe-host`): `:deny-read` needs a mount namespace (bwrap or the trampoline with user namespaces), since Landlock is an allow-list and cannot subtract; without one only `:read :system` is offered and `check-confinement` refuses read-all-minus-secrets. `:network-none` is a net namespace or, without namespaces, a seccomp filter on inet sockets. Port allowlists need Landlock ABI ≥ 4. `:network-hosts` is never offered.

## CI

`test.yml`: the canned matrix (macOS / Windows load and skip; Ubuntu in the `ci-base` container, where the backend must report itself unavailable cleanly) plus `linux-confinement` on the ubuntu-24.04 VM in three modes — `bwrap`, `landlock` (AppArmor `kernel.apparmor_restrict_unprivileged_userns=0`) and `restricted` (left at 1: Landlock + seccomp only). `COMPUTE_LANDLOCK_CI_MODE` makes the mode's tests fail instead of skipping; each job runs compute-protocol's `run-confinement-suite`.

## License

MIT
