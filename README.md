# compute-backend-landlock

Confining backend for [compute-protocol](https://github.com/egao1980/compute-protocol): Linux Landlock + seccomp + user/mount namespaces, bubblewrap when installed.

**Status:** skeleton. Milestone **R4d-2** of R4d — decisions locked in [cl-stack confinement.md](https://github.com/egao1980/cl-stack/blob/main/docs/capabilities/confinement.md). It implements the `confining-backend` protocol (`confinement-features`, `confinement-available-p`, `backend-confine-argv`) of compute-protocol 0.3.0 and must pass `compute-protocol/confinement-suite` on its OS.

## License

MIT
