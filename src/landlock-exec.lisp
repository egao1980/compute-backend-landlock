;;;; landlock-exec.lisp — the Landlock trampoline (compute-backend-landlock).
;;;;
;;;;   runtime --core core --script landlock-exec.lisp --plan <plan> -- argv…
;;;;   runtime --core core --script landlock-exec.lisp --probe
;;;;
;;;; Run by this SBCL with --script: no ASDF, no Quicklisp, no systems — only
;;;; the core's own sb-alien (libc: syscall, prctl, setrlimit, mount, unshare,
;;;; execvp). It confines ITSELF (Landlock restricts the calling thread and
;;;; everything it execs) and then execs the command, so the confinement holds
;;;; for the command and every descendant. The plan and the step order are
;;;; specified in src/plan.lisp ("THE TRAMPOLINE"). Exit 126 = refused to
;;;; confine (nothing exec'd), 127 = execvp failed.
;;;;
;;;; Contract stub (R4d-2 pending): refuses everything.

(format *error-output* "landlock-exec: R4d-2 pending~%")
(finish-output *error-output*)
(sb-ext:exit :code 126 :abort t)
