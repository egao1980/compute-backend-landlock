;;;; R4d-2 (cl-stack docs/capabilities/confinement.md): compute-protocol 0.3.0's
;;;; CONFINING-BACKEND on Linux. Two mechanisms, best first: bubblewrap when a
;;;; usable bwrap is installed, else the Landlock trampoline — this SBCL running
;;;; landlock-exec.lisp with --script, which confines itself and execs the
;;;; command. CONFINE-COMMAND never runs anything: the launch argv starts with
;;;; bwrap or the trampoline.

(defpackage #:compute-backend-landlock
  (:use #:cl)
  (:nicknames #:stack-compute-landlock)
  (:local-nicknames (#:sc #:compute-protocol))
  (:export
   ;; conditions
   #:landlock-error
   #:landlock-error-errno

   ;; the ABI ladder (abi.lisp)
   #:+landlock-fs-rights+
   #:+landlock-net-rights+
   #:+landlock-scopes+
   #:+landlock-file-rights+
   #:+landlock-read-rights+
   #:+landlock-max-abi+
   #:abi-fs-access
   #:abi-net-access
   #:abi-scopes
   #:abi-supports-p
   #:landlock-access-mask
   #:landlock-rights-for

   ;; the host (host.lisp)
   #:host-facts
   #:host-facts-p
   #:make-host-facts
   #:host-linux-p
   #:host-landlock-abi
   #:host-bwrap
   #:host-bwrap-usable-p
   #:host-user-namespaces-p
   #:host-seccomp-p
   #:host-arch
   #:landlock-abi
   #:probe-host

   ;; mechanisms (mechanisms.lisp)
   #:+mechanisms+
   #:mechanism-rank
   #:mechanism-available-p
   #:mechanism-features
   #:available-mechanisms
   #:select-mechanism

   ;; plans (plan.lisp)
   #:+trampoline-setup-exit+
   #:+trampoline-exec-exit+
   #:trampoline-pathname
   #:trampoline-plan
   #:print-trampoline-plan
   #:read-trampoline-plan
   #:trampoline-argv
   #:bwrap-argv
   #:chain-trampoline-p

   ;; the backend (backend.lisp)
   #:landlock-backend
   #:make-landlock-backend
   #:landlock-backend-requested
   #:landlock-backend-host
   #:backend-mechanism
   #:use-landlock-backend))

(in-package #:compute-backend-landlock)
