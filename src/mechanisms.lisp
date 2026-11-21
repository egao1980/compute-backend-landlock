(in-package #:compute-backend-landlock)

;;; Mechanisms, best first. A LANDLOCK-BACKEND uses exactly one: the one asked
;;; for, or with :AUTO the highest-ranked available one. Its features are that
;;; mechanism's on that host — never a union, never "read-all and hope".
;;;
;;; :BWRAP (rank 20) — bubblewrap: a mount namespace builds the file view
;;;   (ro-bind / or the read set, binds for the writable set, a mode-0000
;;;   read-only tmpfs or /dev/null over deny-read entries), --unshare-net for
;;;   :NONE, --unshare-pid --die-with-parent, --new-session. When the confinement
;;;   needs what bwrap cannot do (limits, a port allowlist) the trampoline is
;;;   chained inside it with :FILESYSTEM NIL (CHAIN-TRAMPOLINE-P).
;;;     available: Linux, bwrap on PATH and usable.
;;;     features: :FILESYSTEM :READ-SYSTEM :DENY-READ :NETWORK-NONE :NETWORK-ALLOW,
;;;       :NETWORK-PORTS when ABI ≥ 4 and seccomp, the four limits.
;;; :LANDLOCK (rank 10) — the trampoline alone: Landlock for the filesystem
;;;   (an allow-list: read rules, write rules), user + mount namespaces for
;;;   deny-read, a net namespace or seccomp for :NONE, Landlock TCP rules +
;;;   seccomp (UDP) for ports, setrlimit for limits.
;;;     available: Linux and ABI ≥ 1.
;;;     features: :FILESYSTEM :READ-SYSTEM :NETWORK-ALLOW always; :DENY-READ with
;;;       user namespaces; :NETWORK-NONE with user namespaces or seccomp;
;;;       :NETWORK-PORTS when ABI ≥ 4 and seccomp; the four limits.
;;; :NETWORK-HOSTS is never offered (a filtering proxy, not in R4d).
;;; Features are listed in +CONFINEMENT-FEATURES+ order.
;;;
;;; Given: the table and MECHANISM-RANK. Stubbed: the rest.

(defparameter +mechanisms+
  '((:bwrap 20 "bubblewrap (mount, user, pid, net namespaces)")
    (:landlock 10 "Landlock trampoline (Landlock, seccomp, namespaces when allowed)"))
  "(name rank description), best first.")

(defun mechanism-rank (mechanism)
  "MECHANISM's rank (higher is preferred). Unknown → LANDLOCK-ERROR."
  (let ((entry (assoc mechanism +mechanisms+)))
    (unless entry
      (error 'landlock-error :message (format nil "unknown mechanism ~s (want ~{~s~^, ~})"
                                              mechanism (mapcar #'first +mechanisms+))))
    (second entry)))

(defun mechanism-available-p (mechanism host)
  "→ (values available-p reason): whether MECHANISM can confine on HOST, and when not a
string saying why (\"not Linux\", \"bwrap not found\", \"bwrap not usable …\",
\"Landlock ABI 0 …\"). Unknown MECHANISM → LANDLOCK-ERROR."
  (declare (ignore mechanism host))
  (%r4d2-pending 'mechanism-available-p))

(defun mechanism-features (mechanism host)
  "The confinement features MECHANISM enforces on HOST (see the table above); NIL when
it is not available there."
  (declare (ignore mechanism host))
  (%r4d2-pending 'mechanism-features))

(defun available-mechanisms (host)
  "The mechanisms available on HOST, best first."
  (declare (ignore host))
  (%r4d2-pending 'available-mechanisms))

(defun select-mechanism (requested host)
  "REQUESTED :AUTO → the best available mechanism on HOST or NIL; a mechanism name → it
when available, else NIL."
  (declare (ignore requested host))
  (%r4d2-pending 'select-mechanism))
