(in-package #:compute-backend-landlock)

;;; Pure planning: from a resolved confinement (RESOLVE-CONFINEMENT, physical
;;; paths), a HOST-FACTS and the launch's private temp directory to the argv
;;; prefix that confines. Nothing here touches the kernel; existence checks
;;; (a deny-read entry, a device, a read path that is not there) read the
;;; file system only.
;;;
;;; Namestrings in plans: native, physical, a directory ends in "/", a file
;;; does not. Namestrings in bwrap argv: the same without the trailing "/"
;;; (except "/" itself).
;;;
;;; THE TRAMPOLINE PLAN (TRAMPOLINE-PLAN) is a plist, every key present, in
;;; this order, printed into the trampoline's argv (PRINT-TRAMPOLINE-PLAN):
;;;   :ABI      the host's Landlock ABI (the ruleset handles exactly ABI-FS-ACCESS,
;;;             ABI-NET-ACCESS when :NETWORK is a port list, ABI-SCOPES)
;;;   :RULES    ((namestring . rights) …) path-beneath rules, NIL when CHAINED.
;;;             READ :ALL → ("/" . read rights). READ :SYSTEM → each existing entry of
;;;             SYSTEM-READ-PATHS, READABLE and the trampoline script, :READ rights.
;;;             Then each WRITABLE, the private TMP, the system temp directory for TMP
;;;             :SHARED: :WRITE rights. Then each existing +DEVICE-PATHS+ file: :DEVICE
;;;             rights. Rights from LANDLOCK-RIGHTS-FOR (ABI, FILE for non-directories).
;;;             ABI < 2: no :REFER anywhere, so the kernel refuses every cross-directory
;;;             rename and link (the rename/hardlink laws hold by refusal).
;;;   :UNSHARE  a subset of (:USER :MOUNT :NET), in that order; NIL when CHAINED or
;;;             the host has no user namespaces. :USER whenever :MOUNT or :NET is in it.
;;;             :MOUNT when :MASKS is non-empty. :NET for NETWORK :NONE.
;;;   :MASKS    ((:TMPFS dir) | (:NULL file) …) for each existing DENY-READ entry that
;;;             must be hidden: READ :ALL — every one; READ :SYSTEM — the ones that
;;;             overlap a :RULES entry (one is the other or below it; a deny entry
;;;             nothing granted reaches is already unreadable under Landlock). A mask
;;;             needed on a host without user namespaces → CONFINEMENT-UNSUPPORTED
;;;             (MISSING (:DENY-READ)), never an unmasked secret. NIL when CHAINED.
;;;   :NETWORK  :ALLOW (nothing to do; also NETWORK :NONE when CHAINED — bwrap
;;;             unshared the net), :NAMESPACE (NETWORK :NONE, :NET unshared),
;;;             :SECCOMP (NETWORK :NONE without user namespaces: socket(2) of
;;;             AF_INET, AF_INET6, AF_PACKET fails with EACCES), or (:PORTS p …) for a
;;;             port policy (ascending, no duplicates: Landlock TCP connect rules, bind
;;;             handled and denied, seccomp refusing SOCK_DGRAM / SOCK_RAW inet sockets)
;;;   :SCOPES   ABI ≥ 6: (:ABSTRACT-UNIX-SOCKET :SIGNAL), or (:SIGNAL) for NETWORK :ALLOW;
;;;             else NIL
;;;   :RLIMITS  ((:CPU . seconds) (:AS . bytes) (:FSIZE . bytes) (:NPROC . n)) — the
;;;             limits that are set, in this order
;;;   :NO-NEW-PRIVS T
;;; One more key exists for tests only and TRAMPOLINE-PLAN never writes it:
;;;   :SPAWN-THREADS n — the trampoline starts N idle threads before its
;;;   single-thread check (so the refusal can be observed).
;;;
;;; THE TRAMPOLINE (landlock-exec.lisp, `runtime --core core --script it --plan
;;; <plan> -- argv…`) in this order: read the plan (*READ-EVAL* NIL); when
;;; :UNSHARE is non-empty refuse unless the process is single-threaded
;;; (/proc/self/task has one entry; stop SBCL's finalizer thread first), then
;;; unshare, write setgroups "deny", uid_map/gid_map (same ids), make / rprivate,
;;; apply :MASKS (tmpfs mode 0000 then remount read-only; bind /dev/null read-only);
;;; setrlimit; prctl(PR_SET_NO_NEW_PRIVS); the seccomp filter (:SECCOMP, :PORTS);
;;; when :RULES or :NETWORK (:PORTS …) or :SCOPES: create the ruleset, add each rule
;;; whose path exists (O_PATH | O_CLOEXEC), restrict_self; then execvp argv with the
;;; environment it was given. A setup step that fails → "landlock-exec: <step>:
;;; <reason>" on stderr, exit +TRAMPOLINE-SETUP-EXIT+, nothing exec'd (never half
;;; confined). execvp failing → exit +TRAMPOLINE-EXEC-EXIT+.
;;; `… --script landlock-exec.lisp --probe` prints one plist to stdout and exits 0:
;;; (:abi n :user-namespaces-p b :seccomp-p b :arch kw) — the namespace check runs
;;; in that probe process (unshare, maps, a tmpfs mount, a net namespace).
;;;
;;; Given: the exit codes, TRAMPOLINE-PATHNAME, PRINT-/READ-TRAMPOLINE-PLAN.
;;; Stubbed: TRAMPOLINE-PLAN, TRAMPOLINE-ARGV, BWRAP-ARGV, CHAIN-TRAMPOLINE-P.

(defconstant +trampoline-setup-exit+ 126
  "The trampoline's exit status when it refused to confine (nothing was exec'd).")

(defconstant +trampoline-exec-exit+ 127
  "The trampoline's exit status when it confined itself but execvp failed.")

(defun trampoline-pathname ()
  "landlock-exec.lisp in this system's src/ directory (physical)."
  (sc:physical-path (asdf:system-relative-pathname "compute-backend-landlock"
                                                   "src/landlock-exec.lisp")))

(defun print-trampoline-plan (plan)
  "PLAN as the one argv string the trampoline reads (standard syntax, keywords)."
  (with-standard-io-syntax
    (let ((*print-readably* nil)
          (*package* (find-package '#:keyword)))
      (prin1-to-string plan))))

(defun read-trampoline-plan (string)
  "The plan PRINT-TRAMPOLINE-PLAN printed (*READ-EVAL* NIL)."
  (with-standard-io-syntax
    (let ((*read-eval* nil)
          (*package* (find-package '#:keyword)))
      (read-from-string string))))

(defun trampoline-plan (resolved host tmp &key chained)
  "The trampoline plan (above) for RESOLVED (a resolved, checked confinement) on HOST
with private temp directory TMP (a physical directory pathname or NIL). CHAINED: the
trampoline runs inside bwrap, which already built the file view and the network
namespace (:RULES, :UNSHARE, :MASKS NIL; NETWORK :NONE → :ALLOW)."
  (declare (ignore resolved host tmp chained))
  (%r4d2-pending 'trampoline-plan))

(defun trampoline-argv (plan &key (runtime #+sbcl sb-ext:*runtime-pathname* #-sbcl nil)
                                  (core #+sbcl sb-ext:*core-pathname* #-sbcl nil)
                                  (script (trampoline-pathname)))
  "→ (runtime \"--core\" core \"--script\" script \"--plan\" printed-plan \"--\"), native
namestrings: the prefix that runs the trampoline with this SBCL. The command's argv
follows it."
  (declare (ignore plan runtime core script))
  (%r4d2-pending 'trampoline-argv))

(defun chain-trampoline-p (resolved host)
  "True when bwrap alone cannot enforce RESOLVED on HOST and the trampoline is chained
inside it: a limit is set, or the network is a port policy."
  (declare (ignore resolved host))
  (%r4d2-pending 'chain-trampoline-p))

(defun bwrap-argv (resolved host directory tmp)
  "The bwrap prefix for RESOLVED on HOST, start DIRECTORY (physical) and private TMP,
ending in \"--\". In this order:
  (host-bwrap host) --unshare-user --unshare-pid --die-with-parent --new-session
  --unshare-net                       ; NETWORK :NONE only
  --ro-bind / /                       ; READ :ALL
  | --ro-bind P P …                   ; READ :SYSTEM: each existing SYSTEM-READ-PATHS entry
                                      ;   not /dev or /proc (or below), then READABLE, then
                                      ;   the trampoline script when CHAIN-TRAMPOLINE-P
  --dev /dev --proc /proc
  --bind W W …                        ; WRITABLE, then TMP, then the system temp dir (:SHARED)
  --perms 0000 --tmpfs D --remount-ro D | --ro-bind /dev/null F …
                                      ; each existing DENY-READ entry (READ :ALL), or each
                                      ;   overlapping a bound path (READ :SYSTEM)
  --chdir DIRECTORY --"
  (declare (ignore resolved host directory tmp))
  (%r4d2-pending 'bwrap-argv))
