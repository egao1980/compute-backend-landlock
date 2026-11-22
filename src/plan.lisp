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

;;; Path helpers (physical native namestrings; a directory ends in /)

(defun %ns (path)
  "PATH (pathname or namestring) as a physical native namestring."
  (uiop:native-namestring (sc:physical-path path)))

(defun %dir-ns-p (ns)
  (and (plusp (length ns)) (char= #\/ (char ns (1- (length ns))))))

(defun %bns (ns)
  "NS in bwrap argv form: no trailing /, except \"/\" itself."
  (let ((s (string-right-trim "/" ns)))
    (if (zerop (length s)) "/" s)))

(defun %existing-ns (path)
  "PATH's physical namestring when it exists (directory form for a directory), else NIL."
  (let ((p (sc:physical-path path)))
    (cond ((uiop:directory-exists-p p)
           (uiop:native-namestring (uiop:ensure-directory-pathname p)))
          ((uiop:file-exists-p p)
           (uiop:native-namestring p)))))

(defun %existing-namestrings (paths)
  (loop for p in paths
        for ns = (and p (%existing-ns p))
        when ns collect ns))

(defun %under-p (target entry)
  "TARGET is ENTRY or below it (ENTRY a directory namestring), or equals ENTRY."
  (if (%dir-ns-p entry)
      (or (uiop:string-prefix-p entry target)
          (string= target (subseq entry 0 (1- (length entry)))))
      (or (string= target entry)
          (and (%dir-ns-p target) (string= entry (subseq target 0 (1- (length target))))))))

(defun %overlap-p (a b)
  "One of A, B is the other or below it."
  (or (%under-p a b) (%under-p b a)))

(defun %mask-for (ns)
  (list (if (%dir-ns-p ns) :tmpfs :null) ns))

(defun %write-namestrings (resolved tmp)
  "WRITABLE, then the private TMP, then the system temp directory (TMP :SHARED)."
  (%existing-namestrings
   (append (sc:confinement-writable resolved)
           (and tmp (list tmp))
           (and (eq (sc:confinement-tmp resolved) :shared)
                (list (uiop:temporary-directory))))))

(defun %port-policy-p (network)
  (not (member network '(:none :allow))))

(defun %policy-ports (network)
  (sort (remove-duplicates (mapcar #'sc:egress-rule-port
                                   (sc:sandbox-network-policy-egress network)))
        #'<))

(defun %rlimits (resolved)
  (loop for (key value) in (list (list :cpu (sc:confinement-cpu-limit resolved))
                                 (list :as (sc:confinement-memory-limit resolved))
                                 (list :fsize (sc:confinement-file-size-limit resolved))
                                 (list :nproc (sc:confinement-process-limit resolved)))
        when value collect (cons key value)))

;;; The trampoline plan

(defun %trampoline-rules (resolved abi tmp)
  "((namestring . rights) …) in plan order; rules with no right are left out (the
kernel refuses an empty rule)."
  (let ((entries
          (append
           (mapcar (lambda (ns) (cons ns :read))
                   (if (eq (sc:confinement-read resolved) :all)
                       (list "/")
                       (%existing-namestrings
                        (append (sc:system-read-paths)
                                (sc:confinement-readable resolved)
                                (list (trampoline-pathname))))))
           (mapcar (lambda (ns) (cons ns :write)) (%write-namestrings resolved tmp))
           (mapcar (lambda (ns) (cons ns :device))
                   (%existing-namestrings sc:+device-paths+)))))
    (loop for (ns . kind) in entries
          for rights = (landlock-rights-for abi kind :file (not (%dir-ns-p ns)))
          when rights collect (cons ns rights))))

(defun %trampoline-masks (resolved rules)
  "The masks the deny-read entries need against RULES (see the plan's :MASKS)."
  (let ((read-all (eq (sc:confinement-read resolved) :all)))
    (loop for ns in (%existing-namestrings (sc:confinement-deny-read resolved))
          when (or read-all
                   (some (lambda (rule) (%overlap-p ns (car rule))) rules))
            collect (%mask-for ns))))

(defun %trampoline-network (network host chained)
  (cond ((eq network :allow) :allow)
        ((eq network :none)
         (cond (chained :allow)          ; bwrap --unshare-net
               ((%userns-p host) :namespace)
               ((%seccomp-p host) :seccomp)
               (t (error 'sc:confinement-unsupported :missing '(:network-none)))))
        (t (cons :ports (%policy-ports network)))))

(defun trampoline-plan (resolved host tmp &key chained)
  "The trampoline plan (above) for RESOLVED (a resolved, checked confinement) on HOST
with private temp directory TMP (a physical directory pathname or NIL). CHAINED: the
trampoline runs inside bwrap, which already built the file view and the network
namespace (:RULES, :UNSHARE, :MASKS NIL; NETWORK :NONE → :ALLOW)."
  (let* ((abi (host-landlock-abi host))
         (network (sc:confinement-network resolved))
         (rules (unless chained (%trampoline-rules resolved abi tmp)))
         (masks (unless chained (%trampoline-masks resolved rules)))
         (net (%trampoline-network network host chained)))
    (when (and masks (not (%userns-p host)))
      ;; Landlock cannot subtract: never an unmasked secret.
      (error 'sc:confinement-unsupported :missing '(:deny-read)))
    (let* ((mount (and masks t))
           (unshare-net (eq net :namespace))
           (unshare (when (and (not chained) (%userns-p host) (or mount unshare-net))
                      (append '(:user) (and mount '(:mount)) (and unshare-net '(:net))))))
      (list :abi abi
            :rules rules
            :unshare unshare
            :masks masks
            :network net
            :scopes (when (>= abi 6)
                      (if (eq network :allow) (list :signal) (abi-scopes abi)))
            :rlimits (%rlimits resolved)
            :no-new-privs t))))

(defun trampoline-argv (plan &key (runtime #+sbcl sb-ext:*runtime-pathname* #-sbcl nil)
                                  (core #+sbcl sb-ext:*core-pathname* #-sbcl nil)
                                  (script (trampoline-pathname)))
  "→ (runtime \"--core\" core \"--script\" script \"--plan\" printed-plan \"--\"), native
namestrings: the prefix that runs the trampoline with this SBCL. The command's argv
follows it."
  (unless (and runtime core)
    (error 'landlock-error :message "the trampoline needs an SBCL runtime and core"))
  (list (uiop:native-namestring runtime)
        "--core" (uiop:native-namestring core)
        "--script" (uiop:native-namestring script)
        "--plan" (print-trampoline-plan plan)
        "--"))

(defun chain-trampoline-p (resolved host)
  "True when bwrap alone cannot enforce RESOLVED on HOST and the trampoline is chained
inside it: a limit is set, or the network is a port policy."
  (declare (ignore host))
  (and (or (%rlimits resolved)
           (%port-policy-p (sc:confinement-network resolved)))
       t))

;;; bwrap

(defun %proc-or-dev-p (ns)
  (or (%under-p ns "/dev/") (%under-p ns "/proc/")))

(defun bwrap-argv (resolved host directory tmp)
  "The bwrap prefix for RESOLVED on HOST, start DIRECTORY (physical) and private TMP,
ending in \"--\". In this order:
  (host-bwrap host) --unshare-user --unshare-pid --die-with-parent --new-session
  --unshare-net                       ; NETWORK :NONE only
  --ro-bind / /                       ; READ :ALL
  | --ro-bind P P …                   ; READ :SYSTEM: each existing SYSTEM-READ-PATHS entry
                                      ;   not /dev or /proc (or below), then READABLE, then
                                      ;   the trampoline script when CHAIN-TRAMPOLINE-P
  --symlink TARGET PATH …             ; READ :SYSTEM: each (HOST-ROOT-SYMLINKS host) entry,
                                      ;   in host order, whose PATH is not already bound
  --dev /dev --proc /proc
  --bind W W …                        ; WRITABLE, then TMP, then the system temp dir (:SHARED)
  --perms 0000 --tmpfs D --remount-ro D | --ro-bind /dev/null F …
                                      ; each existing DENY-READ entry (READ :ALL), or each
                                      ;   overlapping a bound path (READ :SYSTEM)
  --chdir DIRECTORY --"
  (let* ((read-all (eq (sc:confinement-read resolved) :all))
         (reads (if read-all
                    (list "/")
                    (append (remove-if #'%proc-or-dev-p
                                       (%existing-namestrings (sc:system-read-paths)))
                            (%existing-namestrings (sc:confinement-readable resolved))
                            (when (chain-trampoline-p resolved host)
                              (%existing-namestrings (list (trampoline-pathname)))))))
         (writes (%write-namestrings resolved tmp))
         ;; --dev and --proc expose /dev and /proc too.
         (bound (append reads writes (list "/dev/" "/proc/")))
         (masks (loop for ns in (%existing-namestrings (sc:confinement-deny-read resolved))
                      when (or read-all (some (lambda (b) (%overlap-p ns b)) bound))
                        collect ns)))
    (append (list (host-bwrap host)
                  "--unshare-user" "--unshare-pid" "--die-with-parent" "--new-session")
            (when (eq (sc:confinement-network resolved) :none)
              (list "--unshare-net"))
            (loop for ns in reads
                  for b = (%bns ns)
                  append (list "--ro-bind" b b))
            (unless read-all
              (let ((bound-names (mapcar #'%bns reads)))
                (loop for (path . target) in (host-root-symlinks host)
                      unless (member path bound-names :test #'string=)
                        append (list "--symlink" target path))))
            (list "--dev" "/dev" "--proc" "/proc")
            (loop for ns in writes
                  for b = (%bns ns)
                  append (list "--bind" b b))
            (loop for ns in masks
                  for b = (%bns ns)
                  append (if (%dir-ns-p ns)
                             (list "--perms" "0000" "--tmpfs" b "--remount-ro" b)
                             (list "--ro-bind" "/dev/null" b)))
            (list "--chdir" (%bns (%ns directory)) "--"))))
