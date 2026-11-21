(in-package #:compute-backend-landlock/tests)

;;; Test support. Three kinds of test:
;;;   pure (DEFUNIX)  — planning from described hosts; every Unix (paths are
;;;                     Unix namestrings; Windows skips with a note)
;;;   Linux (DEFLINUX) — the real kernel; elsewhere one SKIP with a note
;;;   CI-strict        — COMPUTE_LANDLOCK_CI_MODE = bwrap | landlock | restricted
;;;                     (the repo's Linux VM jobs) turns "this mechanism is not
;;;                     available here, skip" into a failure: those jobs prove
;;;                     the mechanism, they must not skip it.

(defun linux-p () #+linux t #-linux nil)

(defun ci-mode ()
  "The CI job's mode keyword (:BWRAP :LANDLOCK :RESTRICTED) or NIL outside those jobs."
  (let ((v (uiop:getenv "COMPUTE_LANDLOCK_CI_MODE")))
    (and v (plusp (length v)) (intern (string-upcase v) '#:keyword))))

(defmacro defunix (name &body body)
  "A DEFTEST on Unix; on Windows one SKIP."
  `(deftest ,name
     (if (uiop:os-unix-p)
         (progn ,@body)
         (skip "planning tests use Unix paths: skipped on Windows"))))

(defmacro deflinux (name &body body)
  "A DEFTEST whose BODY runs on Linux only; elsewhere one SKIP with a note."
  `(deftest ,name
     (if (linux-p)
         (progn ,@body)
         (skip "Linux only (CI: the ubuntu-24.04 VM jobs bwrap / landlock / restricted)"))))

(defun require-mechanism (mechanism required-in)
  "On Linux: a backend for MECHANISM when it is available here. When not: in a CI mode
listed in REQUIRED-IN a failing assertion and NIL; otherwise a SKIP and NIL."
  (let ((backend (make-landlock-backend :mechanism mechanism)))
    (multiple-value-bind (ok reason) (sc:confinement-available-p backend)
      (cond (ok backend)
            ((member (ci-mode) required-in)
             (ok nil (format nil "CI mode ~(~a~) requires ~s: ~a" (ci-mode) mechanism reason))
             nil)
            (t (skip (format nil "~s unavailable here: ~a" mechanism reason))
               nil)))))

;;; Described hosts

(defparameter +merged-usr+
  '(("/bin" . "usr/bin") ("/sbin" . "usr/sbin") ("/lib" . "usr/lib") ("/lib64" . "usr/lib64"))
  "ROOT-SYMLINKS of a merged-/usr host (ubuntu-24.04): /bin /sbin /lib /lib64, that order.")

(defun full-host (&key (abi 6) (bwrap "/usr/bin/bwrap") (root-symlinks +merged-usr+))
  "Everything works: Landlock ABI, a usable bwrap, user namespaces, seccomp; merged /usr."
  (make-host-facts :landlock-abi abi :bwrap bwrap :bwrap-usable-p (and bwrap t)
                   :user-namespaces-p t :seccomp-p t :root-symlinks root-symlinks))

(defun restricted-host (&key (abi 4) (root-symlinks +merged-usr+))
  "GitHub's ubuntu-24.04 with AppArmor's userns restriction and no bwrap; merged /usr."
  (make-host-facts :landlock-abi abi :user-namespaces-p nil :seccomp-p t
                   :root-symlinks root-symlinks))

(defun host (&rest keys)
  (apply #'make-host-facts keys))

;;; Paths

(defun ns (p)
  "Native namestring of the physical path (directories end in /)."
  (uiop:native-namestring (sc:physical-path p)))

(defun bns (p)
  "As NS without the trailing / (bwrap argv form), \"/\" for the root."
  (let ((s (string-right-trim "/" (ns p))))
    (if (zerop (length s)) "/" s)))

(defun call-with-tree (fn)
  "FN on a fresh physical temp tree: area/ (with f), ro/ (with r and hidden/), outside/
\(victim), secrets/ (token), key (a file), deleted on exit."
  (let* ((base (sc:physical-path (uiop:temporary-directory)))
         (root (uiop:ensure-directory-pathname
                (merge-pathnames (format nil "landlock-test-~36r/" (random (expt 36 8) (make-random-state t)))
                                 base))))
    (ensure-directories-exist root)
    (unwind-protect
         (progn
           (dolist (d '("area/" "ro/" "ro/hidden/" "outside/" "secrets/"))
             (ensure-directories-exist (merge-pathnames d root)))
           (flet ((put (rel text)
                    (with-open-file (s (merge-pathnames rel root) :direction :output
                                                                  :if-exists :supersede)
                      (write-string text s))))
             (put "area/f" "f") (put "ro/r" "r") (put "ro/hidden/h" "h")
             (put "outside/victim" "original") (put "secrets/token" "secret") (put "key" "k"))
           (funcall fn (uiop:ensure-directory-pathname (truename root))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(defmacro with-tree ((var) &body body)
  `(call-with-tree (lambda (,var) ,@body)))

(defun sub (root rel)
  (merge-pathnames rel root))

(defun resolved (&rest keys)
  "MAKE-CONFINEMENT of KEYS, resolved (physical paths)."
  (sc:resolve-confinement (apply #'sc:make-confinement keys)))

(defun area-confinement (root &rest keys &key (read :all) (network :none) &allow-other-keys)
  "The tree's usual confinement: area writable, ro readable, secrets + key deny-read."
  ;; KEYS first: the first occurrence of a keyword wins, so they override the defaults.
  (apply #'resolved
         (append (loop for (k v) on keys by #'cddr
                       unless (member k '(:read :network)) append (list k v))
                 (list :writable (list (sub root "area/"))
                       :readable (list (sub root "ro/"))
                       :read read
                       :deny-read (list (sub root "secrets/") (sub root "key") (sub root "missing/"))
                       :network network))))

(defun ports-policy (&rest ports)
  (sc:make-sandbox-network-policy
   :egress (mapcar (lambda (p) (sc:make-egress-rule :host "*" :port p)) ports)))

(defun plan-keys (plan)
  (loop for k in plan by #'cddr collect k))

(defun rule-for (plan path)
  "The rights of PLAN's rule on PATH (a namestring), or :NONE when it has none."
  (let ((rule (assoc path (getf plan :rules) :test #'string=)))
    (if rule (cdr rule) :none)))

(defparameter +abi6-all-fs+
  '(:execute :write-file :read-file :read-dir :remove-dir :remove-file :make-char
    :make-dir :make-reg :make-sock :make-fifo :make-block :make-sym :refer :truncate
    :ioctl-dev))

(defparameter +all-limits+ '(:cpu-limit :memory-limit :file-size-limit :process-limit))

(defun stack-compute-dirs ()
  "The stack-compute-* private temp directories that exist now."
  (remove-if-not (lambda (d)
                   (let ((name (car (last (pathname-directory d)))))
                     (and (stringp name) (uiop:string-prefix-p "stack-compute-" name)
                          (not (uiop:string-prefix-p "stack-compute-suite-" name)))))
                 (uiop:subdirectories (sc:physical-path (uiop:temporary-directory)))))
