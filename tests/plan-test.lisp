(in-package #:compute-backend-landlock/tests)

;;; Trampoline plans from confinements: pure (described hosts), every Unix.

(defparameter +plan-keys+ '(:abi :rules :unshare :masks :network :scopes :rlimits :no-new-privs))

(defun tmp-of (root)
  "A stand-in private temp directory inside ROOT (exists, physical)."
  (ensure-directories-exist (sub root "stack-compute-0123456789abcdef/")))

(defunix plan-shape
  (with-tree (root)
    (let ((plan (trampoline-plan (area-confinement root) (full-host) (tmp-of root))))
      (ok (equal +plan-keys+ (plan-keys plan)) "every key, in order")
      (ok (= 6 (getf plan :abi)))
      (ok (eq t (getf plan :no-new-privs))))))

(defunix plan-read-all-rules
  (with-tree (root)
    (let* ((tmp (tmp-of root))
           (plan (trampoline-plan (area-confinement root) (full-host) tmp)))
      (ok (equal '(:execute :read-file :read-dir) (rule-for plan "/")) "/ readable")
      (ok (equal +abi6-all-fs+ (rule-for plan (ns (sub root "area/")))) "area: every right")
      (ok (equal +abi6-all-fs+ (rule-for plan (ns tmp))) "private tmp: every right")
      (ok (equal '(:write-file :read-file :truncate :ioctl-dev) (rule-for plan (ns "/dev/null")))
          "devices")
      (ok (eq :none (rule-for plan (ns (sub root "outside/")))) "outside: no rule"))))

(defunix plan-read-system-rules
  (with-tree (root)
    (let* ((c (area-confinement root :read :system
                                     :readable (list (sub root "ro/") (sub root "outside/victim"))))
           (plan (trampoline-plan c (full-host) (tmp-of root))))
      (ok (eq :none (rule-for plan "/")) "no / rule")
      (dolist (p (sc:system-read-paths))
        (ok (equal '(:execute :read-file :read-dir) (rule-for plan (ns p))) (ns p)))
      (ok (equal '(:execute :read-file :read-dir) (rule-for plan (ns (sub root "ro/")))))
      (ok (equal '(:execute :read-file) (rule-for plan (ns (sub root "outside/victim"))))
          "a readable file: file rights only")
      (ok (equal '(:execute :read-file) (rule-for plan (ns (trampoline-pathname))))
          "the trampoline script")
      (ok (equal +abi6-all-fs+ (rule-for plan (ns (sub root "area/"))))))))

(deftest-parametrize plan-refer-by-abi
    ((abi refer-p)
     :ids ("abi1" "abi2")
     (1 nil) (2 t))
  (if (uiop:os-unix-p)
      (with-tree (root)
        (let ((plan (trampoline-plan (area-confinement root :read :system)
                                     (full-host :abi abi) (tmp-of root))))
          (ok (eq refer-p (and (member :refer (rule-for plan (ns (sub root "area/")))) t))
              "area")
          (ok (notany (lambda (rule) (and (member :refer (cdr rule))
                                          (equal (cdr rule) (landlock-rights-for abi :read))))
                      (getf plan :rules))
              "no read rule carries REFER")
          (unless refer-p
            (ok (notany (lambda (rule) (member :refer (cdr rule))) (getf plan :rules))
                "ABI 1: no REFER anywhere"))))
      (skip "Unix paths")))

(defunix plan-masks-read-all
  (with-tree (root)
    (let ((plan (trampoline-plan (area-confinement root) (full-host) (tmp-of root))))
      (ok (equal (list (list :tmpfs (ns (sub root "secrets/")))
                       (list :null (ns (sub root "key"))))
                 (getf plan :masks))
          "existing entries only: missing/ is left out")
      (ok (equal '(:user :mount :net) (getf plan :unshare))))))

(defunix plan-read-all-deny-without-userns
  (with-tree (root)
    (ok (equal '(:deny-read)
               (handler-case (progn (trampoline-plan (area-confinement root) (restricted-host)
                                                     (tmp-of root))
                                    :planned)
                 (sc:confinement-unsupported (e) (sc:confinement-unsupported-missing e))))
        "a mask without a mount namespace is refused, never skipped")))

(deftest-parametrize plan-read-system-deny
    ((host deny masks unshare)
     :ids ("unreachable-restricted" "inside-readable-full" "outside-granted-full")
     ((restricted-host) "secrets/" nil nil)
     ((full-host) "ro/hidden/" '(:tmpfs "ro/hidden/") '(:user :mount))
     ((full-host) "secrets/" nil nil))
  (if (uiop:os-unix-p)
      (with-tree (root)
        (let ((plan (trampoline-plan (area-confinement root :read :system :network :allow
                                                            :deny-read (list (sub root deny)))
                                     host (tmp-of root))))
          (ok (equal (and masks (list (list (first masks) (ns (sub root (second masks))))))
                     (getf plan :masks)))
          (ok (equal unshare (getf plan :unshare)))))
      (skip "Unix paths")))

(defunix plan-read-system-deny-inside-granted-restricted
  (with-tree (root)
    (ok (equal '(:deny-read)
               (handler-case (progn (trampoline-plan (area-confinement root :read :system
                                                                            :deny-read (list (sub root "ro/hidden/")))
                                                     (restricted-host) (tmp-of root))
                                    :planned)
                 (sc:confinement-unsupported (e) (sc:confinement-unsupported-missing e))))
        "Landlock cannot subtract ro/hidden/ from ro/: refused")))

(deftest-parametrize plan-network
    ((host network expected unshare)
     :ids ("none-namespace" "none-seccomp" "allow" "ports")
     ((full-host) :none :namespace '(:user :net))
     ((restricted-host) :none :seccomp nil)
     ((full-host) :allow :allow nil)
     ((full-host) (ports-policy 443 80 443) '(:ports 80 443) nil))
  (if (uiop:os-unix-p)
      (with-tree (root)
        (let ((plan (trampoline-plan (area-confinement root :read :system :network network
                                                            :deny-read nil)
                                     host (tmp-of root))))
          (ok (equal expected (getf plan :network)))
          (ok (equal unshare (getf plan :unshare)))))
      (skip "Unix paths")))

(deftest-parametrize plan-scopes
    ((abi network scopes)
     :ids ("abi6-none" "abi6-allow" "abi5")
     (6 :none '(:abstract-unix-socket :signal))
     (6 :allow '(:signal))
     (5 :none nil))
  (if (uiop:os-unix-p)
      (with-tree (root)
        (ok (equal scopes
                   (getf (trampoline-plan (area-confinement root :read :system :network network)
                                          (full-host :abi abi) (tmp-of root))
                         :scopes))))
      (skip "Unix paths")))

(defunix plan-rlimits
  (with-tree (root)
    (ok (equal '((:cpu . 10) (:as . 1000000000) (:fsize . 4096) (:nproc . 50))
               (getf (trampoline-plan (area-confinement root :read :system :cpu-limit 10
                                                             :memory-limit 1000000000
                                                             :file-size-limit 4096
                                                             :process-limit 50)
                                      (restricted-host) (tmp-of root))
                     :rlimits)))
    (ok (equal '((:fsize . 4096))
               (getf (trampoline-plan (area-confinement root :read :system :file-size-limit 4096)
                                      (restricted-host) (tmp-of root))
                     :rlimits)))
    (ok (null (getf (trampoline-plan (area-confinement root :read :system) (restricted-host)
                                     (tmp-of root))
                    :rlimits)))))

(defunix plan-chained
  (with-tree (root)
    (let ((plan (trampoline-plan (area-confinement root :cpu-limit 5) (full-host) (tmp-of root)
                                 :chained t)))
      (ok (equal +plan-keys+ (plan-keys plan)))
      (ok (null (getf plan :rules)) "bwrap built the file view")
      (ok (null (getf plan :unshare)))
      (ok (null (getf plan :masks)))
      (ok (eq :allow (getf plan :network)) ":none is bwrap's --unshare-net")
      (ok (equal '((:cpu . 5)) (getf plan :rlimits))))
    (ok (equal '(:ports 443)
               (getf (trampoline-plan (area-confinement root :network (ports-policy 443))
                                      (full-host) (tmp-of root) :chained t)
                     :network))
        "ports stay with the trampoline")))

(defunix plan-tmp-shared
  (with-tree (root)
    (let ((plan (trampoline-plan (area-confinement root :read :system :tmp :shared)
                                 (restricted-host) nil)))
      (ok (listp (rule-for plan (ns (uiop:temporary-directory))))
          "the system temp directory is a write rule"))))

(deftest plan-print-read-round-trip
  (let ((plan '(:abi 4 :rules (("/usr/" :execute :read-file :read-dir)) :unshare nil :masks nil
                :network (:ports 80) :scopes nil :rlimits ((:cpu . 1)) :no-new-privs t)))
    (ok (stringp (print-trampoline-plan plan)))
    (ok (equal plan (read-trampoline-plan (print-trampoline-plan plan))))))

(defunix trampoline-argv-shape
  (let* ((plan '(:abi 1 :rules nil :unshare nil :masks nil :network :allow :scopes nil
                 :rlimits nil :no-new-privs t))
         (argv (trampoline-argv plan :runtime #p"/opt/sbcl/bin/sbcl" :core #p"/opt/sbcl/lib/sbcl.core"
                                     :script #p"/src/landlock-exec.lisp")))
    (ok (equal (list "/opt/sbcl/bin/sbcl" "--core" "/opt/sbcl/lib/sbcl.core"
                     "--script" "/src/landlock-exec.lisp" "--plan" (print-trampoline-plan plan) "--")
               argv)))
  #+sbcl
  (let ((argv (trampoline-argv '(:abi 1))))
    (ok (equal (uiop:native-namestring sb-ext:*runtime-pathname*) (first argv)) "this SBCL")
    (ok (equal (uiop:native-namestring (trampoline-pathname)) (fifth argv)))))

(defunix trampoline-script-shipped
  (ok (probe-file (trampoline-pathname)))
  (ok (equal "landlock-exec.lisp" (file-namestring (trampoline-pathname)))))

(deftest-parametrize chain-trampoline
    ((keys expected)
     :ids ("plain" "allow" "cpu-limit" "process-limit" "ports")
     ('() nil)
     ('(:network :allow) nil)
     ('(:cpu-limit 3) t)
     ('(:process-limit 30) t)
     ((list :network (ports-policy 443)) t))
  (if (uiop:os-unix-p)
      (with-tree (root)
        (ok (eq expected (and (chain-trampoline-p (apply #'area-confinement root keys) (full-host)) t))))
      (skip "Unix paths")))
