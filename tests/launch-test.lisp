(in-package #:compute-backend-landlock/tests)

;;; CONFINE-COMMAND on a LANDLOCK-BACKEND with a described host: the launch
;;; is planned (nothing runs), so this works on every Unix.

(defun env-value (launch name)
  (cdr (assoc name (sc:confined-launch-env launch) :test #'string=)))

(defun tail-p (tail list)
  (let ((n (length list)) (m (length tail)))
    (and (>= n m) (equal tail (subseq list (- n m))))))

(defun plan-in (argv)
  "The plan printed after --plan in ARGV, read back."
  (let ((pos (position "--plan" argv :test #'string=)))
    (and pos (read-trampoline-plan (nth (1+ pos) argv)))))

(defunix launch-bwrap
  (with-tree (root)
    (let ((b (make-landlock-backend :host (full-host))))
      (sc:with-confined-launch (l b (area-confinement root) '("/bin/echo" "hi"))
        (let ((argv (sc:confined-launch-argv l))
              (tmp (sc:confined-launch-tmp l)))
          (ok (equal "/usr/bin/bwrap" (first argv)))
          (ok (equal (bwrap-argv (sc:confined-launch-confinement l) (full-host)
                                 (sc:confined-launch-directory l) tmp)
                     (subseq argv 0 (- (length argv) 2)))
              "exactly BWRAP-ARGV, then the command")
          (ok (tail-p '("--" "/bin/echo" "hi") argv))
          (ok (null (plan-in argv)) "no trampoline without limits or ports")
          (ok (equal "bwrap" (env-value l "STACK_COMPUTE_CONFINEMENT")))
          (ok (equal (uiop:native-namestring tmp) (env-value l "TMPDIR"))))))))

(defunix launch-landlock
  (with-tree (root)
    (let ((b (make-landlock-backend :mechanism :landlock :host (full-host))))
      (sc:with-confined-launch (l b (area-confinement root) '("/bin/echo" "hi"))
        (let* ((argv (sc:confined-launch-argv l))
               (plan (plan-in argv)))
          #+sbcl (ok (equal (uiop:native-namestring sb-ext:*runtime-pathname*) (first argv)))
          (ok (equal (uiop:native-namestring (trampoline-pathname))
                     (nth (1+ (position "--script" argv :test #'string=)) argv)))
          (ok (equal plan (trampoline-plan (sc:confined-launch-confinement l) (full-host)
                                           (sc:confined-launch-tmp l))))
          (ok (eq :namespace (getf plan :network)))
          (ok (tail-p '("--" "/bin/echo" "hi") argv))
          (ok (equal "landlock" (env-value l "STACK_COMPUTE_CONFINEMENT"))))))))

(defunix launch-bwrap-chains-trampoline
  (with-tree (root)
    (let ((b (make-landlock-backend :host (full-host))))
      (sc:with-confined-launch (l b (area-confinement root :cpu-limit 7) '("/bin/true"))
        (let* ((argv (sc:confined-launch-argv l))
               (plan (plan-in argv))
               (first-dashes (position "--" argv :test #'string=)))
          (ok (equal "/usr/bin/bwrap" (first argv)))
          (ok (and plan (null (getf plan :rules))) "the chained plan")
          (ok (equal '((:cpu . 7)) (getf plan :rlimits)))
          #+sbcl
          (ok (equal (uiop:native-namestring sb-ext:*runtime-pathname*) (nth (1+ first-dashes) argv))
              "bwrap's -- is followed by the trampoline")
          (ok (tail-p '("--" "/bin/true") argv)))))))

(defunix launch-restricted-refuses-deny-read
  (with-tree (root)
    (let ((b (make-landlock-backend :host (restricted-host)))
          (before (length (stack-compute-dirs))))
      (ok (equal '(:deny-read)
                 (handler-case (progn (sc:confine-command b (area-confinement root) '("/bin/true")) :made)
                   (sc:confinement-unsupported (e) (sc:confinement-unsupported-missing e)))))
      (ok (= before (length (stack-compute-dirs))) "refused before anything was created"))))

(defunix launch-restricted-use-value
  (with-tree (root)
    (let* ((b (make-landlock-backend :host (restricted-host)))
           (fallback (sc:make-confinement :writable (list (sub root "area/")) :read :system))
           (l (handler-bind ((sc:confinement-unsupported
                               (lambda (e) (declare (ignore e)) (use-value fallback))))
                (sc:confine-command b (area-confinement root) '("/bin/true")))))
      (unwind-protect
           (progn
             (ok (eq :system (sc:confinement-read (sc:confined-launch-confinement l))))
             (ok (eq :seccomp (getf (plan-in (sc:confined-launch-argv l)) :network))))
        (sc:release-confined-launch l)))))

(defunix launch-plan-refusal-cleans-up
  (with-tree (root)
    (let ((b (make-landlock-backend :host (restricted-host)))
          (before (length (stack-compute-dirs))))
      ;; Passes CHECK-CONFINEMENT (READ :SYSTEM needs no :DENY-READ), refused by the
      ;; plan: ro/hidden/ cannot be subtracted from ro/ without a mount namespace.
      (ok (signals (sc:confine-command b (area-confinement root :read :system
                                                                :deny-read (list (sub root "ro/hidden/")))
                                       '("/bin/true"))
                   'sc:confinement-unsupported))
      (ok (= before (length (stack-compute-dirs))) "the private tmp was removed"))))

(defunix launch-unavailable-host
  (with-tree (root)
    (ok (signals (sc:confine-command (make-landlock-backend :host (host :linux-p nil))
                                     (area-confinement root) '("/bin/true"))
                 'sc:confinement-unavailable))))

(defunix launch-start-directory
  (with-tree (root)
    (let ((b (make-landlock-backend :host (full-host))))
      (sc:with-confined-launch (l b (area-confinement root :network :allow) '("/bin/pwd")
                                  :directory (sub root "ro/"))
        (let ((argv (sc:confined-launch-argv l)))
          (ok (equal (bns (sub root "ro/"))
                     (nth (1+ (position "--chdir" argv :test #'string=)) argv))))))))
