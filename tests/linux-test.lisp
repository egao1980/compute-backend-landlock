(in-package #:compute-backend-landlock/tests)

;;; The real kernel. Linux only; in the CI VM jobs (COMPUTE_LANDLOCK_CI_MODE)
;;; the mode's mechanism must be there — absent is a failure, not a skip.

(deftest probe-host-off-linux
  (if (linux-p)
      (skip "not Linux only")
      (let ((h (probe-host)))
        (ok (host-facts-p h))
        (ok (not (host-linux-p h)))
        (ok (= 0 (landlock-abi)))
        (ok (null (available-mechanisms h)))
        (multiple-value-bind (ok reason) (sc:confinement-available-p (make-landlock-backend))
          (ok (null ok))
          (ok (and (stringp reason) (search "Linux" reason)))))))

(deflinux landlock-abi-probe
  (let ((abi (landlock-abi)))
    (format t "~&;; Landlock ABI ~d; host ~a; CI mode ~(~a~)~%" abi (probe-host) (ci-mode))
    (ok (and (integerp abi) (<= 0 abi +landlock-max-abi+)))
    (when (ci-mode)
      (ok (>= abi 1) "the CI runner kernel has Landlock (fails loudly if an image drops it)"))))

(defun measured-root-symlinks ()
  "Which of /bin /sbin /lib /lib64 are symlinks here (in that order)."
  (loop for path in '("/bin" "/sbin" "/lib" "/lib64")
        for dir = (uiop:ensure-directory-pathname path)
        for true = (ignore-errors (truename dir))
        when (and true (string/= (uiop:native-namestring dir) (uiop:native-namestring true)))
          collect path))

(deflinux probe-host-on-linux
  (let ((h (probe-host)))
    (ok (host-linux-p h))
    (ok (= (landlock-abi) (host-landlock-abi h)))
    (ok (eq h (probe-host)) "cached")
    (ok (host-facts-p (probe-host :refresh t)))
    (ok (member (host-arch h) '(:x86-64 :arm64)))
    (ok (equal (measured-root-symlinks) (mapcar #'car (host-root-symlinks h)))
        "root-symlinks: exactly the symlinked /bin /sbin /lib /lib64, in that order")
    (loop for (path . target) in (host-root-symlinks h)
          do (ok (equal (truename (uiop:ensure-directory-pathname path))
                        (truename (uiop:merge-pathnames* (uiop:ensure-directory-pathname target) #p"/")))
                 (format nil "~a -> ~a" path target)))
    (case (ci-mode)
      (:bwrap
       (ok (host-bwrap-usable-p h) "apt bubblewrap + userns sysctl 0")
       (ok (host-user-namespaces-p h)))
      (:landlock
       (ok (null (host-bwrap h)) "no bwrap in this job")
       (ok (host-user-namespaces-p h) "userns sysctl 0"))
      (:restricted
       (ok (null (host-bwrap h)))
       (ok (not (host-user-namespaces-p h)) "AppArmor restrict_unprivileged_userns = 1")
       (ok (host-seccomp-p h))))))

(deflinux auto-picks-the-mode-mechanism
  (let ((expected (case (ci-mode) (:bwrap :bwrap) ((:landlock :restricted) :landlock))))
    (if expected
        (ok (eq expected (backend-mechanism (make-landlock-backend))))
        (skip "outside the CI VM jobs"))))

(defun call-in-area (fn)
  (with-tree (root)
    (funcall fn root (area-confinement root :read (if (host-user-namespaces-p (probe-host))
                                                       :all :system)))))

(defmacro with-mechanisms ((backend) &body body)
  "BODY once per available mechanism (:LANDLOCK required in every CI mode, :BWRAP in
the bwrap job)."
  `(dolist (m '(:bwrap :landlock))
     (let ((,backend (require-mechanism m (if (eq m :bwrap) '(:bwrap) '(:bwrap :landlock :restricted)))))
       (when ,backend
         (testing (format nil "~(~a~)" m)
           ,@body)))))

(deflinux run-confined-echo
  (with-mechanisms (b)
    (call-in-area
     (lambda (root c)
       (declare (ignore root))
       (let ((c (if (sc:confinement-supports-p b :deny-read)
                    c
                    (sc:make-confinement :writable (sc:confinement-writable c) :read :system))))
         (let ((r (sc:run-confined b c '("/bin/sh" "-c" "echo hi; echo $TMPDIR"))))
           (ok (eql 0 (sc:sandbox-result-exit-code r)) (sc:sandbox-result-stderr r))
           (ok (uiop:string-prefix-p "hi" (sc:sandbox-result-stdout r)))))))))

(deflinux trampoline-exec-failure
  (let ((b (require-mechanism :landlock '(:bwrap :landlock :restricted))))
    (when b
      (with-tree (root)
        (let ((r (sc:run-confined b (area-confinement root :read :system) '("/nonexistent/command"))))
          (ok (eql +trampoline-exec-exit+ (sc:sandbox-result-exit-code r)))
          (ok (search "landlock-exec" (sc:sandbox-result-stderr r))))))))

(defun run-trampoline (plan argv)
  "Run the trampoline with PLAN directly (no confine-command) → (values stdout stderr exit-code)."
  (uiop:run-program (append (trampoline-argv plan) argv)
                    :output :string :error-output :string :ignore-error-status t))

(deflinux trampoline-refuses-threads
  (let ((b (require-mechanism :landlock '(:landlock :bwrap :restricted))))
    (when b
      (with-tree (root)
        (let* ((plan (trampoline-plan (area-confinement root :read :system :deny-read nil)
                                      (landlock-backend-host b) nil))
               (plan (append (list :abi (getf plan :abi) :rules (getf plan :rules)
                                   :unshare '(:user :net))
                             (loop for (k v) on plan by #'cddr
                                   unless (member k '(:abi :rules :unshare)) append (list k v))
                             (list :spawn-threads 1))))
          (multiple-value-bind (out err code) (run-trampoline plan '("/bin/true"))
            (declare (ignore out))
            (ok (eql +trampoline-setup-exit+ code) "multi-threaded unshare refused")
            (ok (search "landlock-exec" err) err)))))))

(deflinux trampoline-single-threaded-unshare
  (let ((b (require-mechanism :landlock '(:landlock :bwrap :restricted))))
    (when b
      (with-tree (root)
        (let ((plan (trampoline-plan (area-confinement root :read :system :deny-read nil)
                                     (landlock-backend-host b) nil)))
          (multiple-value-bind (out err code) (run-trampoline plan '("/bin/echo" "ok"))
            (if (host-user-namespaces-p (landlock-backend-host b))
                (progn
                  (ok (equal '(:user :net) (getf plan :unshare)))
                  (ok (eql 0 code) err)
                  (ok (equal (format nil "ok~%") out)))
                (progn
                  (ok (null (getf plan :unshare)) "restricted: seccomp, no namespaces")
                  (ok (eql 0 code) err)))))))))

(deflinux trampoline-unshare-fails-closed
  (if (and (eq (ci-mode) :restricted) (require-mechanism :landlock '(:restricted)))
      (with-tree (root)
        (let ((plan (list :abi (landlock-abi) :rules nil :unshare '(:user :mount)
                          :masks (list (list :tmpfs (ns (sub root "secrets/"))))
                          :network :allow :scopes nil :rlimits nil :no-new-privs t)))
          (multiple-value-bind (out err code) (run-trampoline plan '("/bin/cat" "secrets/token"))
            (ok (eql +trampoline-setup-exit+ code) "a mask it cannot make → refused, not run")
            (ok (not (search "secret" out)))
            (ok (search "landlock-exec" err)))))
      (skip "the restricted CI job only (namespaces must fail there)")))

(deflinux file-size-limit
  (with-mechanisms (b)
    (with-tree (root)
      (let* ((c (area-confinement root :read :system :deny-read nil :file-size-limit 1024))
             (r (sc:run-confined b c '("/bin/sh" "-c" "echo ran; head -c 4096 /dev/zero > big"))))
        (ok (uiop:string-prefix-p "ran" (sc:sandbox-result-stdout r))
            (format nil "the command ran (not an exec failure): ~a" (sc:sandbox-result-stderr r)))
        (ok (not (eql 0 (sc:sandbox-result-exit-code r))))
        (ok (<= (or (ignore-errors (with-open-file (s (sub root "area/big")) (file-length s))) 0)
                1024))))))

(deflinux read-system-hides-outside
  (with-mechanisms (b)
    (with-tree (root)
      (let ((r (sc:run-confined b (area-confinement root :read :system :deny-read nil)
                                (list "/bin/sh" "-c" "echo ran; exec /bin/cat \"$1\"" "sh"
                                      (uiop:native-namestring (sub root "outside/victim"))))))
        (ok (uiop:string-prefix-p "ran" (sc:sandbox-result-stdout r))
            (format nil "the command ran (not an exec failure): ~a" (sc:sandbox-result-stderr r)))
        (ok (not (eql 0 (sc:sandbox-result-exit-code r))))
        (ok (not (search "original" (sc:sandbox-result-stdout r))))))))

(deflinux read-system-runs-the-command
  ;; READ :SYSTEM must still exec binaries: on merged-/usr hosts bwrap's new root needs
  ;; the /bin /lib /lib64 symlinks (HOST-ROOT-SYMLINKS) or the ELF interpreter is missing.
  (with-mechanisms (b)
    (with-tree (root)
      (let ((r (sc:run-confined b (area-confinement root :read :system :deny-read nil)
                                '("/bin/sh" "-c" "echo ran"))))
        (ok (eql 0 (sc:sandbox-result-exit-code r)) (sc:sandbox-result-stderr r))
        (ok (equal (format nil "ran~%") (sc:sandbox-result-stdout r)))))))
