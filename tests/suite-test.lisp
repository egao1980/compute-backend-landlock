(in-package #:compute-backend-landlock/tests)

;;; compute-protocol's confinement suite (21 laws) through each mechanism.
;;; This is the R4d-2 verdict: no failures, and exactly the cases the
;;; mechanism's features allow ran.

(defun suite-report (name failures ran skipped)
  (format t "~&;; suite ~(~a~): ~d ran, ~d skipped ~s~%" name (length ran) (length skipped) skipped)
  (dolist (f failures)
    (format t ";;   FAIL ~s: ~a~%" (car f) (cdr f))))

(defun run-landlock-suite (backend name)
  (multiple-value-bind (failures ran skipped)
      (stack-compute-suite:run-confinement-suite backend)
    (suite-report name failures ran skipped)
    (ok (null failures) (format nil "~(~a~): ~{~s~^, ~}" name (mapcar #'car failures)))
    (values ran skipped)))

(deflinux suite-bwrap
  (let ((b (require-mechanism :bwrap '(:bwrap))))
    (when b
      (multiple-value-bind (ran skipped) (run-landlock-suite b :bwrap)
        (ok (= 21 (length ran)) "every law runs: bwrap has :deny-read and :read-system")
        (ok (null skipped))))))

(deflinux suite-landlock
  (let ((b (require-mechanism :landlock '(:bwrap :landlock :restricted))))
    (when b
      (multiple-value-bind (ran skipped) (run-landlock-suite b :landlock)
        (if (host-user-namespaces-p (landlock-backend-host b))
            (progn
              (ok (sc:confinement-supports-p b :deny-read))
              (ok (= 21 (length ran)))
              (ok (null skipped)))
            (progn
              (ok (not (sc:confinement-supports-p b :deny-read))
                  "no mount namespace: :deny-read absent, never faked")
              (ok (equal '(:secret-read :outside-read-all) skipped)
                  "read-system base: the deny-read and read-all cases skip")
              (ok (= 19 (length ran)))))))))

(deflinux suite-restricted-mode
  (if (eq (ci-mode) :restricted)
      (let ((b (make-landlock-backend)))
        (ok (eq :landlock (backend-mechanism b)))
        (ok (equal '(:filesystem :read-system :network-none :network-allow :network-ports
                     :cpu-limit :memory-limit :file-size-limit :process-limit)
                   (sc:confinement-features b))
            "Landlock + seccomp only (the runner kernel has ABI >= 4)"))
      (skip "the restricted CI job only")))

(deftest suite-off-linux-unavailable
  (if (linux-p)
      (skip "not Linux only")
      (ok (signals (stack-compute-suite:run-confinement-suite (make-landlock-backend))
                   'sc:confinement-unavailable))))
