(in-package #:compute-backend-landlock)

;;; Confinement refusals are compute-protocol's conditions
;;; (CONFINEMENT-UNSUPPORTED, CONFINEMENT-UNAVAILABLE, INVALID-CONFINEMENT).
;;; LANDLOCK-ERROR is this backend's own failure: a bad constructor argument, a
;;; syscall in this image that failed unexpectedly. The trampoline, a separate
;;; process, reports its failures by exit status (+TRAMPOLINE-SETUP-EXIT+,
;;; +TRAMPOLINE-EXEC-EXIT+) and a "landlock-exec: " line on stderr.

(define-condition landlock-error (sc:compute-error)
  ((errno :initarg :errno :reader landlock-error-errno :initform nil
          :documentation "The errno of the failed syscall, or NIL."))
  (:report (lambda (c s)
             (format s "Landlock backend: ~a~@[ (errno ~d)~]"
                     (or (sc:compute-error-message c) "error")
                     (landlock-error-errno c)))))

(defun %r4d2-pending (what)
  "Contract stub: R4d-2 implements WHAT."
  (error "R4d-2 pending: ~a" what))
