(in-package #:compute-backend-landlock)

;;; LANDLOCK-BACKEND: compute-protocol's CONFINING-BACKEND protocol.
;;;   CONFINEMENT-FEATURES   MECHANISM-FEATURES of BACKEND-MECHANISM on the host
;;;                          (NIL when none is available)
;;;   CONFINEMENT-AVAILABLE-P  (values t nil) | (values nil reason): not Linux, the
;;;                          requested mechanism's reason, or with :AUTO one reason
;;;                          naming both (\"Landlock ABI 0 … and bwrap …\")
;;;   BACKEND-CONFINE-ARGV   :BWRAP → BWRAP-ARGV, then (CHAIN-TRAMPOLINE-P) the
;;;                          TRAMPOLINE-ARGV of the :CHAINED plan, then the argv;
;;;                          :LANDLOCK → TRAMPOLINE-ARGV of the plan, then the argv.
;;;                          Extra env: STACK_COMPUTE_CONFINEMENT = \"bwrap\" or
;;;                          \"landlock\". No cleanups. A plan refusal
;;;                          (CONFINEMENT-UNSUPPORTED) propagates; CONFINE-COMMAND
;;;                          removes the private temp directory.
;;; The host is probed once per backend, on first use (PROBE-HOST), unless one
;;; was given — a described host plans for that host on any OS (tests), and
;;; CONFINEMENT-AVAILABLE-P then answers for the described host.
;;;
;;; Given: the class, constructor (argument checks), readers,
;;; USE-LANDLOCK-BACKEND. Stubbed: LANDLOCK-BACKEND-HOST's probe,
;;; BACKEND-MECHANISM and the three protocol methods.

(defclass landlock-backend (sc:confining-backend)
  ((requested :initarg :requested :reader landlock-backend-requested :initform :auto
              :documentation ":AUTO, :BWRAP or :LANDLOCK.")
   (host :initarg :host :initform nil :accessor %backend-host
         :documentation "HOST-FACTS, or NIL until probed."))
  (:documentation "Confines commands on Linux with bubblewrap or the Landlock trampoline
\(+MECHANISMS+). Elsewhere it loads and is unavailable (\"not Linux\")."))

(defun make-landlock-backend (&key (mechanism :auto) host)
  "A LANDLOCK-BACKEND. MECHANISM :AUTO (the best available), :BWRAP or :LANDLOCK; HOST
a HOST-FACTS to plan for instead of probing this machine. Anything else →
LANDLOCK-ERROR."
  (unless (or (eq mechanism :auto) (assoc mechanism +mechanisms+))
    (error 'landlock-error :message (format nil "mechanism ~s: want :auto~{, ~s~}"
                                            mechanism (mapcar #'first +mechanisms+))))
  (unless (or (null host) (host-facts-p host))
    (error 'landlock-error :message (format nil "host ~s: want a host-facts or NIL" host)))
  (make-instance 'landlock-backend :requested mechanism :host host))

(defmethod print-object ((b landlock-backend) stream)
  (print-unreadable-object (b stream :type t :identity t)
    (format stream "~s" (landlock-backend-requested b))))

(defun landlock-backend-host (backend)
  "BACKEND's HOST-FACTS: the one given, else (PROBE-HOST), remembered."
  (or (%backend-host backend)
      (setf (%backend-host backend) (probe-host))))

(defun backend-mechanism (backend)
  "The mechanism BACKEND confines with on its host (SELECT-MECHANISM), or NIL."
  (select-mechanism (landlock-backend-requested backend) (landlock-backend-host backend)))

(defmethod sc:confinement-features ((backend landlock-backend))
  (let ((mechanism (backend-mechanism backend)))
    (and mechanism (mechanism-features mechanism (landlock-backend-host backend)))))

(defun %unavailable-reason (backend)
  (let ((host (landlock-backend-host backend))
        (requested (landlock-backend-requested backend)))
    (cond ((not (host-linux-p host)) "not Linux")
          ((eq requested :auto)
           (format nil "no confinement mechanism: ~a and ~a"
                   (nth-value 1 (mechanism-available-p :landlock host))
                   (nth-value 1 (mechanism-available-p :bwrap host))))
          (t (nth-value 1 (mechanism-available-p requested host))))))

(defmethod sc:confinement-available-p ((backend landlock-backend))
  (if (backend-mechanism backend)
      (values t nil)
      (values nil (%unavailable-reason backend))))

(defmethod sc:backend-confine-argv ((backend landlock-backend) confinement argv directory tmp)
  (let ((host (landlock-backend-host backend))
        (mechanism (backend-mechanism backend)))
    (values
     (ecase mechanism
       ((nil) (error 'sc:confinement-unavailable :backend backend
                                                 :reason (%unavailable-reason backend)))
       (:bwrap
        (append (bwrap-argv confinement host directory tmp)
                (when (chain-trampoline-p confinement host)
                  (trampoline-argv (trampoline-plan confinement host tmp :chained t)))
                argv))
       (:landlock
        (append (trampoline-argv (trampoline-plan confinement host tmp))
                argv)))
     (list (cons "STACK_COMPUTE_CONFINEMENT" (string-downcase (symbol-name mechanism))))
     nil)))

(defun use-landlock-backend (&rest args)
  "Make a LANDLOCK-BACKEND (MAKE-LANDLOCK-BACKEND ARGS) the default *COMPUTE-BACKEND*."
  (setf sc:*compute-backend* (apply #'make-landlock-backend args)))

;;; RUN-CONFINED and the confinement suite launch through process-protocol's
;;; default backend: loading this system is enough to run a confined command.
(unless process-protocol:*process-backend*
  (process-backend-uiop:use-uiop-process-backend))
