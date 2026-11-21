(in-package #:compute-backend-landlock)

;;; What this machine can do, as a value. Every decision the backend makes
;;; (features, mechanism, plan, argv) is a pure function of a HOST-FACTS and
;;; the confinement, so it is tested on every OS with described hosts;
;;; PROBE-HOST measures the real one on Linux.
;;;
;;; Given: the HOST-FACTS class, its constructor and readers, the libc
;;; syscall(2) binding. Stubbed: LANDLOCK-ABI, PROBE-HOST.

(defclass host-facts ()
  ((linux-p :initarg :linux-p :reader host-linux-p :initform t)
   (landlock-abi :initarg :landlock-abi :reader host-landlock-abi :initform 0
                 :documentation "0 = no Landlock (ENOSYS, EOPNOTSUPP: built without it or
not in the LSM list), else the running ABI capped at +LANDLOCK-MAX-ABI+.")
   (bwrap :initarg :bwrap :reader host-bwrap :initform nil
          :documentation "The absolute namestring of bwrap found on PATH, or NIL.")
   (bwrap-usable-p :initarg :bwrap-usable-p :reader host-bwrap-usable-p :initform nil
                   :documentation "BWRAP ran a trivial sandbox (user, pid and net namespaces,
read-only root) to exit 0.")
   (user-namespaces-p :initarg :user-namespaces-p :reader host-user-namespaces-p :initform nil
                      :documentation "An unprivileged single-threaded process can
unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWNET), write its uid/gid maps and mount a
tmpfs: false under AppArmor's restrict_unprivileged_userns, in default Docker
containers, with user.max_user_namespaces = 0.")
   (seccomp-p :initarg :seccomp-p :reader host-seccomp-p :initform nil
              :documentation "seccomp(SECCOMP_SET_MODE_FILTER) is available.")
   (arch :initarg :arch :reader host-arch :initform :x86-64
         :documentation ":X86-64, :ARM64, or NIL for an architecture without syscall
numbers here (no seccomp, no trampoline namespaces)."))
  (:documentation "What one machine supports for confinement. Immutable."))

(defun host-facts-p (object)
  (typep object 'host-facts))

(defun make-host-facts (&key (linux-p t) (landlock-abi 0) bwrap bwrap-usable-p
                          user-namespaces-p seccomp-p (arch :x86-64))
  "A described host (tests, planning). LANDLOCK-ABI an integer ≥ 0; BWRAP a namestring
or NIL; ARCH :X86-64, :ARM64 or NIL. Anything else → LANDLOCK-ERROR."
  (unless (and (integerp landlock-abi) (>= landlock-abi 0))
    (error 'landlock-error :message (format nil "landlock-abi ~s: want an integer >= 0" landlock-abi)))
  (unless (or (null bwrap) (stringp bwrap))
    (error 'landlock-error :message (format nil "bwrap ~s: want a namestring or NIL" bwrap)))
  (unless (member arch '(:x86-64 :arm64 nil))
    (error 'landlock-error :message (format nil "arch ~s: want :x86-64, :arm64 or NIL" arch)))
  (make-instance 'host-facts
                 :linux-p (and linux-p t)
                 :landlock-abi (min landlock-abi +landlock-max-abi+)
                 :bwrap bwrap
                 :bwrap-usable-p (and bwrap bwrap-usable-p t)
                 :user-namespaces-p (and user-namespaces-p t)
                 :seccomp-p (and seccomp-p t)
                 :arch arch))

(defmethod print-object ((h host-facts) stream)
  (print-unreadable-object (h stream :type t)
    (format stream "~:[not Linux~;Linux~] abi ~d~@[ bwrap ~a~]~:[~; userns~]~:[~; seccomp~]"
            (host-linux-p h) (host-landlock-abi h)
            (and (host-bwrap-usable-p h) (host-bwrap h))
            (host-user-namespaces-p h) (host-seccomp-p h))))

;;; libc syscall(2). Linux SBCL only; elsewhere the name exists and is never
;;; called (LANDLOCK-ABI answers 0 without it).

#+(and sbcl linux)
(declaim (inline %syscall3))
#+(and sbcl linux)
(defun %syscall3 (number a b c)
  "syscall(NUMBER, A, B, C) with integer (or pointer-as-integer) arguments → (values
result errno). RESULT -1 means failure."
  (let ((r (sb-alien:alien-funcall
            (sb-alien:extern-alien "syscall"
                                   (function sb-alien:long sb-alien:long
                                             sb-alien:unsigned-long sb-alien:unsigned-long
                                             sb-alien:unsigned-long))
            number a b c)))
    (values r (if (= r -1) (sb-alien:get-errno) 0))))

#-(and sbcl linux)
(defun %syscall3 (number a b c)
  (declare (ignore number a b c))
  (error 'landlock-error :message "syscall(2) is only bound on Linux SBCL"))

(defun landlock-abi ()
  "The running kernel's Landlock ABI: landlock_create_ruleset(NULL, 0,
LANDLOCK_CREATE_RULESET_VERSION), capped at +LANDLOCK-MAX-ABI+. ENOSYS / EOPNOTSUPP →
0. Not Linux, or not SBCL → 0. Harmless: creates no ruleset."
  (%r4d2-pending 'landlock-abi))

(defun probe-host (&key refresh)
  "This machine's HOST-FACTS, measured once and cached (REFRESH measures again).
Not Linux → (MAKE-HOST-FACTS :LINUX-P NIL). On Linux: LANDLOCK-ABI in this image;
bwrap from PATH, usable when it runs /bin/true (or the absolute true) under
--unshare-user --unshare-pid --unshare-net --ro-bind / / to exit 0; user namespaces,
seccomp and the architecture from the trampoline run in its probe mode (one
process, through process-protocol; its own namespaces die with it). A probe that
cannot run reports the feature false, never signals."
  (declare (ignore refresh))
  (%r4d2-pending 'probe-host))
