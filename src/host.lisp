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
numbers here (no seccomp, no trampoline namespaces).")
   (root-symlinks :initarg :root-symlinks :reader host-root-symlinks :initform nil
                  :documentation "A list of (PATH . TARGET): the host's top-level symlinks
among /bin /sbin /lib /lib64, in that order (merged /usr: (\"/lib\" . \"usr/lib\")).
TARGET is the raw readlink(2) value. bwrap READ :SYSTEM mirrors them."))
  (:documentation "What one machine supports for confinement. Immutable."))

(defun host-facts-p (object)
  (typep object 'host-facts))

(defun %root-name-p (path)
  "PATH is a string \"/NAME\": a top-level absolute name, no further slash."
  (and (stringp path)
       (> (length path) 1)
       (char= #\/ (char path 0))
       (not (find #\/ path :start 1))))

(defun make-host-facts (&key (linux-p t) (landlock-abi 0) bwrap bwrap-usable-p
                          user-namespaces-p seccomp-p (arch :x86-64) root-symlinks)
  "A described host (tests, planning). LANDLOCK-ABI an integer ≥ 0; BWRAP a namestring
or NIL; ARCH :X86-64, :ARM64 or NIL; ROOT-SYMLINKS a list of (PATH . TARGET), PATH a
top-level absolute name \"/NAME\", TARGET a non-empty string. Anything else →
LANDLOCK-ERROR."
  (unless (and (integerp landlock-abi) (>= landlock-abi 0))
    (error 'landlock-error :message (format nil "landlock-abi ~s: want an integer >= 0" landlock-abi)))
  (unless (or (null bwrap) (stringp bwrap))
    (error 'landlock-error :message (format nil "bwrap ~s: want a namestring or NIL" bwrap)))
  (unless (member arch '(:x86-64 :arm64 nil))
    (error 'landlock-error :message (format nil "arch ~s: want :x86-64, :arm64 or NIL" arch)))
  (unless (listp root-symlinks)
    (error 'landlock-error :message (format nil "root-symlinks ~s: want a list of (PATH . TARGET)" root-symlinks)))
  (dolist (entry root-symlinks)
    (unless (and (consp entry)
                 (%root-name-p (car entry))
                 (stringp (cdr entry)) (plusp (length (cdr entry))))
      (error 'landlock-error
             :message (format nil "root-symlinks entry ~s: want (\"/NAME\" . TARGET), TARGET a non-empty string"
                              entry))))
  (make-instance 'host-facts
                 :root-symlinks (copy-list root-symlinks)
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

;;; What the planners and features derive from the facts. Namespaces and seccomp
;;; need the architecture's syscall numbers (the trampoline's seccomp filter, its
;;; AUDIT_ARCH check), so an unknown architecture has neither.

(defun %userns-p (host)
  (and (host-user-namespaces-p host) (host-arch host) t))

(defun %seccomp-p (host)
  (and (host-seccomp-p host) (host-arch host) t))

;;; The probe

(defvar *landlock-abi* nil
  "LANDLOCK-ABI's answer in this image, or NIL before the first call.")

(defvar *host-facts* nil
  "PROBE-HOST's cached HOST-FACTS, or NIL before the first probe.")

(defun %forget-host ()
  "Drop the cached measurements (a saved core starts on another machine)."
  (setf *landlock-abi* nil
        *host-facts* nil))

#+sbcl (pushnew '%forget-host sb-ext:*save-hooks*)

(defun landlock-abi ()
  "The running kernel's Landlock ABI: landlock_create_ruleset(NULL, 0,
LANDLOCK_CREATE_RULESET_VERSION), capped at +LANDLOCK-MAX-ABI+. ENOSYS / EOPNOTSUPP →
0. Not Linux, or not SBCL → 0. Harmless: creates no ruleset."
  (or *landlock-abi*
      (setf *landlock-abi*
            #+(and sbcl linux)
            (let ((r (%syscall3 +sys-landlock-create-ruleset+ 0 0
                                +landlock-create-ruleset-version+)))
              ;; -1: ENOSYS (no Landlock), EOPNOTSUPP (built in, not in the LSM list),
              ;; anything else a kernel we cannot use either.
              (if (plusp r) (min r +landlock-max-abi+) 0))
            #-(and sbcl linux)
            0)))

(defun %image-arch ()
  #+x86-64 :x86-64
  #+arm64 :arm64
  #-(or x86-64 arm64) nil)

(defun %process-backend ()
  (or process-protocol:*process-backend*
      (process-backend-uiop:make-uiop-process-backend)))

(defun %run-quietly (argv &key (timeout 30))
  "Run ARGV to the end → (values exit-code stdout), or NIL when it could not be run
\(missing program, timeout, any failure of the launch)."
  (handler-case
      (multiple-value-bind (code out)
          (process-protocol:run argv :backend (%process-backend)
                                     :output :string :error-output nil
                                     :timeout timeout)
        (values code out))
    (error () nil)))

(defun %executable-file-p (namestring)
  (let ((p (uiop:file-exists-p (uiop:parse-native-namestring namestring))))
    (and p (not (uiop:directory-exists-p p))
         #+(and sbcl unix)
         (zerop (sb-alien:alien-funcall
                 (sb-alien:extern-alien "access" (function sb-alien:int sb-alien:c-string
                                                           sb-alien:int))
                 namestring 1))     ; X_OK
         #-(and sbcl unix) t)))

(defun %find-on-path (name)
  "The absolute namestring of executable NAME on PATH, or NIL."
  (let ((path (uiop:getenv "PATH")))
    (when path
      (dolist (dir (uiop:split-string path :separator ":"))
        (when (and (plusp (length dir)) (char= #\/ (char dir 0)))
          (let ((candidate (concatenate 'string (string-right-trim "/" dir) "/" name)))
            (when (%executable-file-p candidate)
              (return candidate))))))))

(defun %true-program ()
  (or (find-if #'%executable-file-p '("/bin/true" "/usr/bin/true"))
      "/bin/true"))

(defun %bwrap-usable-p (bwrap)
  "BWRAP runs a trivial sandbox (the namespaces BWRAP-ARGV uses) to exit 0."
  (eql 0 (%run-quietly (list bwrap "--unshare-user" "--unshare-pid" "--unshare-net"
                             "--die-with-parent" "--new-session"
                             "--ro-bind" "/" "/" "--dev" "/dev" "--proc" "/proc"
                             (%true-program)))))

(defun %trampoline-probe ()
  "The trampoline's --probe plist, or NIL."
  #+sbcl
  (multiple-value-bind (code out)
      (%run-quietly (list (uiop:native-namestring sb-ext:*runtime-pathname*)
                          "--core" (uiop:native-namestring sb-ext:*core-pathname*)
                          "--script" (uiop:native-namestring (trampoline-pathname))
                          "--probe"))
    (when (eql code 0)
      (handler-case
          (let ((plist (read-trampoline-plan out)))
            (and (listp plist) (evenp (length plist)) plist))
        (error () nil))))
  #-sbcl nil)

(defun %root-symlinks ()
  "Which of /bin /sbin /lib /lib64 are symlinks here, in that order, as (PATH . TARGET)
with TARGET the raw readlink(2) value."
  #+(and sbcl linux)
  (loop for path in '("/bin" "/sbin" "/lib" "/lib64")
        for target = (ignore-errors (sb-unix:unix-readlink path))
        when (and (stringp target) (plusp (length target)))
          collect (cons path target))
  #-(and sbcl linux) nil)

(defun %measure-host ()
  #-linux (make-host-facts :linux-p nil :arch (%image-arch))
  #+linux
  (let* ((abi (handler-case (landlock-abi) (error () 0)))
         (bwrap (handler-case (%find-on-path "bwrap") (error () nil)))
         (usable (and bwrap (%bwrap-usable-p bwrap)))
         (probe (%trampoline-probe))
         (arch (let ((a (getf probe :arch (%image-arch))))
                 (and (member a '(:x86-64 :arm64)) a))))
    (make-host-facts :landlock-abi abi
                     :bwrap bwrap
                     :bwrap-usable-p usable
                     :user-namespaces-p (eq t (getf probe :user-namespaces-p))
                     :seccomp-p (eq t (getf probe :seccomp-p))
                     :arch arch
                     :root-symlinks (handler-case (%root-symlinks) (error () nil)))))

(defun probe-host (&key refresh)
  "This machine's HOST-FACTS, measured once and cached (REFRESH measures again).
Not Linux → (MAKE-HOST-FACTS :LINUX-P NIL). On Linux: LANDLOCK-ABI in this image;
bwrap from PATH, usable when it runs /bin/true (or the absolute true) under
--unshare-user --unshare-pid --unshare-net --ro-bind / / to exit 0; user namespaces,
seccomp and the architecture from the trampoline run in its probe mode (one
process, through process-protocol; its own namespaces die with it). A probe that
cannot run reports the feature false, never signals."
  (when refresh
    (setf *host-facts* nil))
  (or *host-facts*
      (setf *host-facts*
            (handler-case (%measure-host)
              ;; Never signals: a probe that broke reports nothing usable.
              (error () (make-host-facts :linux-p #+linux t #-linux nil
                                         :arch (%image-arch)))))))
