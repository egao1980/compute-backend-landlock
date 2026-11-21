(in-package #:compute-backend-landlock)

;;; The Landlock ABI ladder (include/uapi/linux/landlock.h). The running
;;; kernel's ABI is LANDLOCK-ABI (host.lisp): 0 = no Landlock. Best effort: a
;;; ruleset handles exactly the rights the running ABI knows, never more (the
;;; kernel rejects unknown bits with EINVAL).
;;;   v1 (5.13) filesystem   v2 (5.19) :REFER   v3 (6.2) :TRUNCATE
;;;   v4 (6.7)  TCP bind/connect   v5 (6.10) :IOCTL-DEV
;;;   v6 (6.12) scopes: abstract unix sockets, signals   v7 (6.15) audit flags
;;;
;;; Given: the tables and the syscall numbers. Stubbed (R4d-2): the
;;; functions.

(defparameter +landlock-max-abi+ 7
  "The highest ABI this backend knows. A newer kernel is treated as this ABI.")

(defparameter +landlock-fs-rights+
  '((:execute     #x0001 1) (:write-file  #x0002 1) (:read-file   #x0004 1)
    (:read-dir    #x0008 1) (:remove-dir  #x0010 1) (:remove-file #x0020 1)
    (:make-char   #x0040 1) (:make-dir    #x0080 1) (:make-reg    #x0100 1)
    (:make-sock   #x0200 1) (:make-fifo   #x0400 1) (:make-block  #x0800 1)
    (:make-sym    #x1000 1) (:refer       #x2000 2) (:truncate    #x4000 3)
    (:ioctl-dev   #x8000 5))
  "(right bit first-abi) for LANDLOCK_ACCESS_FS_*, in bit order.")

(defparameter +landlock-net-rights+
  '((:bind-tcp #x1 4) (:connect-tcp #x2 4))
  "(right bit first-abi) for LANDLOCK_ACCESS_NET_*.")

(defparameter +landlock-scopes+
  '((:abstract-unix-socket #x1 6) (:signal #x2 6))
  "(scope bit first-abi) for LANDLOCK_SCOPE_*.")

(defparameter +landlock-file-rights+
  '(:execute :write-file :read-file :truncate :ioctl-dev)
  "The rights that apply to a non-directory. A path-beneath rule on a file may carry
only these (the kernel refuses the others with EINVAL).")

(defparameter +landlock-read-rights+
  '(:execute :read-file :read-dir)
  "What a read entry grants (READ :ALL's \"/\", READ :SYSTEM's read set).")

;;; Syscalls the trampoline and the probe use. landlock_* are the same on
;;; every architecture; the rest are per architecture (HOST-ARCH).

(defconstant +sys-landlock-create-ruleset+ 444)
(defconstant +sys-landlock-add-rule+ 445)
(defconstant +sys-landlock-restrict-self+ 446)
(defconstant +landlock-create-ruleset-version+ 1)
(defconstant +landlock-rule-path-beneath+ 1)
(defconstant +landlock-rule-net-port+ 2)

(defparameter +arch-syscalls+
  '((:x86-64 :unshare 272 :seccomp 317 :socket 41  :audit-arch #xc000003e)
    (:arm64  :unshare 97  :seccomp 277 :socket 198 :audit-arch #xc00000b7))
  "Per-architecture syscall numbers and the seccomp AUDIT_ARCH value.")

(defun %capped-abi (abi)
  (check-type abi (integer 0))
  (min abi +landlock-max-abi+))

(defun %upto (table abi)
  "The keys of TABLE ((key bit first-abi) …) that ABI knows, in table order."
  (let ((abi (%capped-abi abi)))
    (loop for (key nil first) in table
          when (<= first abi) collect key)))

(defun abi-fs-access (abi)
  "The filesystem rights ABI handles (+LANDLOCK-FS-RIGHTS+ order). ABI 0 → NIL; ABI
above +LANDLOCK-MAX-ABI+ counts as the maximum."
  (%upto +landlock-fs-rights+ abi))

(defun abi-net-access (abi)
  "The network rights ABI handles: NIL below 4, (:BIND-TCP :CONNECT-TCP) from 4."
  (%upto +landlock-net-rights+ abi))

(defun abi-scopes (abi)
  "The scopes ABI knows: NIL below 6, (:ABSTRACT-UNIX-SOCKET :SIGNAL) from 6."
  (%upto +landlock-scopes+ abi))

(defparameter +abi-features+
  '((:filesystem . 1) (:refer . 2) (:truncate . 3) (:network . 4) (:ioctl-dev . 5)
    (:scope . 6) (:audit . 7))
  "(feature . first ABI) for ABI-SUPPORTS-P.")

(defun abi-supports-p (abi what)
  "WHAT one of :FILESYSTEM (≥1) :REFER (≥2) :TRUNCATE (≥3) :NETWORK (≥4) :IOCTL-DEV (≥5)
:SCOPE (≥6) :AUDIT (≥7). Another WHAT → LANDLOCK-ERROR."
  (let ((entry (assoc what +abi-features+)))
    (unless entry
      (error 'landlock-error
             :message (format nil "unknown Landlock feature ~s (want ~{~s~^, ~})"
                              what (mapcar #'car +abi-features+))))
    (>= (%capped-abi abi) (cdr entry))))

(defun landlock-access-mask (rights)
  "The bitmask of RIGHTS, keywords from +LANDLOCK-FS-RIGHTS+, +LANDLOCK-NET-RIGHTS+ or
+LANDLOCK-SCOPES+ (one table per call; mixing tables or an unknown keyword →
LANDLOCK-ERROR). NIL → 0."
  (when (null rights)
    (return-from landlock-access-mask 0))
  (let ((table (find-if (lambda (table) (assoc (first rights) table))
                        (list +landlock-fs-rights+ +landlock-net-rights+ +landlock-scopes+))))
    (loop with mask = 0
          for right in rights
          for entry = (and table (assoc right table))
          do (unless entry
               (error 'landlock-error
                      :message (format nil "~s: not a right of the same table as ~s (rights ~s)"
                                       right (first rights) rights)))
             (setf mask (logior mask (second entry)))
          finally (return mask))))

(defun landlock-rights-for (abi kind &key file)
  "The rights a rule of KIND grants under ABI, in +LANDLOCK-FS-RIGHTS+ order.
KIND :READ → +LANDLOCK-READ-RIGHTS+; :WRITE → every right ABI handles; :DEVICE →
:READ-FILE :WRITE-FILE :TRUNCATE :IOCTL-DEV. Each is cut to what ABI handles, and with
FILE true (the entry is not a directory) to +LANDLOCK-FILE-RIGHTS+."
  (let* ((handled (abi-fs-access abi))
         (base (case kind
                 (:read +landlock-read-rights+)
                 (:write handled)
                 (:device '(:read-file :write-file :truncate :ioctl-dev))
                 (t (error 'landlock-error
                           :message (format nil "rule kind ~s: want :read, :write or :device"
                                            kind))))))
    (remove-if-not (lambda (right)
                     (and (member right base)
                          (or (not file) (member right +landlock-file-rights+))))
                   handled)))
