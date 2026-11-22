;;;; landlock-exec.lisp — the Landlock trampoline (compute-backend-landlock).
;;;;
;;;;   runtime --core core --script landlock-exec.lisp --plan <plan> -- argv…
;;;;   runtime --core core --script landlock-exec.lisp --probe
;;;;
;;;; Run by this SBCL with --script: no ASDF, no Quicklisp, no systems — only
;;;; the core's own sb-alien (libc: syscall, prctl, setrlimit, mount, unshare,
;;;; execvp). It confines ITSELF (Landlock restricts the calling thread and
;;;; everything it execs) and then execs the command, so the confinement holds
;;;; for the command and every descendant. The plan and the step order are
;;;; specified in src/plan.lisp ("THE TRAMPOLINE"). Exit 126 = refused to
;;;; confine (nothing exec'd), 127 = execvp failed.
;;;;
;;;; Two phases. PREPARE reads the plan and builds every C buffer the setup needs
;;;; (argv, strings, the seccomp program, the Landlock attributes) while nothing
;;;; about the process has changed. COMMIT then only makes syscalls on that memory,
;;;; in the plan's order. So a failure is either before any change or a refused
;;;; setup step, and nothing allocates after setrlimit(RLIMIT_AS) (SBCL already
;;;; maps more address space than a memory limit allows). Any failure before
;;;; execvp → "landlock-exec: <step>: <reason>" on stderr and exit 126.
;;;;
;;;; This file carries its own copy of the Landlock rights tables and the
;;;; per-architecture numbers (src/abi.lisp): it cannot load the system.

(defpackage #:landlock-exec
  (:use #:cl))

(in-package #:landlock-exec)

;;; --script compiles each toplevel form: forward references and foreign symbols
;;; that do not exist on this OS (never called there) are not news.
(declaim (sb-ext:muffle-conditions style-warning sb-ext:compiler-note))

(defconstant +setup-exit+ 126)
(defconstant +exec-exit+ 127)
(defconstant +max-abi+ 7)

;;; Copies of src/abi.lisp's tables: (right bit first-abi).

(defparameter +fs-rights+
  '((:execute     #x0001 1) (:write-file  #x0002 1) (:read-file   #x0004 1)
    (:read-dir    #x0008 1) (:remove-dir  #x0010 1) (:remove-file #x0020 1)
    (:make-char   #x0040 1) (:make-dir    #x0080 1) (:make-reg    #x0100 1)
    (:make-sock   #x0200 1) (:make-fifo   #x0400 1) (:make-block  #x0800 1)
    (:make-sym    #x1000 1) (:refer       #x2000 2) (:truncate    #x4000 3)
    (:ioctl-dev   #x8000 5)))

(defparameter +scopes+
  '((:abstract-unix-socket #x1 6) (:signal #x2 6)))

(defconstant +net-bind-tcp+ #x1)
(defconstant +net-connect-tcp+ #x2)

(defparameter +arches+
  '((:x86-64 :audit-arch #xc000003e :socket 41 :io-uring-setup 425 :x32-guard t)
    (:arm64  :audit-arch #xc00000b7 :socket 198 :io-uring-setup 425 :x32-guard nil))
  "Seccomp's AUDIT_ARCH and the syscall numbers the filter tests, per architecture.")

(defun image-arch ()
  (cond ((member :x86-64 *features*) :x86-64)
        ((member :arm64 *features*) :arm64)))

(defun mask-of (keys table)
  (let ((mask 0))
    (dolist (k keys mask)
      (let ((entry (assoc k table)))
        (unless entry (error "unknown Landlock right ~s" k))
        (setf mask (logior mask (second entry)))))))

(defun handled-fs-mask (abi)
  (let ((mask 0))
    (loop for (nil bit first) in +fs-rights+
          when (<= first abi) do (setf mask (logior mask bit)))
    mask))

;;; Kernel constants (generic Linux, identical on x86-64 and arm64)

(defconstant +clone-newns+   #x00020000)
(defconstant +clone-newuser+ #x10000000)
(defconstant +clone-newnet+  #x40000000)

(defconstant +ms-rdonly+  #x1)
(defconstant +ms-nosuid+  #x2)
(defconstant +ms-nodev+   #x4)
(defconstant +ms-noexec+  #x8)
(defconstant +ms-remount+ #x20)
(defconstant +ms-bind+    #x1000)
(defconstant +ms-rec+     #x4000)
(defconstant +ms-private+ #x40000)

(defconstant +o-wronly+  #x1)
(defconstant +o-cloexec+ #x80000)
(defconstant +o-path+    #x200000)

(defconstant +enoent+ 2)

(defconstant +pr-set-seccomp+ 22)
(defconstant +pr-set-no-new-privs+ 38)
(defconstant +seccomp-mode-filter+ 2)

(defconstant +rlimit-cpu+ 0)
(defconstant +rlimit-fsize+ 1)
(defconstant +rlimit-nproc+ 6)
(defconstant +rlimit-as+ 9)

(defconstant +sys-landlock-create-ruleset+ 444)
(defconstant +sys-landlock-add-rule+ 445)
(defconstant +sys-landlock-restrict-self+ 446)
(defconstant +landlock-create-ruleset-version+ 1)
(defconstant +landlock-rule-path-beneath+ 1)
(defconstant +landlock-rule-net-port+ 2)

(defconstant +sig-setmask+ 2)
(defconstant +sigpipe+ 13)

(defconstant +af-inet+ 2)
(defconstant +af-inet6+ 10)
(defconstant +af-packet+ 17)
(defconstant +sock-stream+ 1)
(defconstant +ipproto-tcp+ 6)
(defconstant +eacces+ 13)
(defconstant +eperm+ 1)

(defconstant +ret-kill-process+ #x80000000)
(defconstant +ret-errno+ #x00050000)
(defconstant +ret-allow+ #x7fff0000)

;;; libc through sb-alien. Every argument is an integer (pointers as addresses).

(defmacro define-libc (name c-name result &rest args)
  `(defun ,name ,args
     (sb-alien:alien-funcall
      (sb-alien:extern-alien ,c-name (function ,result
                                               ,@(mapcar (constantly 'sb-alien:unsigned-long)
                                                         args)))
      ,@args)))

(define-libc %syscall "syscall" sb-alien:long nr a b c d)
(define-libc %unshare "unshare" sb-alien:int flags)
(define-libc %prctl "prctl" sb-alien:int option a b c d)
(define-libc %mount "mount" sb-alien:int source target fstype flags data)
(define-libc %getrlimit "getrlimit" sb-alien:int resource rlim)
(define-libc %setrlimit "setrlimit" sb-alien:int resource rlim)
(define-libc %open "open" sb-alien:int path flags mode)
(define-libc %write "write" sb-alien:long fd buf count)
(define-libc %close "close" sb-alien:int fd)
(define-libc %getuid "getuid" sb-alien:unsigned-int)
(define-libc %getgid "getgid" sb-alien:unsigned-int)
(define-libc %sigprocmask "sigprocmask" sb-alien:int how set oldset)
(define-libc %signal "signal" sb-alien:unsigned-long signum handler)
(define-libc %execvp "execvp" sb-alien:int file argv)

(defun strerror (errno)
  (sb-alien:alien-funcall
   (sb-alien:extern-alien "strerror" (function sb-alien:c-string sb-alien:int))
   errno))

;;; Steps and refusal

(defvar *step* "plan"
  "The setup step running now (named in the refusal line).")

(defmacro with-step ((name) &body body)
  `(let ((*step* ,name)) ,@body))

(define-condition setup-failure (error)
  ((text :initarg :text :reader setup-failure-text))
  (:report (lambda (c s) (write-string (setup-failure-text c) s))))

(defun fail (fmt &rest args)
  (error 'setup-failure :text (apply #'format nil fmt args)))

(defun check (result what)
  "RESULT of a libc call: -1 → a SETUP-FAILURE naming WHAT and errno."
  (when (= result -1)
    (let ((errno (sb-alien:get-errno)))
      (fail "~a: ~a (errno ~d)" what (or (ignore-errors (strerror errno)) "error") errno)))
  result)

(defun say (fmt &rest args)
  (ignore-errors
   (format *error-output* "landlock-exec: ~?~%" fmt args)
   (finish-output *error-output*)))

(defun refuse (condition)
  (say "~a: ~a" *step* (or (ignore-errors (princ-to-string condition)) "error"))
  (sb-ext:exit :code +setup-exit+ :abort t))

;;; C memory (malloc'd through make-alien; never freed: the process execs or exits)

(defun buffer (size)
  "A zeroed SIZE-byte buffer → its address."
  (let* ((alien (sb-alien:make-alien (sb-alien:unsigned 8) (max size 1)))
         (sap (sb-alien:alien-sap alien)))
    (dotimes (i (max size 1)) (setf (sb-sys:sap-ref-8 sap i) 0))
    (sb-sys:sap-int sap)))

(defun poke (address offset bytes value)
  (let ((sap (sb-sys:int-sap address)))
    (ecase bytes
      (1 (setf (sb-sys:sap-ref-8 sap offset) value))
      (2 (setf (sb-sys:sap-ref-16 sap offset) value))
      (4 (setf (sb-sys:sap-ref-32 sap offset) value))
      (8 (setf (sb-sys:sap-ref-64 sap offset) value)))))

(defun peek64 (address offset)
  (sb-sys:sap-ref-64 (sb-sys:int-sap address) offset))

(defun c-string (string)
  "STRING as a NUL-terminated UTF-8 C string → (values address byte-length)."
  (let* ((octets (sb-ext:string-to-octets string :external-format :utf-8))
         (n (length octets))
         (address (buffer (1+ n))))
    (dotimes (i n) (poke address i 1 (aref octets i)))
    (values address n)))

(defun c-argv (strings)
  "A NULL-terminated char*[] of STRINGS → its address."
  (let ((address (buffer (* 8 (1+ (length strings))))))
    (loop for s in strings
          for i from 0
          do (poke address (* 8 i) 8 (c-string s)))
    address))

;;; The seccomp filter: a tiny assembler with labels.
;;; Instructions: (:ld offset) (:and k) (:jeq k true false) (:jge k true false)
;;; (:ret value) (:label name); a jump target NIL is the next instruction.

(defun assemble (program)
  "PROGRAM → a list of (code jt jf k) with jump offsets resolved."
  (let ((labels (make-hash-table))
        (pc 0))
    (dolist (insn program)
      (if (eq (first insn) :label)
          (setf (gethash (second insn) labels) pc)
          (incf pc)))
    (setf pc 0)
    (flet ((offset (target)
             (if (null target)
                 0
                 (let ((to (or (gethash target labels) (error "no label ~s" target))))
                   (let ((d (- to pc 1)))
                     (unless (<= 0 d 255) (error "jump to ~s out of range" target))
                     d)))))
      (loop for insn in program
            unless (eq (first insn) :label)
              collect (prog1
                          (ecase (first insn)
                            (:ld (list #x20 0 0 (second insn)))
                            (:and (list #x54 0 0 (second insn)))
                            (:ret (list #x06 0 0 (second insn)))
                            (:jeq (list #x15 (offset (third insn)) (offset (fourth insn))
                                        (second insn)))
                            (:jge (list #x35 (offset (third insn)) (offset (fourth insn))
                                        (second insn))))
                        (incf pc))))))

(defun filter-program (mode arch)
  "The BPF program for network MODE (:SECCOMP or :PORTS) on ARCH."
  (let ((a (rest (assoc arch +arches+))))
    (unless a (fail "no seccomp numbers for architecture ~s" arch))
    (append
     `((:ld 4)                                   ; seccomp_data.arch
       (:jeq ,(getf a :audit-arch) nil :kill)
       (:ld 0))                                  ; seccomp_data.nr
     (when (getf a :x32-guard)
       '((:jge #x40000000 :kill nil)))           ; x32 syscalls
     `((:jeq ,(getf a :io-uring-setup) :eperm nil)
       (:jeq ,(getf a :socket) nil :allow)
       (:ld 16))                                 ; args[0]: domain
     (ecase mode
       (:seccomp
        `((:jeq ,+af-inet+ :eacces nil)
          (:jeq ,+af-inet6+ :eacces nil)
          (:jeq ,+af-packet+ :eacces :allow)))
       (:ports
        `((:jeq ,+af-packet+ :eacces nil)
          (:jeq ,+af-inet+ :inet nil)
          (:jeq ,+af-inet6+ :inet :allow)
          (:label :inet)
          (:ld 24)                               ; args[1]: type (flags in the high bits)
          (:and #xf)
          (:jeq ,+sock-stream+ nil :eacces)
          (:ld 32)                               ; args[2]: protocol (0 or TCP only)
          (:jeq 0 :allow nil)
          (:jeq ,+ipproto-tcp+ :allow :eacces))))
     `((:label :allow) (:ret ,+ret-allow+)
       (:label :eacces) (:ret ,(logior +ret-errno+ +eacces+))
       (:label :eperm) (:ret ,(logior +ret-errno+ +eperm+))
       (:label :kill) (:ret ,+ret-kill-process+)))))

(defun build-fprog (mode arch)
  "struct sock_fprog for the filter → its address."
  (let* ((insns (assemble (filter-program mode arch)))
         (n (length insns))
         (filter (buffer (* 8 n)))
         (fprog (buffer 16)))
    (loop for (code jt jf k) in insns
          for off from 0 by 8
          do (poke filter off 2 code)
             (poke filter (+ off 2) 1 jt)
             (poke filter (+ off 3) 1 jf)
             (poke filter (+ off 4) 4 k))
    (poke fprog 0 2 n)
    (poke fprog 8 8 filter)
    fprog))

;;; The plan

(defun read-plan (string)
  (with-standard-io-syntax
    ;; PRINT-TRAMPOLINE-PLAN writes keywords and COMMON-LISP:NIL / T; reading in
    ;; CL-USER takes those and a hand-written nil alike.
    (let ((*read-eval* nil)
          (*package* (find-package '#:cl-user)))
      (let ((plan (read-from-string string)))
        (unless (and (listp plan) (evenp (length plan)))
          (fail "not a plan: ~s" string))
        plan))))

(defstruct prepared
  abi rules unshare masks network scopes rlimits argv argv0
  uid-map gid-map deny setgroups uid-map-path gid-map-path
  root none tmpfs mode-0000 dev-null
  fprog ruleset-attr ruleset-size rule-attr port-attr rlimit sigset)

(defun prepare (plan command)
  (let* ((abi (min (or (getf plan :abi) 0) +max-abi+))
         (network (getf plan :network :allow))
         (scopes (getf plan :scopes))
         (rules (getf plan :rules))
         (ports (and (consp network) (eq (first network) :ports) (rest network)))
         (unshare (getf plan :unshare))
         (arch (image-arch)))
    (unless command (fail "no command after --"))
    (unless (or (member network '(:allow :namespace :seccomp)) (consp network))
      (fail "network ~s" network))
    (when (and (eq network :namespace) (not (member :net unshare)))
      (fail "network :namespace without :net in :unshare"))
    (when (and ports (< abi 4))
      (fail "a port policy needs Landlock ABI 4 (have ~d)" abi))
    (when (and (getf plan :masks) (not (member :mount unshare)))
      (fail "masks without a mount namespace"))
    (let ((p (make-prepared
              :abi abi
              :unshare unshare
              :network network
              :scopes scopes
              :rlimits (getf plan :rlimits)
              :argv (c-argv command)
              :argv0 (c-string (first command))
              :rules (loop for (ns . rights) in rules
                           collect (cons (c-string ns) (mask-of rights +fs-rights+)))
              :masks (loop for (kind ns) in (getf plan :masks)
                           collect (list (ecase kind ((:tmpfs :null) kind)) (c-string ns) ns)))))
      (when unshare
        (let ((uid (%getuid)) (gid (%getgid)))
          (multiple-value-bind (a n) (c-string (format nil "~d ~d 1~%" uid uid))
            (setf (prepared-uid-map p) (cons a n)))
          (multiple-value-bind (a n) (c-string (format nil "~d ~d 1~%" gid gid))
            (setf (prepared-gid-map p) (cons a n)))
          (multiple-value-bind (a n) (c-string "deny")
            (setf (prepared-deny p) (cons a n)))
          (setf (prepared-setgroups p) (c-string "/proc/self/setgroups")
                (prepared-uid-map-path p) (c-string "/proc/self/uid_map")
                (prepared-gid-map-path p) (c-string "/proc/self/gid_map")
                (prepared-root p) (c-string "/")
                (prepared-none p) (c-string "none")
                (prepared-tmpfs p) (c-string "tmpfs")
                (prepared-mode-0000 p) (c-string "mode=0000")
                (prepared-dev-null p) (c-string "/dev/null"))))
      (when (or (eq network :seccomp) ports)
        (setf (prepared-fprog p) (build-fprog (if ports :ports :seccomp) arch)))
      (when (and (plusp abi) (or rules ports scopes))
        (let ((attr (buffer 24)))
          (poke attr 0 8 (if rules (handled-fs-mask abi) 0))
          (poke attr 8 8 (if ports (logior +net-bind-tcp+ +net-connect-tcp+) 0))
          (poke attr 16 8 (mask-of scopes +scopes+))
          (setf (prepared-ruleset-attr p) attr
                (prepared-ruleset-size p) (cond ((< abi 4) 8) ((< abi 6) 16) (t 24))
                (prepared-rule-attr p) (buffer 16)
                (prepared-port-attr p) (buffer 16))))
      (when (and (null (prepared-ruleset-attr p)) (or rules ports scopes))
        (fail "the plan has Landlock rules but the ABI is ~d" abi))
      (setf (prepared-rlimit p) (buffer 16)
            (prepared-sigset p) (buffer 128))
      p)))

;;; Commit steps

(defun task-count ()
  "Threads of this process (/proc/self/status \"Threads:\")."
  (with-open-file (s "/proc/self/status")
    (loop for line = (read-line s nil)
          while line
          when (and (> (length line) 8) (string= "Threads:" line :end2 8))
            return (parse-integer line :start 8 :junk-allowed t))))

(defun stop-finalizer-thread ()
  (let ((f (find-symbol "FINALIZER-THREAD-STOP" "SB-IMPL")))
    (when (and f (fboundp f))
      (ignore-errors (funcall f)))))

(defun ensure-single-threaded ()
  (with-step ("threads")
    (stop-finalizer-thread)
    (loop repeat 100
          for n = (task-count)
          until (eql n 1)
          do (sleep 0.01)
          finally (let ((n (task-count)))
                    (unless (eql n 1)
                      (fail "~a threads in /proc/self/task: unshare(CLONE_NEWUSER) needs ~
                             a single-threaded process" n))))))

(defun write-proc (path-address content)
  "One write(2) of CONTENT (address . length) to the file at PATH-ADDRESS."
  (let ((fd (check (%open path-address +o-wronly+ 0) "open")))
    (unwind-protect
         (let ((n (check (%write fd (car content) (cdr content)) "write")))
           (unless (= n (cdr content)) (fail "short write")))
      (%close fd))))

(defun commit-namespaces (p)
  (let ((unshare (prepared-unshare p)))
    (with-step ("unshare")
      (check (%unshare (logior (if (member :user unshare) +clone-newuser+ 0)
                               (if (member :mount unshare) +clone-newns+ 0)
                               (if (member :net unshare) +clone-newnet+ 0)))
             "unshare"))
    (when (member :user unshare)
      (with-step ("setgroups") (write-proc (prepared-setgroups p) (prepared-deny p)))
      (with-step ("uid_map") (write-proc (prepared-uid-map-path p) (prepared-uid-map p)))
      (with-step ("gid_map") (write-proc (prepared-gid-map-path p) (prepared-gid-map p))))
    (when (member :mount unshare)
      (with-step ("mount private")
        (check (%mount (prepared-none p) (prepared-root p) 0 (logior +ms-rec+ +ms-private+) 0)
               "mount / rprivate"))
      (let ((locked (logior +ms-nosuid+ +ms-nodev+ +ms-noexec+)))
        (loop for (kind address ns) in (prepared-masks p)
              do (with-step ((format nil "mask ~a" ns))
                   (ecase kind
                     (:tmpfs
                      (check (%mount (prepared-tmpfs p) address (prepared-tmpfs p) locked
                                     (prepared-mode-0000 p))
                             "mount tmpfs")
                      (check (%mount (prepared-tmpfs p) address (prepared-tmpfs p)
                                     (logior +ms-remount+ +ms-rdonly+ locked)
                                     (prepared-mode-0000 p))
                             "remount read-only"))
                     (:null
                      (check (%mount (prepared-dev-null p) address 0 +ms-bind+ 0)
                             "bind /dev/null")
                      ;; NOSUID NODEV NOEXEC: /dev's flags are locked in a child user
                      ;; namespace, and a remount may add flags, never drop them.
                      (check (%mount 0 address 0
                                     (logior +ms-remount+ +ms-bind+ +ms-rdonly+ locked) 0)
                             "remount read-only")))))))))

(defun commit-rlimits (p)
  (let ((buf (prepared-rlimit p)))
    (loop for (key . value) in (prepared-rlimits p)
          for resource = (ecase key
                           (:cpu +rlimit-cpu+) (:as +rlimit-as+)
                           (:fsize +rlimit-fsize+) (:nproc +rlimit-nproc+))
          do (with-step ((format nil "setrlimit ~(~a~)" key))
               (check (%getrlimit resource buf) "getrlimit")
               ;; Never above the current hard limit (raising it is refused).
               (let ((v (min value (peek64 buf 8))))
                 (poke buf 0 8 v)
                 (poke buf 8 8 v))
               (check (%setrlimit resource buf) "setrlimit")))))

(defun commit-landlock (p)
  (with-step ("landlock")
    (let ((ruleset (check (%syscall +sys-landlock-create-ruleset+ (prepared-ruleset-attr p)
                                    (prepared-ruleset-size p) 0 0)
                          "landlock_create_ruleset"))
          (attr (prepared-rule-attr p)))
      (loop for (path . rights) in (prepared-rules p)
            do (let ((fd (%open path (logior +o-path+ +o-cloexec+) 0)))
                 (if (= fd -1)
                     (let ((errno (sb-alien:get-errno)))
                       (unless (= errno +enoent+)   ; a rule whose path is gone: skipped
                         (fail "open rule path: ~a (errno ~d)" (strerror errno) errno)))
                     (unwind-protect
                          (progn
                            (poke attr 0 8 rights)
                            (poke attr 8 4 fd)
                            (check (%syscall +sys-landlock-add-rule+ ruleset
                                             +landlock-rule-path-beneath+ attr 0)
                                   "landlock_add_rule (path)"))
                       (%close fd)))))
      (let ((network (prepared-network p))
            (port-attr (prepared-port-attr p)))
        (when (consp network)
          (dolist (port (rest network))
            (poke port-attr 0 8 +net-connect-tcp+)
            (poke port-attr 8 8 port)
            (check (%syscall +sys-landlock-add-rule+ ruleset +landlock-rule-net-port+
                             port-attr 0)
                   "landlock_add_rule (port)"))))
      (check (%syscall +sys-landlock-restrict-self+ ruleset 0 0 0) "landlock_restrict_self")
      (%close ruleset))))

(defun commit (p)
  (when (prepared-unshare p)
    (ensure-single-threaded)
    (commit-namespaces p))
  (commit-rlimits p)
  (with-step ("no_new_privs")
    (check (%prctl +pr-set-no-new-privs+ 1 0 0 0) "prctl(PR_SET_NO_NEW_PRIVS)"))
  (when (prepared-fprog p)
    (with-step ("seccomp")
      (check (%prctl +pr-set-seccomp+ +seccomp-mode-filter+ (prepared-fprog p) 0 0)
             "prctl(PR_SET_SECCOMP)")))
  (when (prepared-ruleset-attr p)
    (commit-landlock p))
  (with-step ("signals")
    ;; exec keeps the signal mask and ignored signals: give the command defaults.
    (check (%sigprocmask +sig-setmask+ (prepared-sigset p) 0) "sigprocmask")
    (%signal +sigpipe+ 0)))

(defun run-plan (plan-string command)
  (let* ((plan (read-plan plan-string))
         (spawn (getf plan :spawn-threads)))
    (when (and (integerp spawn) (plusp spawn))
      ;; Tests only: idle threads, so the single-thread refusal can be seen.
      (dotimes (i spawn)
        (sb-thread:make-thread (lambda () (loop (sleep 60))) :name "landlock-exec idle")))
    (let ((p (with-step ("prepare") (prepare plan command))))
      (commit p)
      (%execvp (prepared-argv0 p) (prepared-argv p))
      ;; Confined, nothing exec'd.
      (let ((errno (sb-alien:get-errno)))
        (say "execvp: ~a: ~a (errno ~d)" (first command)
             (or (ignore-errors (strerror errno)) "error") errno)
        (sb-ext:exit :code +exec-exit+ :abort t)))))

;;; --probe: what this kernel lets an unprivileged process do

(defun probe-abi ()
  (let ((r (%syscall +sys-landlock-create-ruleset+ 0 0 +landlock-create-ruleset-version+ 0)))
    (if (plusp r) (min r +max-abi+) 0)))

(defun probe-user-namespaces ()
  "unshare(USER|NS|NET), the maps, rprivate, a tmpfs and a /dev/null bind remounted
read-only: exactly what the masks need. This process exits after the probe."
  (ignore-errors
   (let* ((script (or *load-truename* (fail "no script path")))
          (plan (list :abi 0 :unshare '(:user :mount :net)
                      :masks (list (list :tmpfs "/tmp/")
                                   (list :null (sb-ext:native-namestring script)))
                      :network :allow))
          (p (prepare plan '("/bin/true"))))
     (ensure-single-threaded)
     (commit-namespaces p)
     t)))

(defun probe-seccomp ()
  "NO_NEW_PRIVS and an allow-everything filter install."
  (ignore-errors
   (let ((fprog (buffer 16))
         (filter (buffer 8)))
     (poke filter 0 2 #x06)
     (poke filter 4 4 +ret-allow+)
     (poke fprog 0 2 1)
     (poke fprog 8 8 filter)
     (check (%prctl +pr-set-no-new-privs+ 1 0 0 0) "no_new_privs")
     (check (%prctl +pr-set-seccomp+ +seccomp-mode-filter+ fprog 0 0) "seccomp")
     t)))

(defun run-probe ()
  (let* ((linux (member :linux *features*))
         (abi (if linux (or (ignore-errors (probe-abi)) 0) 0))
         (arch (image-arch))
         (userns (and linux arch (probe-user-namespaces) t))
         (seccomp (and linux arch (probe-seccomp) t)))
    (with-standard-io-syntax
      (let ((*package* (find-package '#:keyword)))
        (prin1 (list :abi abi :user-namespaces-p userns :seccomp-p seccomp :arch arch))
        (terpri)))
    (finish-output)
    (sb-ext:exit :code 0)))

;;; Main

(defun main (args)
  (let ((mode (find-if (lambda (a) (member a '("--plan" "--probe") :test #'string=)) args)))
    (cond ((equal mode "--probe")
           (run-probe))
          ((equal mode "--plan")
           (let* ((tail (rest (member "--plan" args :test #'string=)))
                  (plan (first tail))
                  (dashes (rest tail)))
             (unless (member :linux *features*)
               (fail "not Linux"))
             (unless (and plan (equal (first dashes) "--"))
               (fail "usage: --plan <plan> -- command…"))
             (run-plan plan (rest dashes))))
          (t (fail "usage: --plan <plan> -- command… | --probe")))))

(handler-bind ((serious-condition #'refuse))
  (main (rest sb-ext:*posix-argv*)))
