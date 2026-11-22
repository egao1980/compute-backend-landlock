(defsystem "compute-backend-landlock"
  :version "0.1.0"
  :description "Confining compute-protocol backend for Linux: bubblewrap when installed, else a Landlock trampoline (Landlock + seccomp + user/mount/net namespaces)"
  :author "egao1980"
  :license "MIT"
  ;; No foreign library: the in-image ABI probe and the trampoline use
  ;; sb-alien into libc (syscall, prctl, setrlimit, mount, execve). bwrap runs
  ;; as a program through process-protocol.
  :depends-on ((:version "compute-protocol" "0.3.2")
               (:version "process-protocol" "0.4.1")
               (:version "process-backend-uiop" "0.3.1")
               "uiop")
  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "conditions")
               (:file "abi")             ; Landlock rights, ABI ladder, syscall numbers
               (:file "host")            ; host facts + the probe
               (:file "mechanisms")      ; :bwrap / :landlock, ranks, features
               (:file "plan")            ; trampoline plan + argv, bwrap argv (pure)
               (:file "backend")         ; LANDLOCK-BACKEND: the confining-backend methods
               (:static-file "landlock-exec.lisp"))  ; the trampoline (sbcl --script)
  :in-order-to ((test-op (test-op "compute-backend-landlock/tests"))))

(defsystem "compute-backend-landlock/tests"
  :depends-on ("compute-backend-landlock"
               (:feature :sbcl "compute-protocol/confinement-suite")
               "rove"
               "uiop")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "support")
               (:file "abi-test")         ; pure: rights, masks, ABI ladder
               (:file "mechanism-test")   ; pure: host facts → features, ranks, availability
               (:file "plan-test")        ; pure: trampoline plans from confinements
               (:file "bwrap-test")       ; pure: golden bwrap argv
               (:file "launch-test")      ; every OS: confine-command on a described Linux host
               (:file "linux-test")       ; Linux: probe, trampoline hazards, run-confined
               (:file "suite-test" :if-feature :sbcl))  ; Linux: run-confinement-suite per mechanism
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))
