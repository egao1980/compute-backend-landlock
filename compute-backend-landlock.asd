(defsystem "compute-backend-landlock"
  :version "0.0.1"
  :description "Confining compute-protocol backend: Linux Landlock + seccomp + user/mount namespaces, bubblewrap when installed"
  :author "egao1980"
  :license "MIT"
  :depends-on ("compute-protocol")
  :serial t
  :pathname "src"
  :components ((:file "package"))
  :in-order-to ((test-op (test-op "compute-backend-landlock/tests"))))

(defsystem "compute-backend-landlock/tests"
  :depends-on ("compute-backend-landlock" "rove")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "smoke-test"))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))
