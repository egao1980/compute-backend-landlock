(in-package #:compute-backend-landlock/tests)

;;; Host facts → mechanisms and features: pure, every OS.

(deftest host-facts-construction
  (let ((h (make-host-facts :landlock-abi 9 :bwrap "/usr/bin/bwrap" :bwrap-usable-p t)))
    (ok (host-facts-p h))
    (ok (host-linux-p h) "a described host is Linux unless told otherwise")
    (ok (= 7 (host-landlock-abi h)) "capped at +landlock-max-abi+")
    (ok (host-bwrap-usable-p h))
    (ok (eq :x86-64 (host-arch h))))
  (ok (not (host-bwrap-usable-p (make-host-facts :bwrap-usable-p t))) "usable needs a path")
  (ok (signals (make-host-facts :landlock-abi -1) 'landlock-error))
  (ok (signals (make-host-facts :bwrap #p"/usr/bin/bwrap") 'landlock-error))
  (ok (signals (make-host-facts :arch :mips) 'landlock-error)))

(deftest mechanism-table
  (ok (equal '(:bwrap :landlock) (mapcar #'first +mechanisms+)))
  (ok (> (mechanism-rank :bwrap) (mechanism-rank :landlock)))
  (ok (signals (mechanism-rank :chroot) 'landlock-error)))

(deftest-parametrize mechanism-features-table
    ((host mechanism expected)
     :ids ("full-bwrap" "full-landlock" "abi3-bwrap-no-ports" "restricted-landlock"
           "restricted-bwrap" "abi1-bare" "abi0-bwrap" "abi0-landlock" "not-linux"
           "bwrap-unusable" "userns-no-seccomp")
     ((full-host) :bwrap (append '(:filesystem :read-system :deny-read :network-none
                                   :network-allow :network-ports) +all-limits+))
     ((full-host) :landlock (append '(:filesystem :read-system :deny-read :network-none
                                      :network-allow :network-ports) +all-limits+))
     ((full-host :abi 3) :bwrap (append '(:filesystem :read-system :deny-read :network-none
                                          :network-allow) +all-limits+))
     ((restricted-host) :landlock (append '(:filesystem :read-system :network-none
                                            :network-allow :network-ports) +all-limits+))
     ((restricted-host) :bwrap nil)
     ((host :landlock-abi 1) :landlock (append '(:filesystem :read-system :network-allow)
                                               +all-limits+))
     ((full-host :abi 0) :bwrap (append '(:filesystem :read-system :deny-read :network-none
                                          :network-allow) +all-limits+))
     ((full-host :abi 0) :landlock nil)
     ((host :linux-p nil :landlock-abi 6 :bwrap "/usr/bin/bwrap" :bwrap-usable-p t
            :user-namespaces-p t :seccomp-p t) :bwrap nil)
     ((host :landlock-abi 6 :bwrap "/usr/bin/bwrap" :seccomp-p t) :bwrap nil)
     ((host :landlock-abi 2 :user-namespaces-p t) :landlock
      (append '(:filesystem :read-system :deny-read :network-none :network-allow) +all-limits+)))
  (ok (equal expected (mechanism-features mechanism host)))
  (ok (not (member :network-hosts (mechanism-features mechanism host))) "never host rules"))

(deftest-parametrize mechanism-unavailable-reasons
    ((host mechanism word)
     :ids ("not-linux" "no-bwrap" "bwrap-unusable" "abi0")
     ((host :linux-p nil :landlock-abi 6) :landlock "Linux")
     ((restricted-host) :bwrap "bwrap")
     ((host :bwrap "/usr/bin/bwrap") :bwrap "usable")
     ((host :landlock-abi 0) :landlock "ABI"))
  (multiple-value-bind (ok reason) (mechanism-available-p mechanism host)
    (ok (null ok))
    (ok (and (stringp reason) (search word reason)) reason)))

(deftest mechanism-available
  (ok (mechanism-available-p :bwrap (full-host)))
  (ok (mechanism-available-p :landlock (restricted-host)))
  (ok (signals (mechanism-available-p :chroot (full-host)) 'landlock-error)))

(deftest-parametrize available-and-selected
    ((host available auto)
     :ids ("full" "restricted" "abi0-no-bwrap" "abi0-bwrap")
     ((full-host) '(:bwrap :landlock) :bwrap)
     ((restricted-host) '(:landlock) :landlock)
     ((host :landlock-abi 0) nil nil)
     ((full-host :abi 0) '(:bwrap) :bwrap))
  (ok (equal available (available-mechanisms host)))
  (ok (eq auto (select-mechanism :auto host))))

(deftest select-named-mechanism
  (ok (eq :landlock (select-mechanism :landlock (full-host))) "asked for, though not the best")
  (ok (null (select-mechanism :bwrap (restricted-host))) "asked for, unavailable → NIL"))

;;; The backend on a described host

(deftest backend-construction
  (let ((b (make-landlock-backend)))
    (ok (typep b 'sc:confining-backend))
    (ok (eq :auto (landlock-backend-requested b))))
  (ok (signals (make-landlock-backend :mechanism :chroot) 'landlock-error))
  (ok (signals (make-landlock-backend :host :linux) 'landlock-error))
  (let ((sc:*compute-backend* nil))
    (use-landlock-backend :mechanism :landlock)
    (ok (typep sc:*compute-backend* 'landlock-backend))
    (ok (eq :landlock (landlock-backend-requested sc:*compute-backend*)))))

(deftest-parametrize backend-on-described-host
    ((requested host mechanism)
     :ids ("auto-full" "landlock-full" "auto-restricted")
     (:auto (full-host) :bwrap)
     (:landlock (full-host) :landlock)
     (:auto (restricted-host) :landlock))
  (let ((b (make-landlock-backend :mechanism requested :host host)))
    (ok (eq host (landlock-backend-host b)) "the given host, not a probe")
    (ok (eq mechanism (backend-mechanism b)))
    (ok (equal (mechanism-features mechanism host) (sc:confinement-features b)))
    (ok (sc:confinement-available-p b))))

(deftest-parametrize backend-unavailable
    ((requested host words)
     :ids ("not-linux" "bwrap-on-restricted" "auto-nothing")
     (:auto (host :linux-p nil) '("Linux"))
     (:bwrap (restricted-host) '("bwrap"))
     (:auto (host :landlock-abi 0) '("ABI" "bwrap")))
  (let ((b (make-landlock-backend :mechanism requested :host host)))
    (multiple-value-bind (ok reason) (sc:confinement-available-p b)
      (ok (null ok))
      (ok (stringp reason))
      (dolist (w words)
        (ok (and (stringp reason) (search w reason)) (format nil "~s in ~s" w reason))))
    (ok (null (sc:confinement-features b)))
    (ok (null (backend-mechanism b)))))

(deftest-parametrize check-through-backend
    ((host confinement missing)
     :ids ("restricted-deny-read" "restricted-hosts" "abi3-ports")
     ((restricted-host) (sc:make-confinement :read :all) '(:deny-read))
     ((restricted-host) (sc:make-confinement
                         :read :system
                         :network (sc:make-sandbox-network-policy
                                   :egress (list (sc:make-egress-rule :host "example.com" :port 443))))
      '(:network-hosts))
     ((full-host :abi 3) (sc:make-confinement :network (ports-policy 443)) '(:network-ports)))
  (let ((b (make-landlock-backend :host host)))
    (ok (equal missing
               (handler-case (progn (sc:check-confinement b confinement) :accepted)
                 (sc:confinement-unsupported (e) (sc:confinement-unsupported-missing e)))))))

(deftest check-accepts-read-system-on-restricted
  (let ((b (make-landlock-backend :host (restricted-host)))
        (c (sc:make-confinement :read :system)))
    (ok (eq c (sc:check-confinement b c)))))
