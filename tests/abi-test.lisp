(in-package #:compute-backend-landlock/tests)

;;; The Landlock ABI ladder: pure, every OS.

(deftest kernel-constants
  (ok (= 16 (length +landlock-fs-rights+)))
  (ok (equal '(:refer #x2000 2) (assoc :refer +landlock-fs-rights+)))
  (ok (equal '(:ioctl-dev #x8000 5) (assoc :ioctl-dev +landlock-fs-rights+)))
  (ok (equal '(:connect-tcp #x2 4) (assoc :connect-tcp +landlock-net-rights+)))
  (ok (= 7 +landlock-max-abi+)))

(deftest-parametrize fs-mask-per-abi
    ((abi mask)
     :ids ("abi0" "abi1" "abi2" "abi3" "abi4" "abi5" "abi6" "abi7" "above-max")
     (0 0) (1 #x1fff) (2 #x3fff) (3 #x7fff) (4 #x7fff) (5 #xffff) (6 #xffff) (7 #xffff) (9 #xffff))
  (ok (= mask (landlock-access-mask (abi-fs-access abi)))))

(deftest fs-access-order
  (ok (equal +abi6-all-fs+ (abi-fs-access 6)) "bit order")
  (ok (null (abi-fs-access 0)))
  (ok (not (member :refer (abi-fs-access 1))) "ABI 1 never handles REFER"))

(deftest-parametrize net-and-scopes
    ((abi net scopes)
     :ids ("abi3" "abi4" "abi5" "abi6")
     (3 nil nil)
     (4 '(:bind-tcp :connect-tcp) nil)
     (5 '(:bind-tcp :connect-tcp) nil)
     (6 '(:bind-tcp :connect-tcp) '(:abstract-unix-socket :signal)))
  (ok (equal net (abi-net-access abi)))
  (ok (equal scopes (abi-scopes abi))))

(deftest-parametrize abi-supports
    ((abi what expected)
     (0 :filesystem nil) (1 :filesystem t) (1 :refer nil) (2 :refer t)
     (2 :truncate nil) (3 :truncate t) (3 :network nil) (4 :network t)
     (4 :ioctl-dev nil) (5 :ioctl-dev t) (5 :scope nil) (6 :scope t)
     (6 :audit nil) (7 :audit t))
  (ok (eq expected (and (abi-supports-p abi what) t))))

(deftest abi-supports-unknown
  (ok (signals (abi-supports-p 4 :teleport) 'landlock-error)))

(deftest access-masks
  (ok (= 0 (landlock-access-mask nil)))
  (ok (= 3 (landlock-access-mask '(:bind-tcp :connect-tcp))))
  (ok (= 2 (landlock-access-mask '(:signal))))
  (ok (= #x0d (landlock-access-mask '(:execute :read-file :read-dir))))
  (ok (signals (landlock-access-mask '(:read-file :connect-tcp)) 'landlock-error) "tables mixed")
  (ok (signals (landlock-access-mask '(:read-everything)) 'landlock-error) "unknown right"))

(deftest-parametrize rights-for
    ((abi kind file expected)
     :ids ("read-dir" "read-file" "write-abi1" "write-abi2-refer" "write-file-abi3"
           "write-file-abi5" "device-abi1" "device-abi3" "device-abi5" "write-abi0")
     (1 :read nil '(:execute :read-file :read-dir))
     (1 :read t '(:execute :read-file))
     (1 :write nil (subseq +abi6-all-fs+ 0 13))
     (2 :write nil (subseq +abi6-all-fs+ 0 14))
     (3 :write t '(:execute :write-file :read-file :truncate))
     (5 :write t '(:execute :write-file :read-file :truncate :ioctl-dev))
     (1 :device t '(:write-file :read-file))
     (3 :device t '(:write-file :read-file :truncate))
     (5 :device t '(:write-file :read-file :truncate :ioctl-dev))
     (0 :write nil nil))
  (ok (equal expected (landlock-rights-for abi kind :file file))))
