(in-package #:compute-backend-landlock/tests)

;;; Golden bwrap argv: pure (described hosts), every Unix.

(defparameter +bwrap-head+
  '("/usr/bin/bwrap" "--unshare-user" "--unshare-pid" "--die-with-parent" "--new-session"))

(defunix bwrap-read-all-network-none
  (with-tree (root)
    (let* ((tmp (tmp-of root))
           (area (bns (sub root "area/"))))
      (ok (equal (append +bwrap-head+
                         (list "--unshare-net"
                               "--ro-bind" "/" "/"
                               "--dev" "/dev" "--proc" "/proc"
                               "--bind" area area
                               "--bind" (bns tmp) (bns tmp)
                               "--perms" "0000" "--tmpfs" (bns (sub root "secrets/"))
                               "--remount-ro" (bns (sub root "secrets/"))
                               "--ro-bind" "/dev/null" (bns (sub root "key"))
                               "--chdir" area
                               "--"))
                 (bwrap-argv (area-confinement root) (full-host) (sub root "area/") tmp))))))

(defunix bwrap-network-allow
  (with-tree (root)
    (let ((argv (bwrap-argv (area-confinement root :network :allow) (full-host)
                            (sub root "area/") (tmp-of root))))
      (ok (not (member "--unshare-net" argv :test #'string=)))
      (ok (equal +bwrap-head+ (subseq argv 0 5)))
      (ok (equal '("--ro-bind" "/" "/") (subseq argv 5 8))))))

(defunix bwrap-ports-share-the-network
  (with-tree (root)
    (ok (not (member "--unshare-net"
                     (bwrap-argv (area-confinement root :network (ports-policy 443)) (full-host)
                                 (sub root "area/") (tmp-of root))
                     :test #'string=))
        "a port policy is the chained trampoline's (Landlock TCP rules)")))

(defun system-binds ()
  "The --ro-bind triples READ :SYSTEM makes for SYSTEM-READ-PATHS."
  (loop for p in (sc:system-read-paths)
        for s = (bns p)
        unless (or (string= s "/dev") (uiop:string-prefix-p "/dev/" s)
                   (string= s "/proc") (uiop:string-prefix-p "/proc/" s))
          append (list "--ro-bind" s s)))

(defunix bwrap-read-system
  (with-tree (root)
    (let* ((tmp (tmp-of root))
           (area (bns (sub root "area/")))
           (ro (bns (sub root "ro/")))
           (c (area-confinement root :read :system
                                     :deny-read (list (sub root "ro/hidden/") (sub root "secrets/")))))
      (ok (equal (append +bwrap-head+
                         '("--unshare-net")
                         (system-binds)
                         (list "--ro-bind" ro ro
                               "--dev" "/dev" "--proc" "/proc"
                               "--bind" area area
                               "--bind" (bns tmp) (bns tmp)
                               "--perms" "0000" "--tmpfs" (bns (sub root "ro/hidden/"))
                               "--remount-ro" (bns (sub root "ro/hidden/"))
                               "--chdir" area
                               "--"))
                 (bwrap-argv c (full-host) (sub root "area/") tmp))
          "secrets/ is never bound, so it needs no mask"))))

(defunix bwrap-read-system-chained-reads-the-trampoline
  (with-tree (root)
    (let ((argv (bwrap-argv (area-confinement root :read :system :cpu-limit 5) (full-host)
                            (sub root "area/") (tmp-of root)))
          (script (bns (trampoline-pathname))))
      (ok (search (list "--ro-bind" script script) argv :test #'equal)))))

(defunix bwrap-start-directory
  (with-tree (root)
    (let ((argv (bwrap-argv (area-confinement root) (full-host) (tmp-of root) (tmp-of root))))
      (ok (equal (list "--chdir" (bns (tmp-of root)) "--") (last argv 3))))))

(defunix bwrap-tmp-shared
  (with-tree (root)
    (let ((argv (bwrap-argv (area-confinement root :tmp :shared) (full-host)
                            (sub root "area/") nil))
          (tmp (bns (uiop:temporary-directory))))
      (ok (search (list "--bind" tmp tmp) argv :test #'equal)))))

(defunix bwrap-path-from-host
  (with-tree (root)
    (ok (equal "/opt/bin/bwrap"
               (first (bwrap-argv (area-confinement root) (full-host :bwrap "/opt/bin/bwrap")
                                  (sub root "area/") (tmp-of root)))))))
