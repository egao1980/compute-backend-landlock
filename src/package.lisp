;;;; Skeleton. The backend lands in milestone R4d-2 (cl-stack
;;;; docs/capabilities/confinement.md); its contract starts the team-solve run.

(defpackage #:compute-backend-landlock
  (:use #:cl)
  (:nicknames #:stack-compute-landlock)
  (:local-nicknames (#:sc #:compute-protocol)))

(in-package #:compute-backend-landlock)
