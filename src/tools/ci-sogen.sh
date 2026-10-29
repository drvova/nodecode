#!/usr/bin/env bash
# ci-sogen.sh --- a spike: the Windows release's guest half, run under Sogen
# on Linux instead of in the winbox VM.
#
# SPDX-License-Identifier: MIT
#
#   ci-sogen.sh ANALYZER ROOT [OUT]
#
# ANALYZER is Sogen's analyzer binary (github.com/momo5502/sogen), ROOT a
# Sogen emulation root: the real Windows system DLLs and a registry dump. No
# Windows boots here. Each guest command is one emulated process: Sogen
# serves its syscalls, and KVM runs its code on the host CPU (SOGEN_BACKEND,
# default kvm). The stages follow the path release-windows.ps1 takes in the
# VM, smallest first, so the first red one says how far an emulated Windows
# carries the release:
#
#   start    sbcl.exe --version, and the image evaluating a form
#   dump     compile-file, threads, a full GC, a socket, save-lisp-and-die,
#            and the dumped exe run
#   build    windows-release.lisp on the release tree: the pinned dist, the
#            whole system, the nodecode/bin dump
#   seams    release-windows.ps1's trial checks against that nodecode.exe
#   serve    a headless serve publishing its port
#
# What the VM does in PowerShell the host does here: the tree (git archive
# and the shipped cells), SBCL (the 2.6.8 MSI, unpacked by msiextract), Git
# for Windows (PortableGit: sh.exe and the OpenSSL pair), libsqlite3.dll and
# quicklisp's sources (the prefetch below). Each guest command's console
# output and Sogen's event report land in OUT (default dist/sogen), and the
# stage table goes to OUT/summary.md and $GITHUB_STEP_SUMMARY. Any red stage
# fails the run.
set -euo pipefail

usage='usage: ci-sogen.sh ANALYZER ROOT [OUT]'
analyzer="$(realpath "${1:?$usage}")"
root="$(realpath "${2:?$usage}")"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"
mkdir -p "${3:-dist/sogen}"
out="$(realpath "${3:-dist/sogen}")"
backend="${SOGEN_BACKEND:-kvm}"
[ -d "$root/filesys" ] || { echo "ci-sogen: $root holds no filesys/: not an emulation root" >&2; exit 1; }
for tool in msiextract 7z unzip sbcl git python3 curl timeout; do
  command -v "$tool" >/dev/null || { echo "ci-sogen: $tool is needed" >&2; exit 1; }
done

sbcl_version=2.6.8
git_version=2.51.0
# build-windows.ps1's own pin, so both builds load the same libsqlite3.dll.
sqlite_url="$(sed -n 's/.*\$SqliteZip = "\(.*\)".*/\1/p' src/tools/build-windows.ps1)"
[ -n "$sqlite_url" ] || { echo 'ci-sogen: no $SqliteZip in build-windows.ps1' >&2; exit 1; }
label="$(git rev-parse --short=9 HEAD)"

work="$(mktemp -d "${TMPDIR:-/tmp}/nodecode-sogen.XXXXXX")"
# Every emulated process, a child process's own analyzer too, runs ANALYZER
# under `timeout': both are stopped by name.
stop_guests() {
  pkill -f "^timeout --kill-after=30 [0-9]* $analyzer " 2>/dev/null || true
  pkill -f "^$analyzer " 2>/dev/null || true
}
trap 'stop_guests; rm -rf "$work"' EXIT
c="$work/c" # the guest's C:\work
tree="$c/nodecode"
mkdir -p "$c/home" "$c/cache" "$c/temp" "$c/out" "$c/trialhome" "$tree" "$work/dl"

fetch() { curl -fsSL --retry 3 -o "$1" "$2"; }

# --- what the guest runs -------------------------------------------------------
echo "ci-sogen: SBCL $sbcl_version, PortableGit $git_version, $(basename "$sqlite_url")"
fetch "$work/dl/sbcl.msi" \
  "https://downloads.sourceforge.net/project/sbcl/sbcl/$sbcl_version/sbcl-$sbcl_version-x86-64-windows-binary.msi"
(cd "$work/dl" && msiextract sbcl.msi >/dev/null)
mv "$work/dl/PFiles/Steel Bank Common Lisp" "$work/sbcl"
fetch "$work/dl/git.7z.exe" \
  "https://github.com/git-for-windows/git/releases/download/v$git_version.windows.1/PortableGit-$git_version-64-bit.7z.exe"
7z x -y -o"$work/git" "$work/dl/git.7z.exe" >/dev/null

git archive HEAD | tar -x -C "$tree"
src/tools/pull-cells.sh "$tree/src/cells" >/dev/null
fetch "$work/dl/sqlite.zip" "$sqlite_url"
unzip -q -o "$work/dl/sqlite.zip" sqlite3.dll -d "$work/dl"
cp "$work/dl/sqlite3.dll" "$tree/src/libsqlite3.dll"
cp "$work/git/mingw64/bin/libssl-3-x64.dll" "$work/git/mingw64/bin/libcrypto-3-x64.dll" "$tree/src/"

# Quicklisp under the guest's home, on windows-release.lisp's own dist, with
# every release the nodecode/bin dump reaches downloaded by the host's SBCL
# (any version): read off the system definitions in the tree, the dist's
# metadata, and every (:feature ...) dependency in each release's .asd files
# whatever the feature -- the dist's metadata was computed on Linux, so a
# Windows-only one (dexador's winhttp) is in it nowhere. Nothing compiles
# here; the guest's SBCL compiles it all, and it reaches no network for it:
# Sogen's live network connects, but a write on the socket fails.
dist="$(sed -n 's|^ *"\(http://beta.quicklisp.org/dist/[^"]*\)".*|\1|p' src/tools/windows-release.lisp)"
[ -n "$dist" ] || { echo 'ci-sogen: no quicklisp dist in windows-release.lisp' >&2; exit 1; }
cat > "$work/prefetch.lisp" <<'EOF'
(require :asdf)
(defpackage #:sogen-prefetch (:use #:cl))
(in-package #:sogen-prefetch)

(destructuring-bind (home tree dist) (last sb-ext:*posix-argv* 3)
  (defparameter *home* (uiop:ensure-directory-pathname home))
  (defparameter *src* (merge-pathnames "src/" (uiop:ensure-directory-pathname tree)))
  (defparameter *dist* dist))

(let ((setup (merge-pathnames "quicklisp/setup.lisp" *home*)))
  (if (probe-file setup)
      (load setup)
      (uiop:symbol-call :quicklisp-quickstart :install :path (merge-pathnames "quicklisp/" *home*))))
(uiop:symbol-call :ql-dist :install-dist *dist* :replace t :prompt nil)

(asdf:load-asd (merge-pathnames "nodecode.asd" *src*))
(dolist (asd (directory (merge-pathnames "cells/context/*.asd" *src*)))
  (asdf:load-asd asd))

(defun dependency-name (spec)
  "The system a DEPENDS-ON entry names, or NIL for a (:require ...) contrib."
  (cond ((stringp spec) spec)
        ((symbolp spec) (string-downcase spec))
        ((member (first spec) '(:feature :if-feature)) (dependency-name (third spec)))
        ((eq (first spec) :version) (dependency-name (second spec)))
        (t nil)))

(defvar *seen* (make-hash-table :test 'equal))
(defvar *scanned* (make-hash-table :test 'equal))

(defun feature-dependencies (asd)
  "Every dependency ASD names in a (:feature ...) form, whatever the feature."
  (let ((text (uiop:read-file-string asd)) (found '()))
    (loop for start = (search "(:feature" text) then (search "(:feature" text :start2 (1+ start))
          while start
          do (let* ((form (ignore-errors
                           (let ((*read-eval* nil) (*package* (find-package '#:sogen-prefetch)))
                             (read-from-string text t nil :start start))))
                    (name (and (consp form) (dependency-name form))))
               (when name (push name found))))
    found))

(defun fetch (name)
  "Download NAME's release and every release its dependencies reach."
  (unless (gethash name *seen*)
    (setf (gethash name *seen*) t)
    (let ((local (asdf:find-system name nil)))
      (if (and local (uiop:subpathp (asdf:system-source-file local) *src*))
          (dolist (spec (asdf:system-depends-on local))
            (let ((dependency (dependency-name spec)))
              (when dependency (fetch dependency))))
          (let ((system (or (ql-dist:find-system name)
                            (ql-dist:find-system (asdf:primary-system-name name)))))
            (if (null system)
                (format t "~&sogen-prefetch: ~a is in no dist (a contrib, or Windows fetches it)~%" name)
                (let ((release (ql-dist:release system)))
                  (ql-dist:ensure-installed system)
                  (dolist (dependency (ql-dist:required-systems system))
                    (fetch dependency))
                  (unless (gethash (ql-dist:name release) *scanned*)
                    (setf (gethash (ql-dist:name release) *scanned*) t)
                    (dolist (asd (directory (merge-pathnames "**/*.asd" (ql-dist:base-directory release))))
                      (dolist (dependency (feature-dependencies asd))
                        (fetch dependency)))))))))))

(fetch "nodecode/bin")
(format t "~&sogen-prefetch: ~d releases under ~a~%"
        (length (ql-dist:installed-releases (ql-dist:dist "quicklisp")))
        (merge-pathnames "quicklisp/" *home*))
EOF
fetch "$work/dl/quicklisp.lisp" https://beta.quicklisp.org/quicklisp.lisp
sbcl --noinform --non-interactive --load "$work/dl/quicklisp.lisp" \
  --load "$work/prefetch.lisp" "$c/home" "$tree" "$dist" > "$out/prefetch.log" 2>&1 || {
  tail -n 30 "$out/prefetch.log"
  exit 1
}
tail -n 1 "$out/prefetch.log"
# release-windows.ps1's scratch home: a build or a trial never looks for a release.
printf '%s\n' '{"update":{"mode":"off"}}' > "$c/home/config.jsonc"
printf '%s\n' '{"update":{"mode":"off"}}' > "$c/trialhome/config.jsonc"

# --- one emulated process ------------------------------------------------------
# guest NAME SECONDS [NAME=VALUE...] -- EXE ARGS... runs EXE in the emulator,
# stdin passed through, its console output in OUT/NAME.out and Sogen's events
# in OUT/NAME.jsonl, and fails as the guest does. GUEST_CWD sets the guest's
# working directory (default C:\work). The environment is release-windows.ps1's
# scratch one; each NAME=VALUE is laid over it.
guest() {
  local name="$1" seconds="$2" env=() rc=0
  shift 2
  while [ "$1" != -- ]; do
    env+=(--env "${1%%=*}" "${1#*=}")
    shift
  done
  shift
  # GUEST_TRACE=1: Sogen's own log of every syscall and exception, not just
  # the guest's console.
  local logging=(-s --very-concise)
  [ "${GUEST_TRACE:-}" != 1 ] || logging=()
  timeout --kill-after=30 "$seconds" "$analyzer" --backend "$backend" -e "$root" --root-mode rw \
    --network live "${logging[@]}" --report "$out/$name.jsonl" \
    --mount "$work/sbcl:C:\\sbcl:ro" --mount "$work/git:C:\\git:rw" --mount "$c:C:\\work:rw" \
    --env HOME 'C:\work\home' --env USERPROFILE 'C:\work\home' \
    --env TEMP 'C:\work\temp' --env TMP 'C:\work\temp' \
    --env XDG_CACHE_HOME 'C:\work\cache' --env SBCL_HOME 'C:\sbcl' \
    --env PATH 'C:\work\nodecode\src;C:\sbcl;C:\git\cmd;C:\Windows\System32;C:\Windows' \
    "${env[@]}" --working-directory "${GUEST_CWD:-C:\\work}" "$@" > "$out/$name.out" 2>&1 || rc=$?
  sed -i 's/\r$//; s/\x1b\[[0-9;]*m//g' "$out/$name.out"
  # A build's report runs to gigabytes: its first and last events say enough.
  if [ "$(stat -c%s "$out/$name.jsonl" 2>/dev/null || echo 0)" -gt 50000000 ]; then
    { head -c 2000000 "$out/$name.jsonl"; echo; tail -c 8000000 "$out/$name.jsonl"; } > "$out/$name.jsonl.cut"
    mv "$out/$name.jsonl.cut" "$out/$name.jsonl"
  fi
  [ "$rc" = 0 ] && return 0
  echo "ci-sogen: $name failed (rc $rc$([ "$rc" = 124 ] && echo ', timed out')); the last of its output:"
  tail -n 40 "$out/$name.out"
  echo "ci-sogen: the last of Sogen's events for $name:"
  tail -n 8 "$out/$name.jsonl" 2>/dev/null | cut -c1-400
  return 1
}

# guest_exit NAME: the exit code the guest itself returned (the analyzer's own
# is 0 or 1), off the footer of its report.
guest_exit() {
  sed -n 's/.*"type":"footer".*"exit":\([0-9-]*\).*/\1/p' "$out/$1.jsonl" 2>/dev/null | tail -n 1
}

# trace NAME SECONDS [NAME=VALUE...] -- EXE ARGS...: run it again with Sogen's
# whole log (as NAME-trace), and print what Sogen said it could not do and the
# log up to the guest's first trap or fault.
trace() {
  local name="$1-trace"
  echo "ci-sogen: $1 again with Sogen's whole log, as $name"
  shift
  GUEST_TRACE=1 guest "$name" "$@" >/dev/null || true
  echo "ci-sogen: what Sogen reported it does not support, in $name:"
  grep -i -E 'unsupported|unimplemented|not implemented|not supported|unknown|unhandled|warn' "$out/$name.out" |
    sort | uniq -c | sort -rn | head -n 40
  local first
  first="$(grep -n -i -E 'breakpoint|exception|violation|illegal' "$out/$name.out" | head -n 1 | cut -d: -f1)"
  if [ -n "$first" ]; then
    echo "ci-sogen: $name up to its first trap (line $first):"
    sed -n "$((first > 120 ? first - 120 : 1)),$((first + 10))p" "$out/$name.out"
  else
    echo "ci-sogen: the last of $name:"
    tail -n 120 "$out/$name.out"
  fi
}

# --- the stages ----------------------------------------------------------------
# The image's first steps, each its own process, smallest first: the
# runtime alone; the Lisp toplevel answering an exit code, no stream touched;
# a file written; the console written to; a file loaded. The probes after the
# first all run with a debugger hook that writes the condition to a file, so
# an error is named even when the console stream is what broke. The first red
# probe is run again with Sogen's whole log (trace).
probe_hook='(setf sb-ext:*invoke-debugger-hook* (lambda (c h) (declare (ignore h)) (ignore-errors (with-open-file (s "C:/work/probe-error.txt" :direction :output :if-exists :append :if-does-not-exist :create) (format s "~s: ~a~%" (type-of c) c))) (sb-ext:exit :code 3 :abort t)))'
probe_red=""
# probe NAME CHECK [SBCL ARGS...]: one probe, judged by the shell command CHECK.
probe() {
  local name="$1" check="$2"
  shift 2
  rm -f "$c/probe-error.txt"
  guest "$name" 300 -- 'C:\sbcl\sbcl.exe' "$@" >/dev/null || true
  if eval "$check"; then
    echo "ci-sogen: probe $name pass"
    return 0
  fi
  echo "ci-sogen: probe $name FAIL (guest exit $(guest_exit "$name")); its console:"
  tail -n 20 "$out/$name.out"
  if [ -s "$c/probe-error.txt" ]; then
    echo "ci-sogen: the condition the hook caught:"
    cat "$c/probe-error.txt"
    cp "$c/probe-error.txt" "$out/$name.error"
  fi
  if [ -z "$probe_red" ]; then
    probe_red="$name"
    trace "$name" 300 -- 'C:\sbcl\sbcl.exe' "$@"
  fi
  return 1
}

stage_start() {
  local quiet=(--noinform --no-sysinit --no-userinit --disable-debugger) red=0
  cat > "$c/start.lisp" <<'EOF'
(format t "~&start: ~a ~a on ~a ~a~%" (lisp-implementation-type) (lisp-implementation-version)
        (software-type) (machine-type))
(format t "~&start: (+ 1 2) = ~a~%" (+ 1 2))
EOF
  probe sbcl-version 'grep -q "SBCL $sbcl_version" "$out/sbcl-version.out"' --version || red=1
  probe sbcl-exit '[ "$(guest_exit sbcl-exit)" = 7 ]' \
    "${quiet[@]}" --eval '(sb-ext:exit :code 7 :abort t)' || red=1
  probe sbcl-file 'grep -qx 3 "$c/probe.txt" 2>/dev/null' "${quiet[@]}" --eval "$probe_hook" \
    --eval '(progn (with-open-file (s "C:/work/probe.txt" :direction :output :if-exists :supersede) (princ (+ 1 2) s)) (sb-ext:exit :code 0 :abort t))' || red=1
  probe sbcl-print 'grep -qx 3 "$out/sbcl-print.out"' "${quiet[@]}" --eval "$probe_hook" \
    --eval '(progn (princ (+ 1 2)) (terpri) (finish-output) (sb-ext:exit :code 0))' || red=1
  probe sbcl-eval 'grep -q "^start: (+ 1 2) = 3" "$out/sbcl-eval.out"' "${quiet[@]}" --eval "$probe_hook" \
    --load 'C:\work\start.lisp' --eval '(sb-ext:exit :code 0)' || red=1
  cat "$out/sbcl-eval.out"
  [ "$red" = 0 ]
}

stage_dump() {
  cat > "$c/dump.lisp" <<'EOF'
(require :sb-posix)
(require :sb-bsd-sockets)
(require :sb-concurrency)
(with-open-file (s "C:/work/temp/fib.lisp" :direction :output :if-exists :supersede)
  (write-string "(defun fib (n) (if (< n 2) n (+ (fib (- n 1)) (fib (- n 2)))))" s))
(load (compile-file "C:/work/temp/fib.lisp"))
(format t "~&dump: fib 25 = ~a~%" (fib 25))
(handler-case
    (format t "~&dump: threads answered ~a~%"
            (mapcar #'sb-thread:join-thread
                    (loop for i below 4
                          collect (let ((n (+ 20 i))) (sb-thread:make-thread (lambda () (fib n)))))))
  (error (e) (format t "~&dump: threads failed: ~a~%" e)))
(let ((junk (loop repeat 200 collect (make-array 100000 :element-type '(unsigned-byte 8)))))
  (sb-ext:gc :full t)
  (format t "~&dump: a full gc kept ~a arrays, ~a bytes in use~%" (length junk) (sb-kernel:dynamic-usage)))
(handler-case
    (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
      (sb-bsd-sockets:socket-bind socket #(127 0 0 1) 0)
      (sb-bsd-sockets:socket-listen socket 5)
      (format t "~&dump: a socket listened on port ~a~%" (nth-value 1 (sb-bsd-sockets:socket-name socket)))
      (sb-bsd-sockets:socket-close socket))
  (error (e) (format t "~&dump: the socket failed: ~a~%" e)))
(finish-output)
(sb-ext:save-lisp-and-die "C:/work/out/dump.exe" :executable t
  :toplevel (lambda ()
              (format t "~&dump: the dumped image says ~a~%" (fib 20))
              (finish-output)
              (sb-ext:exit :code 0)))
EOF
  guest sbcl-dump 900 -- 'C:\sbcl\sbcl.exe' --noinform --non-interactive --no-sysinit --no-userinit \
    --load 'C:\work\dump.lisp' || return 1
  cat "$out/sbcl-dump.out"
  [ -s "$c/out/dump.exe" ] || { echo 'ci-sogen: save-lisp-and-die left no dump.exe'; return 1; }
  guest dump-run 300 -- 'C:\work\out\dump.exe' || return 1
  cat "$out/dump-run.out"
  grep -q '^dump: the dumped image says 6765' "$out/dump-run.out"
}

# The fault that corrupted the build, kept as a check. A GC safepoint fault
# (a read of the page SBCL's GC protects) exits Sogen's KVM backend as MMIO;
# until patch 0003 the dispatched exception lost its RIP and kept its RSP,
# so no handler ran and each fault cost a 0x600-byte exception frame -- the
# 2 MB stack was gone at the 1362nd, and the build read zeroed frames.
#   sp-drift  one frame consing through ~200 GCs, watching its own SP
#   mem       tagged vectors and lists checked word by word through the GCs
isolate_options=(--dynamic-space-size 8192 --control-stack-size 8MB --noinform --non-interactive --no-sysinit --no-userinit)
isolate() { # isolate NAME FORM...: run FORMs; the probe passes when NAME's marker line is printed
  local name="$1" forms=() form
  shift
  for form in "$@"; do forms+=(--eval "$form"); done
  mkdir -p "$c/cache-$name"
  guest "$name" 900 XDG_CACHE_HOME="C:\\work\\cache-$name" -- 'C:\sbcl\sbcl.exe' "${isolate_options[@]}" \
    "${forms[@]}" --eval "(format t \"~&$name-done, GC run time ~d~%\" sb-ext:*gc-run-time*)" >/dev/null || true
  local faults
  faults="$(grep -c 0x50100000 "$out/$name.jsonl" 2>/dev/null)"
  if grep -q "^$name-done" "$out/$name.out"; then
    echo "ci-sogen: $name: pass ($faults safepoint faults) -- $(grep -h "^$name-done\|^mem:\|^drift:" "$out/$name.out" | tr '\n' ' ')"
    return 0
  fi
  echo "ci-sogen: $name: FAIL ($faults safepoint faults):"
  grep -m 8 -E 'Unhandled|Unknown|error|fatal|Ptr|junk|sees|verify|corrupt|^mem:|^0: ' "$out/$name.out"
  return 1
}

stage_isolate() {
  local red=0
  # sp-drift: one frame that conses through ~200 GCs (a 4 MB nursery, so each
  # GC's safepoint faults land in this frame) and watches its own stack
  # pointer. Resuming from a fault must give back the frame's stack pointer;
  # the run that took 1362 faults in mem ran out of a 2 MB stack.
  cat > "$c/drift.lisp" <<'EOF'
(setf (sb-ext:bytes-consed-between-gcs) (* 4 1024 1024))
(sb-ext:gc)
(defun drift ()
  (let* ((sp0 (sb-sys:sap-int (sb-kernel:current-sp))) (lo sp0) (hi sp0) (x nil))
    (dotimes (i 50000000)
      (setq x (cons i x))
      (when (zerop (logand i 1023)) (setq x nil))
      (let ((sp (sb-sys:sap-int (sb-kernel:current-sp))))
        (when (< sp lo) (setq lo sp))
        (when (> sp hi) (setq hi sp))))
    (format t "~&drift: sp ~x at entry, lowest ~x, highest ~x: ~d bytes below entry~%" sp0 lo hi (- sp0 lo))))
(compile 'drift)
(drift)
EOF
  isolate sp-drift '(load "C:/work/drift.lisp")' || red=1
  grep -q '^drift: .*: 0 bytes below entry' "$out/sp-drift.out" || red=1
  cat > "$c/mem.lisp" <<'EOF'
(defvar *bad* 0)
(defun check-vector (v tag)
  (loop for x across v unless (eql x tag) do (incf *bad*)))
(let ((keep '()))
  (dotimes (round 60)
    (push (loop for i below 50
                collect (let ((tag (+ (* round 100) i)))
                          (cons tag (make-array 16384 :initial-element tag))))
          keep)
    (when (> (length keep) 10) (setf keep (subseq keep 0 10)))
    (let ((l (loop for i below 200000 collect (cons i (* 2 i)))))
      (loop for (a . b) in l unless (eql b (* 2 a)) do (incf *bad*)))
    (dolist (batch keep)
      (dolist (e batch) (check-vector (cdr e) (car e)))))
  (sb-ext:gc :full t)
  (dolist (batch keep)
    (dolist (e batch) (check-vector (cdr e) (car e)))))
(format t "~&mem: ~d bad words~%" *bad*)
EOF
  isolate mem '(load "C:/work/mem.lisp")' || red=1
  grep -q '^mem: 0 bad words' "$out/mem.out" || red=1
  [ "$red" = 0 ]
}

# SOGEN_BUILD_SECONDS bounds the build (default 90 minutes). SOGEN_TRACE_BUILD=1
# runs it under Sogen's whole log and keeps the log's tail: where a build that
# hangs stops is what it is waiting on.
stage_build() {
  local rc=0
  GUEST_TRACE="${SOGEN_TRACE_BUILD:-}" GUEST_CWD='C:\work\nodecode\src' guest build "${SOGEN_BUILD_SECONDS:-5400}" \
    NODECODE_BUILD_COMMIT="$label" -- 'C:\sbcl\sbcl.exe' \
    --dynamic-space-size 8192 --control-stack-size 8MB --noinform --non-interactive \
    --load 'C:\work\nodecode\src\tools\windows-release.lisp' || rc=1
  if [ "${SOGEN_TRACE_BUILD:-}" = 1 ]; then
    echo "ci-sogen: the build's threads, under Sogen's whole log:"
    grep -i -E 'thread (created|terminated|exit)|switch' "$out/build.out" | tail -n 30
    echo "ci-sogen: the syscalls in the last 5000 lines of that log:"
    tail -n 5000 "$out/build.out" | grep -o 'Executing syscall: [A-Za-z0-9_]*' | sort | uniq -c | sort -rn | head -n 15
    echo "ci-sogen: the last of it:"
    tail -n 120 "$out/build.out"
    tail -n 20000 "$out/build.out" > "$out/build.out.tail" && mv "$out/build.out.tail" "$out/build.out"
  fi
  [ "$rc" = 0 ] || return 1
  tail -n 5 "$out/build.out"
  if [ ! -e "$tree/nodecode.exe" ] && [ -e "$tree/nodecode" ]; then mv "$tree/nodecode" "$tree/nodecode.exe"; fi
  [ -s "$tree/nodecode.exe" ] || { echo "ci-sogen: the build left no nodecode.exe in $tree"; return 1; }
  cp "$tree/src/libsqlite3.dll" "$tree/src/libssl-3-x64.dll" "$tree/src/libcrypto-3-x64.dll" "$tree/"
  echo "ci-sogen: nodecode.exe $(stat -c%s "$tree/nodecode.exe") bytes"
}

# trial FORM WANT [NAME=VALUE...]: release-windows.ps1's Trial, the form on the
# trial verb's stdin and the score line read back.
trials=0
trial() {
  local form="$1" want="$2" name got
  shift 2
  trials=$((trials + 1))
  name="trial-$trials"
  printf '%s\n' "$form" > "$out/$name.form"
  GUEST_CWD='C:\work\nodecode' guest "$name" 300 HOME='C:\work\trialhome' USERPROFILE='C:\work\trialhome' \
    NODECODE_HOME='C:\work\trialhome\.nodecode' "$@" -- 'C:\work\nodecode\nodecode.exe' trial \
    < "$out/$name.form" >/dev/null || true
  got="$(sed -n 's/^nodecode-trial-score \([^ ]*\).*/\1/p' "$out/$name.out" | tail -n 1)"
  if [ "$got" = "$want" ]; then
    echo "ci-sogen: pass  $form"
    return 0
  fi
  echo "ci-sogen: FAIL  $form -- answered '${got:-nothing}', wanted $want ($name.out):"
  tail -n 15 "$out/$name.out"
  return 1
}

stage_seams() {
  local red=0
  printf '%s\n' new > "$c/temp/from.txt"
  printf '%s\n' old > "$c/temp/to.txt"
  trial '(+ 1 2)' 3 || red=1
  trial '(progn (nlk::hand-over-to-published-image) 1)' 1 || red=1
  # what the image reopens at start is the files beside it, not a PATH's
  trial '(+ 2 3)' 5 PATH='C:\Windows\System32;C:\Windows' || red=1
  trial '(if (= 2 (length (multiple-value-list (nlt:terminal-size)))) 1 0)' 1 || red=1
  trial '(if (and nlk:*shell* (search "sh" (namestring nlk:*shell*))) 1 0)' 1 || red=1
  trial '(multiple-value-bind (out err status) (nlk:run-bounded (nlk:shell-argv "echo hi; echo bad 1>&2; exit 4") :seconds 20) (if (and (search "hi" out) (search "bad" err) (eql status 4)) 1 0))' 1 || red=1
  trial '(if (eq :timeout (nth-value 2 (nlk:run-bounded (nlk:shell-argv "sleep 30") :seconds 1))) 1 0)' 1 || red=1
  trial '(if (nlk:pid-live-p (sb-posix:getpid)) 1 0)' 1 || red=1
  trial '(let ((before (nlk:resident-bytes))) (if (and (integerp before) (eq t (nlk::release-image-pages)) (< (nlk:resident-bytes) before)) 1 0))' 1 || red=1
  trial '(if (nlk:pid-live-p 4000000) 0 1)' 1 || red=1
  trial '(let ((lock (nlk:lock-file "C:/work/temp/probe.lock"))) (if (and lock (nlk:file-locked-p "C:/work/temp/probe.lock") (progn (nlk:unlock-file lock) (not (nlk:file-locked-p "C:/work/temp/probe.lock")))) 1 0))' 1 || red=1
  trial '(progn (nlk:spawn-detached (list "cmd" "/c" "echo detached-marker") "C:/work/temp/detached.log") (sleep 3) (if (search "detached-marker" (uiop:read-file-string "C:/work/temp/detached.log")) 1 0))' 1 || red=1
  trial '(progn (nlk:replace-file "C:/work/temp/from.txt" "C:/work/temp/to.txt") (if (and (search "new" (uiop:read-file-string "C:/work/temp/to.txt")) (not (probe-file "C:/work/temp/from.txt"))) 1 0))' 1 || red=1
  [ "$red" = 0 ]
}

# The VM's serve check also proves the store lock is held while the owner lives
# and free after it. Each Sogen run is its own kernel, so no second process
# here can ask for that lock: this stage proves the boot and the port only.
stage_serve() {
  local owner="$c/temp/serve/history.db.owner" port="" waited=0
  mkdir -p "$c/temp/serve"
  GUEST_CWD='C:\work\nodecode' guest serve 600 HOME='C:\work\trialhome' USERPROFILE='C:\work\trialhome' \
    NODECODE_HOME='C:\work\trialhome\.nodecode' -- 'C:\work\nodecode\nodecode.exe' serve \
    --store 'C:\work\temp\serve\history.db' < /dev/null > /dev/null &
  local runner=$!
  while [ "$waited" -lt 300 ] && kill -0 "$runner" 2>/dev/null; do
    if [ -s "$owner" ]; then
      port="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("port") or "")' "$owner" 2>/dev/null || true)"
      [ -n "$port" ] && break
    fi
    sleep 2
    waited=$((waited + 2))
  done
  if [ -n "$port" ]; then
    echo "ci-sogen: serve published port $port after ${waited}s"
    # --network live: whether the guest's listener is a host socket too
    local code
    code="$(curl -s -m 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/" || true)"
    case "$code" in
      ''|000) echo "ci-sogen: the host did not reach port $port (the emulator's own, not a host socket)" ;;
      *) echo "ci-sogen: the host reached port $port: HTTP $code" ;;
    esac
  fi
  stop_guests
  wait "$runner" 2>/dev/null || true
  tail -n 20 "$out/serve.out"
  [ -n "$port" ] || { echo 'ci-sogen: serve never published its port'; return 1; }
}

# --- the run ---------------------------------------------------------------------
results=()
red=0
# stage NAME: run stage_NAME, timed, its verdict kept for the table.
stage() {
  local t0=$SECONDS verdict=pass
  echo "ci-sogen: === $1 ==="
  "stage_$1" || verdict=FAIL
  results+=("$1|$verdict|$((SECONDS - t0))")
  echo "ci-sogen: $1 $verdict in $((SECONDS - t0))s"
  [ "$verdict" = pass ] || red=1
  [ "$verdict" = pass ]
}
skip() {
  local name
  for name in "$@"; do results+=("$name|skipped|-"); done
}

if stage start; then
  stage dump || true
  stage isolate || true
  if stage build; then
    stage seams || true
    stage serve || true
  else
    skip seams serve
  fi
else
  red=1
  skip dump isolate build seams serve
fi

{
  echo "### Nodecode's Windows release under Sogen ($backend backend), $label"
  echo
  echo '| stage | verdict | seconds |'
  echo '|---|---|---|'
  for row in "${results[@]}"; do
    IFS='|' read -r name verdict seconds <<< "$row"
    echo "| $name | $verdict | $seconds |"
  done
} > "$out/summary.md"
cat "$out/summary.md"
[ -z "${GITHUB_STEP_SUMMARY:-}" ] || cat "$out/summary.md" >> "$GITHUB_STEP_SUMMARY"
[ "$red" = 0 ]
