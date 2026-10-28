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
# (any version): read off the system definitions in the tree and the dist's
# metadata. Nothing compiles here; the guest's SBCL compiles it all. A
# dependency only Windows names (a #+win32 one the dist's Linux-computed
# metadata leaves out) is fetched by the guest's own quickload.
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
                (progn
                  (ql-dist:ensure-installed system)
                  (dolist (dependency (ql-dist:required-systems system))
                    (fetch dependency)))))))))

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
  timeout --kill-after=30 "$seconds" "$analyzer" --backend "$backend" -e "$root" --root-mode rw \
    --network live -s --very-concise --report "$out/$name.jsonl" \
    --mount "$work/sbcl:C:\\sbcl:ro" --mount "$work/git:C:\\git:rw" --mount "$c:C:\\work:rw" \
    --env HOME 'C:\work\home' --env USERPROFILE 'C:\work\home' \
    --env TEMP 'C:\work\temp' --env TMP 'C:\work\temp' \
    --env XDG_CACHE_HOME 'C:\work\cache' --env SBCL_HOME 'C:\sbcl' \
    --env PATH 'C:\work\nodecode\src;C:\sbcl;C:\git\cmd;C:\Windows\System32;C:\Windows' \
    "${env[@]}" --working-directory "${GUEST_CWD:-C:\\work}" "$@" > "$out/$name.out" 2>&1 || rc=$?
  sed -i 's/\r$//' "$out/$name.out"
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

# --- the stages ----------------------------------------------------------------
stage_start() {
  guest sbcl-version 300 -- 'C:\sbcl\sbcl.exe' --version || return 1
  cat "$out/sbcl-version.out"
  grep -q "SBCL $sbcl_version" "$out/sbcl-version.out" || return 1
  cat > "$c/start.lisp" <<'EOF'
(format t "~&start: ~a ~a on ~a ~a~%" (lisp-implementation-type) (lisp-implementation-version)
        (software-type) (machine-type))
(format t "~&start: (+ 1 2) = ~a~%" (+ 1 2))
EOF
  guest sbcl-eval 300 -- 'C:\sbcl\sbcl.exe' --noinform --non-interactive --no-sysinit --no-userinit \
    --load 'C:\work\start.lisp' || return 1
  cat "$out/sbcl-eval.out"
  grep -q '^start: (+ 1 2) = 3' "$out/sbcl-eval.out"
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

stage_build() {
  GUEST_CWD='C:\work\nodecode\src' guest build 5400 NODECODE_BUILD_COMMIT="$label" -- 'C:\sbcl\sbcl.exe' \
    --dynamic-space-size 8192 --control-stack-size 8MB --noinform --non-interactive \
    --load 'C:\work\nodecode\src\tools\windows-release.lisp' || return 1
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
  if stage build; then
    stage seams || true
    stage serve || true
  else
    skip seams serve
  fi
else
  red=1
  skip dump build seams serve
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
