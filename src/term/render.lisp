;;;; render.lisp --- one frame onto the terminal.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Copyright (C) 2025  Anthony Green <green@moxielogic.com>
;;;; Derived from cl-tuition's renderer.lisp (see NOTICE).
;;;;
;;;; A frame is the view-state's content laid out into cells, its overlay
;;;; applied to them, diffed against the previous frame, and written inside a
;;;; synchronized update so the terminal shows no tearing. The mode
;;;; transitions between the two view-states go first, the image placements
;;;; are diffed after the cells, and the cursor, hidden for the whole paint,
;;;; is placed and shown last, before the update closes, reached from where
;;;; the paint left it.

(in-package #:nodecode.term)

(nlk:access (cursor cursor) (view view-state))

(nlk:define-record (renderer (:constructor make-renderer (&key (output-stream *standard-output*)
                                                               (width 80) (height 24))))
  "The painter's memory: the last frame's cells and view-state, the
terminal's size, the placements on screen."
  (last-buffer nil)
  (last-view-state nil)
  (output-stream *standard-output*)
  (width 80 :type fixnum)
  (height 24 :type fixnum)
  (last-images '() :type list))

;;; A frame used to build a fresh WIDTH x HEIGHT grid of cells, which is 828
;;; KiB on a 157x72 window, every frame. Two grids alternating is enough to
;;; paint anything — the new one is diffed against the last one and then
;;; becomes it — so the third and later frames of a geometry allocate nothing.
;;;
;;; One scratch for the process, not a slot on the renderer, and deliberately:
;;; redefining the renderer struct under a running paint leaves the live
;;; instance obsolete, and an accessor on the new slot would read past an old
;;; instance's last slot. The scratch is only ever a retired front buffer — a
;;; renderer's own last-buffer is never handed out — so two renderers sharing
;;; it cannot hurt either one's diff.
(defvar *frame-scratch* nil
  "The cell grid the next frame is parsed into: the buffer one paint retired.")

;;; A launcher's hand-over waits for the first of them (cli/entry.lisp,
;;; DECIDE-FOLDER-BEHIND-THE-FRAME): a successor is told it inherited a live
;;; screen, and that is only true once a frame is really on it. A
;;; process-level counter, not a renderer slot — redefining the renderer
;;; struct under a running paint leaves the live instance obsolete. Zeroed
;;; at every image start: the release dump paints four frames warming the
;;; shell up, and a launch that started counting at four handed its process
;;; over before painting anything, so the successor never entered the
;;; alternate screen and the whole session painted over the shell's
;;; scrollback (a multiplexer drew its own scrollbar beside the rail).
(nlk:define-startup-parameter *frames-on-screen* 0
  "How many frames this process has painted and flushed to its terminal.")

(defun wait-for-frames-past (count &optional (deadline-ms 2000))
  "Wait until this process has painted more than COUNT frames, at most
DEADLINE-MS."
  ;; => T when they landed, NIL at the deadline. A caller that must
  ;; not land inside a frame waits on the number, not on a clock
  (nlk:wait-until (lambda () (> *frames-on-screen* count))
                  (nlk:deadline-after (/ deadline-ms 1000)) 0.001))

(defun row-keys (buffer &aux (w buffer.width))
  "A fixnum per row of BUFFER, its last column (the scroll gutter) left out."
  (let ((keys (make-array buffer.height)))
    (dotimes (y buffer.height keys)
      (let ((h 0))
        (declare (fixnum h))
        (dotimes (x (1- w))
          (let ((cell (screen-buffer-ref buffer x y)))
            (setf h (logand most-positive-fixnum
                            (+ (* h 31) (char-code cell.char) (sxhash cell.fg) (* 7 (sxhash cell.bg)) cell.attrs)))))
        (setf (aref keys y) h)))))

(defun scroll-band (old new stream &aux (h new.height) (ka (row-keys old)) (kb (row-keys new)) best (gain 2))
  "omp's row move: when NEW's rows are OLD's shifted, scroll the band with the
terminal and shift OLD to match, so the diff after it repaints only what changed."
  ;; An optimization only: the diff that follows compares against the shifted
  ;; OLD, so a key collision costs bytes, never a wrong cell. Row 0 never
  ;; moves (Terminal.app archives a top row a scroll deletes into scrollback).
  (loop for shift in (loop for d from 1 below (floor h 2) collect d collect (- d))
        do (loop with start = nil and saved = 0
                 for y from 1 to h
                 for hit = (and (< y h) (< 0 (+ y shift) h) (= (aref kb y) (aref ka (+ y shift))))
                 do (cond (hit (unless start (setf start y saved 0))
                               (unless (= (aref kb y) (aref ka y)) (incf saved)))
                          (start (when (> saved gain)
                                   (setf gain saved best (list shift start (1- y))))
                                 (setf start nil)))))
  (when best
    (destructuring-bind (shift first last) best
      (let* ((d (abs shift))
             (top (if (plusp shift) first (- first d)))
             (bot (if (plusp shift) (+ last d) last)))
        (format stream "~C[0m~C[~D;~Dr~C[~D~C~C[r" #\Escape #\Escape (1+ top) (1+ bot)
                #\Escape d (if (plusp shift) #\S #\T) #\Escape)
        (flet ((move-row (to from)
                 (dotimes (x old.width)
                   (let ((lead (and from (screen-buffer-ref old x from))))
                     (if lead
                         (set-cell (screen-buffer-ref old x to) lead.char lead.width lead.fg lead.bg lead.attrs lead.link)
                         (set-cell (screen-buffer-ref old x to) #\Space 1 nil nil 0 nil))))))
          (if (plusp shift)
              (loop for y from top to bot do (move-row y (and (<= (+ y d) bot) (+ y d))))
              (loop for y from bot downto top do (move-row y (and (>= (- y d) top) (- y d))))))
        t))))

(defun render (renderer view &aux (stream renderer.output-stream)
                                  (width renderer.width)
                                  (height renderer.height))
  "Paint the view-state VIEW through RENDERER."
  (apply-terminal-transitions renderer.last-view-state view stream)
  (setf renderer.last-view-state view)
  ;; The screen is this shell's from here on: whatever INHERIT-SCREEN asked of
  ;; the first frame, later frames are transitions against our own paint.
  (setf *inherit-screen* nil)
  ;; A geometry change (SIGWINCH) makes the previous cells meaningless:
  ;; erase and paint the whole frame rather than diff mismatched grids.
  (let ((old renderer.last-buffer))
    (when (and old (or (/= width old.width) (/= height old.height)))
      (format stream "~C[2J" #\Escape)
      (setf renderer.last-buffer nil)))
  (let ((new (parse-styled-string view.rows width height
                                  :buffer (reusable-screen-buffer
                                           *frame-scratch* width height))))
    ;; A half-block picture is cells like any other, laid in under the
    ;; overlay, so a toast or the selection's wash still draws over it.
    (paint-block-images new view.images)
    (nlk:when-let (overlay view.overlay)
      (funcall overlay new))
    ;; A sixel that moved or went is erased by writing its cells again, and
    ;; one the diff is about to write over is drawn again after it.
    (forget-departed-sixels renderer.last-buffer renderer.last-images view.images)
    ;; The cursor hides before the paint moves it and shows only once it is
    ;; parked, all inside the update. A terminal that holds the update shows
    ;; the frame whole either way; but ConPTY re-emits a console's output on
    ;; its own schedule and cuts it where it likes, so on Windows any point
    ;; of the paint can reach the screen. Shown through the paint, the cursor
    ;; was drawn on whatever cell the frame wrote last (a spinner, a
    ;; countdown) and then jumped back: the caret flickered, and so did
    ;; everything that moves.
    ;;
    ;; The six bytes that hide it are paid for by the motion: the paint
    ;; starts from a cursor whose place it does not assume, so it sends no
    ;; home and goes straight to its first changed cell, and the caret is
    ;; reached from where the paint left off -- a typed key ends its paint
    ;; right at the caret, and costs no motion at all.
    (format stream "~C[?2026h~C[?25l" #\Escape #\Escape)
    (when (and renderer.last-buffer (null renderer.last-images) (null view.images))
      (scroll-band renderer.last-buffer new stream))
    (multiple-value-bind (x y damaged)
        (let ((damaged (damaged-sixels renderer.last-buffer new renderer.last-images view.images)))
          (multiple-value-bind (x y)
              (render-diff renderer.last-buffer new stream :cursor-x nil :cursor-y nil)
            (values x y damaged)))
      (multiple-value-bind (images placed)
          (%render-image-placements renderer.last-images
                                    view.images
                                    stream
                                    :force (null renderer.last-buffer)
                                    :damaged damaged)
        (setf renderer.last-images images)
        (nlk:when-let (cursor view.cursor)
          (move-cursor stream (and (not placed) x) (and (not placed) y)
                       cursor.x cursor.y)
          (format stream "~C[?25h" #\Escape))))
    (format stream "~C[?2026l" #\Escape)
    (force-output stream)
    ;; The frame is on the terminal: the count a launcher's hand-over waits
    ;; on before it replaces itself with a successor that will be told it
    ;; inherited a live screen.
    (incf *frames-on-screen*)
    ;; The buffer just diffed stops being the frame and becomes the next
    ;; frame's scratch: the painter alternates between two grids and
    ;; allocates cells only when the geometry moves. The scratch is a
    ;; retired FRONT buffer, never a live one, so no renderer ever parses
    ;; into a grid something else is still diffing against.
    (setf *frame-scratch* (shiftf renderer.last-buffer new))))
