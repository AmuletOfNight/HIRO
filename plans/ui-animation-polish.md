# HIRO — Smooth state transitions for the status UIs

Status: PLAN — authored for session ses_fef4b6dc8ffeHpeE3T4DkljSgs, 2026-08-17

## 1. Problem

Both status UIs jump between states instead of morphing:

- **GNOME Shell extension** (`packaging/gnome-shell-extension/hiro-status@hiro/extension.js`):
  the daemon broadcasts the first `scanning` event with `variance`/`motion` unset
  (`crates/hirod/src/auth.rs:761` sends `StateEvent::scanning(user)` bare), then starts
  streaming liveness telemetry ~100 ms later (every 3 frames,
  `auth.rs:794-819`). The extension's `_updateLiveness` → `_setMeterVisible(true)`
  flips `_meter.visible`/`_hint.visible` instantly, which changes the column's natural
  size, and `_positionOverlay()` re-centers — the card visibly *jumps* and the meters
  pop into being below the face. The same instant toggle happens when the meters are
  hidden for a result/approval, when the approval box appears/clears, and when the
  enrollment hint appears. Meter *fills* also snap to their new width on every tick.
- **hiro-ui fallback** (`crates/hiro-ui/src/app.rs`): the same symptoms — `meter_box
  .set_visible(true)` changes the window's natural size request, and the
  `connect_size_allocate` re-centre makes the window jump.

UX goals (confirmed with the user):

1. **Meters beside the face** — put the two liveness bars next to the smiley (label on
   top, face on the left, meters stacked beside it) instead of a full-width row below,
   cutting the unused vertical space.
2. **Meters from the first frame** — show empty tracks the moment the scan card appears;
   bars fill in as telemetry streams. Zero mid-scan layout change.
3. **Stay centred** — when the card grows or shrinks it expands/shrinks symmetrically
   around the screen centre (it "breathes"), rather than snapping to a new position.

## 2. Decisions (locked)

| Decision | Choice | Rationale |
| --- | --- | --- |
| Meter placement | Beside the face, stacked in a right-hand column | User-confirmed; reduces vertical bulk |
| Meter timing | Shown empty from the first scanning frame | User-confirmed; removes the mid-scan layout jump entirely |
| Growth direction | Symmetric around screen centre | User-confirmed; both UIs already centre on the primary monitor |
| Reveal mechanism (extension) | Auto-centring stage + animated column size (`clip_to_allocation` + eased `width`/`height`, reset to natural on completion) | Layout-driven reveal keeps every element where it is while the card morphs; no per-frame position math |
| Reveal mechanism (hiro-ui) | Animated window resize (16 ms stepping timer, ease-out) + visibility-driven layout; existing `size_allocate` hook re-centres each step | Deterministic on X11 and XWayland; matches the existing fade-timer pattern |
| Fill animation | Eased `width`/`fraction` tween (~200 ms, ease-out-quad), retargetable on each telemetry tick | Bars grow smoothly instead of snapping |
| Cross-state content swap | Keep today's content crossfade (`_transitionToResult` / label+face fade) and run the size morph in parallel | Already smooth; only the size change needs fixing |

## 3. GNOME Shell extension — implementation

Files: `extension.js`, `stylesheet.css`.

### 3.1 New layout

```
_overlay        (styled card, St.Bin — non-reactive; reactive only during approval)
 └ _column      (vertical)
    ├ _brandRow
    ├ _label             ← moved out of _box; x_align CENTER, on top
    ├ _box               (horizontal, x_align CENTER)
    │  ├ _face
    │  └ _side           (NEW vertical column)
    │     ├ _meter       (Scene motion / Head motion rows)
    │     └ _hint
    └ _approvalBox       (unchanged position: full-width below the content row)
```

- `_label` is a direct child of `_column` above `_box` (today it lives inside `_box`
  beside the face). `_transitionToResult` already crossfades `_box`; extend it to
  crossfade `_label` too (or wrap label+box in a `_body` vertical container and fade
  that — fewer moving parts, recommended).
- `_side` is new: a vertical `St.BoxLayout` holding `_meter` then `_hint`, aligned to
  the face (CAPTION/track rows line up beside the glyph). `_box` keeps `spacing: 18px`.
- Meter rows stay as built by `_makeMeterRow` (`caption 110px` + `METER_WIDTH 190px`
  track). Card becomes wider (~`96 + 18 + 110 + 10 + 190 + padding` ≈ 460 px) and
  shorter (one row of face/meters instead of two stacked blocks).

### 3.2 Centring

The overlay is kept centred on the primary monitor with the original manual
positioning (`_positionOverlay()` → `set_position`), which is proven to work across
shell versions. A full-screen `St.Widget` stage was tried and **reverted**: it caused
the card to fail to re-appear after the first hide/show cycle in live testing.

- A `notify::allocation` handler on the overlay re-centres it whenever its **size**
  changes (tracked via cached last width/height to avoid reacting to position
  changes). This fires every frame while a size morph is running, so the card stays
  centred as it grows/shrinks — no per-frame hook on the transitions needed.
- `_positionOverlay()` centres from the overlay's **current allocation** (the actual
  visual size), falling back to `get_preferred_*` only when the allocation is not yet
  laid out (fresh show). Using the allocation (not preferred) means content changes on
  an already-visible card never jump it before a morph re-centres.
- `_updateOverlayParent()` re-parents `_overlay` between `screenShieldGroup` and
  `overlayGroup` on lock/unlock, and calls `_positionOverlay()`.

### 3.3 Size morph helper

A single interruptible helper animates every grow/shrink. It is invoked *after* the
content has been mutated in the same synchronous block (no relayout in between), so:

1. capture the column's **current allocation** (still stale → the pre-swap size),
2. the caller has already toggled the section visibility,
3. measure the **new natural** size from `get_preferred_width/height`,
4. pin the column to the captured size, clip to allocation,
5. `ease_property('width'|'height', nat, { duration: TRANSITION_MS,
   mode: EASE_IN_OUT_QUAD, onComplete: reset to -1, clip off, run onComplete })`.

```js
_morphOverlay(onComplete = null) {
    if (!this._overlay || !this._column) { if (onComplete) onComplete(); return; }
    const token = ++this._morphToken;               // new field, init in enable()
    const alloc = this._column.get_allocation_box();
    const curW = alloc.get_width();
    const curH = alloc.get_height();
    const [, natW] = this._column.get_preferred_width(-1);
    const [, natH] = this._column.get_preferred_height(-1);
    if (Math.abs(curW - natW) < 1 && Math.abs(curH - natH) < 1) {
        if (onComplete) onComplete();
        return;
    }
    this._column.set_width(curW);                   // pin — no jump after the swap
    this._column.set_height(curH);
    this._column.set_clip_to_allocation(true);
    this._column.ease_property('width', natW, { duration: TRANSITION_MS,
        mode: Clutter.AnimationMode.EASE_IN_OUT_QUAD });
    this._column.ease_property('height', natH, { duration: TRANSITION_MS,
        mode: Clutter.AnimationMode.EASE_IN_OUT_QUAD,
        onComplete: () => {
            if (token !== this._morphToken) return;
            this._column.set_width(-1);
            this._column.set_height(-1);
            this._column.set_clip_to_allocation(false);
            if (onComplete) onComplete();
        } });
}
```

- `_morphToken` cancels a running morph when a newer state arrives (mirrors
  `_animationToken`). `_cancelOverlayAnimation()` and `disable()` must also bump/clear
  it and remove the column's transitions.
- `-1` resets St.Widget explicit sizes back to natural.

### 3.4 State-driven changes

- **Entering `scanning`** (in `setState`): before `_showOverlay(...)`, call
  `_setMeterVisible(!this._enrolling)` and pre-zero the fills (they are already 0) so
  the tracks are present from the first frame; then `_morphOverlay()` only when the
  scan arrives over a live card (approval→scanning). The pop-in (`_popIn`) still
  animates entry; a fresh entry never morphs. The `_queueResult` fast-match flash does
  **not** show meters (it is a placeholder for the verdict that follows).
- **`_updateLiveness`**: never toggles meter visibility while scanning — when telemetry
  is absent it only returns early (leaves the last values). If *no* telemetry ever
  arrives (`enable_liveness = false`), the empty tracks collapse after a 500 ms grace
  period (`LIVENESS_GRACE_MS`) so the card isn't left with pointless bars. Update fills
  via the eased `_animateFill` below; update hint text as today.
- **`_setMeterVisible(visible)`**: toggles `_meter.visible` + `_hint.visible` and calls
  `_morphOverlay()`. No manual `_positionOverlay()` call.
- **`_presentResult`** / `_transitionToResult`: the verified card **keeps the
  scanning card's dimensions** — the meters/hint stay in the layout and fade out in
  place (opacity → 0), so there is no shrink. The label crossfades to the verdict
  ("✓ Verified (97%)") and the smiley fades to the result accent while gliding to the
  centre of the card (`translation-x` to `(boxW − faceW) / 2`). The meters are hidden
  only in the compact, no-scan path (immediate failures), which pops in the verdict
  without any transition. `_resetResultLayout()` undoes the leftovers (transparent
  meters, shifted smiley) on hide and on the next state entry.
- **`_showApproval`**: keeps the meter tracks **in the layout** (the approval card
  holds the scan card's width) but fades them out in place and glides the smiley to
  the centre — the same face position the verified card will use — then grows the
  card for the prompt (`_morphOverlay`). The approval → result transition is then
  barely a change: the smiley is already centred, the meters are already gone.
- **`_transitionToResult`** (approval result): fades the approval box out
  (`approvalBox` opacity → 0), hides it, then `_morphOverlay()` shrinks the card back
  to the scan height (width preserved by the meters still being in the layout). The
  label crossfades to the verdict and the smiley turns the result colour, matching a
  normal verify's verified card exactly.
- **`_clearApproval(hideBox = true)`**: stops the timer/state; the success/failure
  branches pass `false` so the box stays visible for the result transition to fade.
  The scanning/idle branches keep the default instant hide.
- **Enroll hints**: keep the debounce; when a hint first becomes visible call
  `_morphOverlay()` so the side column grows smoothly.
- **`_showOverlay`**: always shows a fully visible card first — it resets the
  overlay's `opacity` to 255 and `scale` to 1 and calls `_positionOverlay()` so an
  interrupted pop-in / mid-fade hide can never leave the card invisible or misplaced,
  then `_popIn` may animate the entrance on top. `_popIn` is **scale-only** (opacity
  stays 255), so the scan/approval cards are visible from the first frame even on very
  fast matches; `_resetResultLayout()` restores the overlay opacity/scale too.
- **`idle`/other**: unchanged — `_animateOverlayOut` fades/scales the whole card out.

### 3.5 Eased meter fills

```js
_animateFill(fill, targetWidth) {
    fill.remove_all_transitions();
    fill.ease_property('width', targetWidth, {
        duration: 200,
        mode: Clutter.AnimationMode.EASE_OUT_QUAD,
    });
}
```

`_updateLiveness` computes the target widths (existing `_barFraction` math) and calls
`_animateFill` for each fill instead of `set_width`. `remove_all_transitions()` makes it
retargetable when a new telemetry tick lands mid-tween.

### 3.6 CSS (`stylesheet.css`)

- `.hiro-status-box`: `spacing: 18px;` (keep), add horizontal centring of the block.
- `.hiro-status-side`: `spacing: 10px;` (gap between meters and hint).
- `.hiro-status-label`: centred (`text-align: center;`), add a little bottom padding.
- `.hiro-status-hint`: keep centred or left-align under the meters (pick one; centred is
  fine since the card is symmetric).
- `.hiro-status-stage`: transparent, `background: transparent;` (guard against any
  default St styling).
- No change to the card (`hiro-status-overlay`) look; the card now just wraps the new
  column size.

## 4. hiro-ui (GTK3 fallback) — implementation

File: `crates/hiro-ui/src/app.rs` (+ CSS string in the same file).

### 4.1 Layout

Same restructure as §3.1, in `build()`:

```
window
 └ card (vertical box, #hiro-card)
    ├ brand (#hiro-brand)
    ├ status_label  (#hiro-label)          ← moved above the content row, centred
    ├ content row (horizontal, centred)
    │  ├ face (DrawingArea 96×96)
    │  └ side (vertical box)
    │     ├ meter_box (2 progress rows)
    │     └ hint (#hiro-hint)
    └ approval_box
```

- `status_label` fills the card width (`set_halign(gtk::Align::Fill)` /
  `set_xalign(0.5)`) so the text block stays the same size between "Scanning your
  face…" and "✓ Verified (97%)".
- Widen the card: `set_size_request(400, -1)` → `(460, -1)` (min width; natural width
  grows with content).
- `meter_row` keeps its caption+track layout (existing helper).

### 4.2 Meters from the first frame

- `enter_scanning`: for `verify`, `meter_box.set_visible(true); hint.set_visible(true);`
  (fractions stay 0), then `animate_to_natural_size()`.
- `update_liveness`: when any telemetry value is `None`, return early *without* hiding
  (keep last values); only update fractions/classes/text when data is present. If *no*
  data ever arrives (`enable_liveness = false`), collapse the empty tracks after a
  500 ms grace period (`LIVENESS_GRACE_MS`) with a smooth shrink.

### 4.3 Animated window resize (grow/shrink, stays centred)

Add a `resize_timer: Option<glib::SourceId>` and helpers:

```rust
const RESIZE_MS: u64 = 200;
const RESIZE_STEP_MS: u64 = 16;

fn ease_out_quad(t: f64) -> f64 { t * (2.0 - t) }   // same shape as EASE_OUT_QUAD

fn animate_to_natural_size(&mut self) {
    self.cancel_resize_animation();
    let (_, natural) = self.card.preferred_size();
    let target_w = natural.width.max(460);
    let target_h = natural.height;
    let (cur_w, cur_h) = self.window.size();
    if (cur_w - target_w).abs() < 2 && (cur_h - target_h).abs() < 2 { return; }
    // Re-assert the current size so GTK's own resize-on-request-change cannot
    // snap the window to the target before the easing below takes over.
    self.window.resize(cur_w, cur_h);
    let start = Instant::now();
    let rc = self.rc();
    self.resize_timer = Some(glib::timeout_add_local(
        Duration::from_millis(RESIZE_STEP_MS), move || {
            let mut app = rc.borrow_mut();
            let t = (start.elapsed().as_secs_f64() / (RESIZE_MS as f64 / 1000.0)).min(1.0);
            let e = ease_out_quad(t);
            let w = (cur_w as f64 + (target_w - cur_w) as f64 * e).round() as i32;
            let h = (cur_h as f64 + (target_h - cur_h) as f64 * e).round() as i32;
            app.window.resize(w, h);                 // existing size_allocate hook re-centres
            if t >= 1.0 { app.resize_timer = None; return ControlFlow::Break; }
            ControlFlow::Continue
        }));
}

fn cancel_resize_animation(&mut self) {
    if let Some(id) = self.resize_timer.take() { id.remove(); }
}
```

- The existing `connect_size_allocate` handler already re-centres on the primary
  monitor, so each 16 ms step keeps the window centred → symmetric growth.
- Interruptible: any new content change cancels the running resize and starts fresh
  from the current size.
- Call `animate_to_natural_size()` from: `enter_scanning` (after meters shown),
  `update_liveness` (first data arrival — but meters are already shown, so usually a
  no-op), `present_result` (meters hidden → shrink), `show_approval` /
  `clear_approval` (approval box reveal/collapse), and label-text changes.
- `hide_window`/`show_window` fade already exists; leave it. Also call
  `cancel_resize_animation()` in `hide_window()` / `on_disconnected()`.

### 4.4 Eased bar fractions

`gtk::ProgressBar::set_fraction` snaps. Add a small retargetable tween per bar:

- `fill_timer_var` / `fill_timer_mot` fields (`Option<glib::SourceId>`).
- `animate_fraction(bar, target, timer_slot)`: cancel the running timer, snapshot
  `bar.get_fraction()`, run a 200 ms ease-out-quad timer calling `bar.set_fraction(eased)`,
  self-terminating; a new telemetry tick retargets from the current value.
- Simpler alternative (preferred if available in gtk-rs 0.18): a
  `glib::PropertyAnimation` on the `fraction` property with
  `glib::AnimationMode::EaseOutQuad` and `bar.animate_property()` — but the timer
  approach is guaranteed and matches the existing code style.

### 4.5 Result transition (keeps the card's width)

- The verified card keeps the scan card's size: the content row's width is frozen
  (`set_size_request(rowW, -1)`), the meters/hint fade out in place (`side` opacity →
  0), the label crossfades to the verdict, and the smiley glides to the centre by
  animating its `margin-start` from 0 to `(rowW − faceW) / 2` while the `face_state`
  swap (result colour) happens under the fade.
- `reset_result_layout()` (called from `cancel_crossfade`, which runs on hide, scan
  entry, and approval) unfreezes the row width, resets the face margin, and restores
  the side opacity.
- Compact verdicts (immediate failures, no scan) keep the old crossfade + smooth
  shrink to fit (`crossfade_result` + `animate_to_natural_size`).

### 4.6 CSS (`CSS` string in app.rs)

- `#hiro-card`: `padding: 18px 26px;` keep; card fills the window so growth is the
  card's own background growing.
- `#hiro-label`: `text-align: center;`.
- Add `#hiro-side { }` spacing via the box constructor (`set_spacing(8)`), no CSS needed.

## 5. Ordering / cancellation rules (both UIs)

1. Mutate content first, then morph/resize, in the same synchronous block — the morph
   must measure the *new* natural size while the allocation is still the *old* one.
2. Every morph/resize is token- or timer-cancellable; a newer state always wins.
3. `disable()` (extension) and `on_disconnected()`/`hide_window()` (hiro-ui) cancel all
   new timers/transitions and reset pinned sizes (`set_width(-1)` etc.).
4. Do not double-morph on chained state changes (e.g. `_clearApproval()` followed by a
   scan): only the final state handler morphs.

## 6. Files touched

| File | Change |
| --- | --- |
| `packaging/gnome-shell-extension/hiro-status@hiro/extension.js` | Layout restructure, `_stage`, `_morphOverlay`, meters-from-first-frame, eased fills, approval/enroll morphs, token hygiene |
| `packaging/gnome-shell-extension/hiro-status@hiro/stylesheet.css` | New layout classes, centred label, stage transparency |
| `crates/hiro-ui/src/app.rs` | Layout restructure, meters-from-first-frame, `animate_to_natural_size`, eased fractions, result crossfade, timer hygiene, CSS |

No daemon/protocol changes.

## 7. Tests & manual matrix

- **Unit (hiro-ui)**: `ease_out_quad` monotonic + endpoints; resize step math lands on
  target; existing `bar_fraction`/countdown tests unchanged.
- **Extension** has no harness; verify live.

| Scenario | Expected |
| --- | --- |
| Verify scan (telemetry present) | Card pops in with empty meter tracks beside the face; bars ease upward; card stays centred; no mid-scan jump |
| Verify scan, `enable_liveness = false` | Card shows face+label only (no meters), stable |
| Fast match (`MIN_SCAN_MS` gating) | Same as above, then the in-place result transition (no shrink) |
| Success / failure result | Card keeps its size; label crossfades to the verdict, bars fade out in place, smiley glides to centre and turns green; auto-hide fade unchanged |
| Immediate failures (camera, rate-limit) | Instant compact verdict, card appears fully formed (meters never shown) |
| Approval prompt | Card grows centred to include title/sub/buttons; countdown ticks; step-away hides buttons; Allow/Deny → shrink. Allow and Deny each span exactly half the card width across the bottom |
| Approval expiry / daemon re-broadcast | No double-morph jank; state clean |
| Enroll | No meters; progress in label; coaching hint grows the side column smoothly; result morphs |
| Lock / unlock (extension) | `_overlay` re-parents; card stays centred and visible above the shield |
| Idle / daemon disconnect | Card fades out (unchanged) |
| GNOME 45–52 (extension) | Manual `_positionOverlay()` centring on each shell; morphs re-centre per frame |
| X11 + Wayland/XWayland (hiro-ui) | Window resize steps smoothly under the compositor; centred throughout; no flicker on bare X11 beyond acceptable |

## 8. Risks / notes

- **Stage allocation across shell versions**: `overlayGroup` uses `Clutter.BinLayout`;
  confirm `x_expand/y_expand` children fill it on all supported shells (45–52). The
  per-frame `_positionOverlay` fallback (§3.2) exists if not.
- **hiro-ui resize on Wayland**: XWayland honours programmatic `gtk_window_resize` per
  frame; bare-X11 (no compositor) may flicker — acceptable, matches today's
  behaviour class. If flicker is a problem, gate the resize animation to composited
  sessions.
- **Reactivity during morphs**: the extension's approval buttons become clickable once
  the morph completes; the window's clipped content region during the 150 ms morph is
  non-interactive by construction. Acceptable.
- **Multi-monitor**: both UIs keep centring on the primary monitor (stage sized to it /
  existing size-allocate hook).
