# HIRO — Desktop-Agnostic Fallback UI (`hiro-ui`)

Status: DRAFT PLAN — authored for session ses_ff25aa129ffeW6Czvtane11nQq, 2026-08-16

## 1. Problem

Today the only graphical UI is the GNOME Shell extension
(`hiro-status@hiro`). It provides:

1. the **scanning indicator** (pulsing camera icon, centered overlay card,
   live liveness meters, enrollment progress + coaching hints),
2. the **in-session Allow/Deny approval prompt** for non-login requests
   (sudo, polkit, lock screen, ...) with a live countdown and
   step-away handling, and
3. the **result flash** (green check with score, or the failure reason).

Users on any other desktop (KDE, XFCE, MATE, Cinnamon, Budgie, i3, sway,
Hyprland, ...) get none of this. In the default config (`approval.enabled =
true`, `approval.secure_desktop = false`) the approval gate is on but
nothing renders the prompt, so every non-login face request silently times
out after its 5 s window and falls back to password. Safe, but invisible
and confusing. The only non-GNOME option today is the opt-in
`approval.secure_desktop` secure-console dialog (`hiro-approve`), which
switches to a dedicated VT.

Goal: a **desktop-agnostic fallback** that replicates the extension's
behaviour everywhere, with no per-desktop shell integration.

## 2. Locked-in decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| Renderer | GTK3 overlay window (frameless, always-on-top, top-center card) | GTK is effectively universal on Linux desktops (native on GNOME/XFCE/MATE/Cinnamon/Budgie, present on KDE for cross-toolkit apps); supports clickable buttons, real-time meters, instant appearance; works on X11 and Wayland (XWayland) |
| Scope | Full parity: scan indicator + liveness meters + approval prompt + results + enrollment feedback | Closes all three gaps; one implementation replaces the extension's behaviour for non-GNOME sessions |
| GNOME conflict | Auto-detect + config override | `hiro-ui` defers to the extension when running on GNOME with the extension enabled; `[ui] active = auto\|on\|off` override for manual control |
| IPC | Reuse the existing `Op::Watch` + `Op::Approve` protocol | Zero daemon/protocol changes; `hiro-ui` is "just one more consumer" of the watch stream, exactly as the README already advertises |
| Launch | systemd `--user` unit + XDG autostart fallback, single-instance guard | Covers distros with and without user service managers; flock prevents double rendering |
| Language | Rust (gtk-rs GTK3) | Consistent with the workspace; safe socket handling; reuses `hiro-core::proto` |

## 3. Architecture

```
 graphical session (user, DISPLAY / WAYLAND_DISPLAY / XDG_RUNTIME_DIR set)
   |
   |  systemd --user hiro-ui.service     (or XDG autostart hiro-ui.desktop)
   |  (single-instance flock guard)
   v
+----------------------+        Watch stream (Op::Watch, keep-alive)
|       hiro-ui        | <-------------------------------------+
|  GTK3 overlay card   |                                       |
|  scan + approval     |        Op::Approve (short-lived conn) |
|  + results           | ------------------------------------->|
+----------------------+        newline-delimited StateEvent    |
        ^                                                     v
        |                                                    +-----------+
        +----------------------------------------------------|   hirod   |
                         StateEvent broadcasts               +-----------+
                                                              (root daemon)
```

`hiro-ui` is a per-session, per-user process. It renders **only**
in-session states; the daemon remains the single source of truth and the
authority on approval (`Op::Approve` is authorized by SO_PEERCRED uid,
exactly as for the GNOME extension today).

No changes to `hirod`, `pam-hiro`, or the wire protocol.

## 4. New crate: `crates/hiro-ui`

```
crates/hiro-ui/
  Cargo.toml
  src/
    main.rs     # entry: parse args, single-instance guard, load config,
                #         GNOME detection, GTK init, run main loop
    app.rs      # window + card layout construction (CSS-styled GtkBox),
                #         positioning (top-center, ABOVE, skip-taskbar),
                #         show/hide + result transitions
    state.rs    # StateEvent -> UI state machine, reason mapping (port of
                #         the extension's _reasonLabel/_isImmediateFailure),
                #         approval countdown bookkeeping
    socket.rs   # watch-stream client (blocking reader thread, events
                #         marshalled into the GTK loop via glib::idle_add),
                #         reconnect with 3 s backoff, short-lived
                #         Op::Approve sender
    face.rs     # Cairo face drawing + sweep/breathe animation (port of
                #         the extension's _drawFace), driven by a
                #         frame-clock / timeout invalidation loop
    detect.rs   # desktop + extension detection (see §6)
```

Dependencies (workspace-consistent additions):

- `gtk = { version = "0.18", features = ["v3_24"] }` (gtk-rs, GTK3)
- `cairo-rs` (via gtk-rs re-export; used by `face.rs`)
- existing workspace deps: `hiro-core`, `serde_json`, `log`, `env_logger`

`hiro-ui` links dynamically against system `libgtk-3`; build requires
`libgtk-3-dev` (`pkg-config gtk+-3.0`), runtime requires `libgtk-3-0`
(deb `Depends`).

## 5. Behaviour spec

The UI mirrors the extension's `setState` handling, driven entirely by
`hiro_core::proto::StateEvent`:

| State event | UI behaviour |
| --- | --- |
| `scanning`, op=verify | Show card "Scanning your face…" (animated dots), animated Cairo face + sweep, pulsing accent. Liveness meters fed by `variance`/`motion` vs `min_variance`/`min_motion`; hint "Move your head slightly" / "Good — hold still" when both gates pass. |
| `scanning`, op=enroll | "Enrolling your face (n/target)" from `accepted`/`target`; debounced coaching hints from `reason` (port `_setEnrollHint`, `HINT_DEBOUNCE_MS = 900`). |
| `approval_pending` | Title "Approve this action?", subtitle `<service> wants to authenticate as <user> · Match NN% · Ns to decide`. **Allow / Deny** buttons. `secure: true` → passive notice "decide on the secure console", no buttons. `user_present: false` → hide buttons, "Step back in front of the camera to approve"; daemon rebroadcast with `true` re-shows them (same `approval_id` keeps the deadline). Expiry → "Decision window closed — request not approved". Sends `Op::Approve { approval_id, user, allow, secret: None }` on click. |
| `success` | Green result flash: "✓ Verified (NN%)" (or "✓ N face templates enrolled"), kept visible ≥ `MIN_SCAN_MS = 480` total, auto-hide after `RESULT_MS = 1600`. |
| `failure` | Red/amber result flash with mapped reason (port `_reasonLabel`). Immediate failures (rate-limited / locked-out / password-required) flash immediately without faking a scan. |
| `idle` / anything else | Hide window. |
| daemon unreachable / EOF | Hide window, log; reconnect attempt every 3 s (daemon replays `idle` on reconnect, which clears any stale prompt). |

Window properties:

- frameless (`decorated = false`), `_NET_WM_STATE_ABOVE`, skip-taskbar /
  skip-pager, type hint `dialog` so tiling WMs float it
- positioned top-center of the primary monitor (y ≈ 24 px), like the
  extension's overlay; pop-in / fade-out transitions via
  `gtk::glib::PropertyAnimation` or manual opacity easing
- CSS card: rounded corners, dark background, accent-colored states
  (port `stylesheet.css`'s look as closely as GTK allows)

## 6. GNOME detection and conflict avoidance

New `[ui]` section in `hiro-core::config`:

```toml
[ui]
# auto | on | off   (default: auto)
active = "auto"
```

- `off` — `hiro-ui` exits immediately (user wants no UI / relies on the
  extension or secure console).
- `on` — render everything, ignoring detection (force). Also disables the
  `hiro-status@hiro` extension at startup (best-effort) so it cannot
  double-render the same overlay; a session-scoped marker lets a later
  `auto`/`off` run re-enable the extension and hand control back.
- `auto` (default) — at startup:
  1. Read `XDG_CURRENT_DESKTOP` / `DESKTOP_SESSION`. If it does **not**
     contain `GNOME` → active.
  2. On GNOME, probe the extension: `gnome-extensions info hiro-status@hiro`.
     If the extension is **enabled** → defer: `hiro-ui` exits 0 with a log
     line (extension owns the UI). If not installed / disabled / errored →
     active.

If `hiro-ui` exits in defer mode, re-login or
`systemctl --user restart hiro-ui` (after disabling the extension) picks it
up; documented. Config load: `/etc/hiro/config.toml` via
`hiro_core::config::Config::from_toml` (already world-readable — `hiro
doctor` reads it today).

## 7. Lifecycle and packaging

- **systemd user unit** `packaging/systemd-user/hiro-ui.service`:

  ```
  [Unit]
  Description=HIRO face-auth status UI (desktop-agnostic)
  PartOf=graphical-session.target
  After=graphical-session.target

  [Service]
  ExecStart=/usr/bin/hiro-ui
  Restart=on-failure
  RestartSec=3
  ```

  Installed to `/usr/lib/systemd/user/` (deb).
- **XDG autostart** `packaging/xdg-autostart/hiro-ui.desktop` installed to
  `/etc/xdg/autostart/` for distros/sessions without a systemd user
  manager. Both are installed; a **single-instance flock guard** on
  `$XDG_RUNTIME_DIR/hiro-ui.lock` (second instance exits 0) makes double
  launch harmless.
- **`build-deb.sh`**: install `target/release/hiro-ui`, the unit, the
  autostart entry; add `libgtk-3-0` to deb `Depends`; add `libgtk-3-dev`
  to debian Build-Depends.
- **`hiro doctor`**: new section reporting config `[ui].active`,
  detected desktop, extension present/enabled, and hiro-ui defer-vs-active
  outcome. `hiro status` gains a `ui:` line (from config, no daemon
  change).
- **Docs**: README "On-screen scanning indicator" section + `docs/pam.md`
  note the fallback; man page for `hiro-ui` (or extend `hiro.conf.5` with
  the `[ui]` section).

## 8. Security considerations

- `hiro-ui` runs **unprivileged** as the logged-in user; it never touches
  the camera, templates, or keys. All authority stays in `hirod`.
- Approval decisions use the identical in-session path as the extension
  today: `Op::Approve` with `secret: None`, authorized by SO_PEERCRED uid
  == target user (or root). No new trust surface.
- Rendering input is sanitized the way `hiro-approve` sanitizes its VT
  output: service/user strings and reasons are **not** trusted to carry
  markup — use `gtk::Label` (no Pango markup) or escape explicitly, so a
  crafted PAM service name can never inject styled/clickable content into
  the card.
- Deferral is a UX choice, not a security boundary: if detection is wrong
  and both UIs render, the daemon still enforces the approval exactly
  once; a duplicate prompt only *looks* duplicated.
- No images/telemetry leave the machine; `hiro-ui` has no network code.

## 9. Known limitations

- **Lock screens / greeters**: an in-session overlay cannot render above a
  locked screen or the login greeter (Wayland especially). The GNOME
  extension covers the GNOME lock screen via shell integration; on other
  desktops, a lock screen whose PAM service requires approval falls back
  to password (fail-closed). Greeter services are in
  `approval.bypass_services` by default, so login itself is unaffected.
- **Tiling WMs / fullscreen**: the card is a normal floating top-level
  (not a layer-shell surface), so on sway/Hyprland it may be occluded by
  fullscreen apps and does not integrate with bar positioning. Good enough
  for the approval prompt (which steals focus); a wlr-layer-shell renderer
  is a future stretch.
- **Timing**: approval windows are ~5 s; notification-based UIs were
  rejected for this reason (see §11).

## 10. Milestones

- **M1 — Crate + window skeleton**: workspace member, GTK3 app with the
  frameless top-center always-on-top card, single-instance guard,
  config load, `--version`. (Requires `libgtk-3-dev`; documented in the
  README dev section.)
- **M2 — Watch client**: `socket.rs` — connect, watch request, blocking
  reader thread marshalling `StateEvent`s into the GTK loop, 3 s
  reconnect, hide-on-disconnect.
- **M3 — Scanning indicator**: Cairo face + sweep/breathe animation,
  pulsing accent, "Scanning…" dots, liveness meters + hints, enrollment
  progress + debounced coaching.
- **M4 — Approval prompt**: full `approval_pending` handling (buttons,
  countdown, `secure` notice, `user_present` hide/re-show, expiry),
  `Op::Approve` sender, "Allowing… / Denying…" feedback.
- **M5 — Results**: success/failure flash, `MIN_SCAN_MS` gating,
  `RESULT_MS` auto-hide, ported reason mapping.
- **M6 — Detection + config**: `[ui]` section (validation + tests),
  `detect.rs` (XDG desktop probe + `gnome-extensions info`), defer/force
  modes.
- **M7 — Packaging + lifecycle**: systemd user unit, XDG autostart,
  build-deb.sh wiring, `hiro doctor` / `hiro status` UI reporting, docs +
  man page.
- **M8 — Tests + manual matrix**: unit tests (state transitions, reason
  mapping, countdown math, config validation, detection parsing);
  manual pass on GNOME (with and without extension), KDE, XFCE, i3,
  sway/Hyprland, bare X11.

## 11. Rejected / deferred

- **Notifications (libnotify/DBus)** — no reliable interactive buttons
  across DEs; too slow for a 5 s approval window; no live meters.
  Rejected.
- **wlr-layer-shell overlay** — wlroots-only; not universal. Deferred as a
  future renderer backend.
- **Reusing `hiro-approve` in-session** — conflates the secure-console
  design (VT switch, root-owned secret) with an in-session widget.
  Rejected.
- **Daemon-side renderer exclusivity** (new protocol op to claim the
  approval renderer) — protocol/daemon surgery with no real benefit over
  detection. Double-rendering on GNOME is instead resolved client-side:
  `[ui] active = "on"` disables the extension from `hiro-ui` (§6).
