/* HIRO Face Auth Status - animated indicator for face scanning. */
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Clutter from 'gi://Clutter';
import Cairo from 'gi://cairo';
import Gdk from 'gi://Gdk';
import GdkPixbuf from 'gi://GdkPixbuf';
import St from 'gi://St';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

const SOCKET = '/run/hirod/hirod.sock';
const RESULT_MS = 1600;
const MIN_SCAN_MS = 480;
const TRANSITION_MS = 150;
const POP_IN_MS = 220;
const POP_SETTLE_MS = 120;
const HIDE_MS = 220;
const METER_WIDTH = 190;
const FACE_SCAN_MS = 1200;
// Accent color per status; used by the Cairo-drawn face.
const FACE_ACCENT = {
    idle: '#c9d1d9',
    scanning: '#ffd166',
    enrolling: '#4fc3f7',
    success: '#66bb6a',
    fail: '#e57373',
    warn: '#ffb74d',
    approval: '#ba68c8',
};
// Minimum interval between enrollment-coaching hint text changes. The
// daemon streams a rejection event per frame and the reason can bounce
// between "blurry", "duplicate pose", etc.; without this the hint flickers.
const HINT_DEBOUNCE_MS = 900;

export default class HiroStatusExtension extends Extension {
    enable() {
        this._enabled = true;
        this._state = 'idle';
        this._op = 'verify';
        this._enrolling = false;
        this._accepted = null;
        this._target = null;
        this._dots = 0;
        this._retry = null;
        this._dotTimer = null;
        this._resultTimer = null;
        this._hideTimer = null;
        this._pendingResult = null;
        this._scanStartedAt = 0;
        this._animationToken = 0;
        this._pulseToken = 0;
        this._faceAnimationToken = 0;
        this._faceState = null;
        this._faceTimeline = null;
        this._faceTimelineId = 0;
        this._logo = null;
        this._loadLogo();
        this._hintText = null;
        this._hintAt = 0;
        this._lockChangedId = 0;
        this._connection = null;
        this._readLoop = null;
        this._approval = null;
        this._approvalTimer = null;

        // Top-bar indicator button. Hidden until a scan starts so the
        // camera icon does not make it look like the camera is in use at
        // all times; it appears only while scanning (and the result flash).
        this._indicator = new PanelMenu.Button(0.0, 'HIRO face auth', true);
        this._icon = new St.Icon({
            icon_name: 'camera-photo-symbolic',
            style_class: 'system-status-icon',
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._indicator.add_child(this._icon);
        this._indicator.visible = false;
        this._setConnected(false);
        Main.panel.addToStatusArea('hiro-status', this._indicator, 1, 'right');

        // Centered overlay with the animated "scanning" message. Lives in
        // the overlay layer when available so it also renders above the
        // screen shield; falls back to the main UI group otherwise.
        this._overlay = new St.Bin({
            style_class: 'hiro-status-overlay',
            reactive: false,
            visible: false,
            x_expand: false,
            y_expand: false,
            x_align: Clutter.ActorAlign.CENTER,
            y_align: Clutter.ActorAlign.START,
        });
        this._overlay.set_translation(0, 0, 0);
        this._overlay.set_pivot_point(0.5, 0.5);
        this._column = new St.BoxLayout({style_class: 'hiro-status-column', vertical: true});

        this._brandRow = new St.BoxLayout({style_class: 'hiro-brand-row', vertical: false});
        this._brandRow.x_align = Clutter.ActorAlign.CENTER;
        this._brandRow.add_child(new St.Widget({
            style_class: 'hiro-brand-mark',
            width: 5,
            height: 5,
        }));
        this._brandRow.add_child(new St.Label({
            text: 'HIRO',
            style_class: 'hiro-brand',
        }));
        this._column.add_child(this._brandRow);

        this._box = new St.BoxLayout({style_class: 'hiro-status-box', vertical: false});
        this._face = this._makeFace();
        this._setFaceState('idle');
        this._label = new St.Label({
            text: 'Scanning your face',
            style_class: 'hiro-status-label',
        });
        this._box.add_child(this._face);
        this._box.add_child(this._label);
        this._column.add_child(this._box);

        // Live liveness progress meter: one bar per anti-spoof signal
        // (temporal frame variance and landmark micro-motion), fed by the
        // daemon's scanning telemetry, plus an actionable hint.
        this._varianceFill = new St.Widget({
            style_class: 'hiro-meter-fill hiro-meter-fill-var',
            height: 8,
            width: 0,
            x_align: Clutter.ActorAlign.START,
        });
        this._motionFill = new St.Widget({
            style_class: 'hiro-meter-fill hiro-meter-fill-mot',
            height: 8,
            width: 0,
            x_align: Clutter.ActorAlign.START,
        });
        this._meter = new St.BoxLayout({style_class: 'hiro-status-meter', vertical: true});
        this._meter.add_child(this._makeMeterRow('Scene motion', this._varianceFill));
        this._meter.add_child(this._makeMeterRow('Head motion', this._motionFill));
        this._meter.visible = false;
        this._column.add_child(this._meter);

        this._hint = new St.Label({
            text: 'Move your head slightly',
            style_class: 'hiro-status-hint',
            visible: false,
        });
        this._column.add_child(this._hint);

        // Approval prompt: shown after a confident match when the requesting
        // service (sudo, lock, polkit, ...) needs an explicit Allow/Deny
        // before the action runs. Hidden by default; appears when the
        // daemon broadcasts `state: "approval_pending"`.
        this._approvalBox = new St.BoxLayout({
            style_class: 'hiro-approval',
            vertical: true,
            visible: false,
        });
        this._approvalTitle = new St.Label({
            text: '',
            style_class: 'hiro-approval-title',
        });
        this._approvalSub = new St.Label({
            text: '',
            style_class: 'hiro-approval-sub',
        });
        this._approvalButtons = new St.BoxLayout({
            style_class: 'hiro-approval-buttons',
            vertical: false,
            visible: false,
        });
        this._allowBtn = new St.Button({
            label: 'Allow',
            style_class: 'hiro-approval-btn hiro-approval-allow',
        });
        this._denyBtn = new St.Button({
            label: 'Deny',
            style_class: 'hiro-approval-btn hiro-approval-deny',
        });
        this._allowBtn.connect('clicked', () => this._decideApproval(true));
        this._denyBtn.connect('clicked', () => this._decideApproval(false));
        this._approvalButtons.add_child(this._allowBtn);
        this._approvalButtons.add_child(this._denyBtn);
        this._approvalBox.add_child(this._approvalTitle);
        this._approvalBox.add_child(this._approvalSub);
        this._approvalBox.add_child(this._approvalButtons);
        this._column.add_child(this._approvalBox);

        this._overlay.set_child(this._column);
        // The lock screen (screen shield) covers the normal overlay layer,
        // so while locked the indicator must live inside the shield group to
        // stay visible. Move it between parents as the lock state changes.
        this._updateOverlayParent = () => {
            if (!this._overlay) return;
            const locked = Main.screenShield?.locked ?? false;
            const target = locked
                ? (Main.layoutManager.screenShieldGroup ?? Main.layoutManager.overlayGroup)
                : (Main.layoutManager.overlayGroup ?? Main.uiGroup);
            if (!target || this._overlay.get_parent() === target) return;
            target.add_child(this._overlay);
            this._positionOverlay();
        };
        this._updateOverlayParent();
        this._lockChangedId =
            Main.screenShield?.connect?.('locked-changed', this._updateOverlayParent) ?? 0;

        this._connect();
        this._retry = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 3, () => {
            if (!this._connected) this._connect();
            return true;
        });
    }

    disable() {
        this._enabled = false;
        if (this._lockChangedId) {
            Main.screenShield?.disconnect?.(this._lockChangedId);
            this._lockChangedId = 0;
        }
        this._stopAnimations();
        this._cancelOverlayAnimation();
        this._stopApprovalTimer();
        if (this._dotTimer) GLib.source_remove(this._dotTimer);
        if (this._retry) GLib.source_remove(this._retry);
        this._dotTimer = null;
        this._retry = null;
        this._cancelResultTimer();
        this._cancelHideTimer();
        if (this._connection) this._connection.close(null);
        this._connection = null;
        this._connected = false;
        if (this._approvalBox) this._approvalBox.destroy();
        this._approvalBox = null;
        if (this._overlay) this._overlay.destroy();
        if (this._indicator) this._indicator.destroy();
        this._overlay = null;
        this._indicator = null;
        this._icon = null;
        this._face = null;
        this._logo = null;
    }

    // The full HIRO logo (Logo/HIRO.svg's raster export, shipped next to the
    // extension). Loaded once and pre-scaled to ~240 px tall so per-frame
    // drawing stays cheap; if it is missing or undecodable the drawing falls
    // back to the legacy hand-drawn smiley so the indicator still works.
    _loadLogo() {
        try {
            const file = this.dir.get_child('hiro-logo.png');
            if (!file || !file.query_exists(null)) return;
            const full = GdkPixbuf.Pixbuf.new_from_file(file.get_path());
            const h = full.get_height();
            if (h > 240) {
                const w = Math.round(full.get_width() * 240 / h);
                this._logo = full.scale_simple(w, 240, GdkPixbuf.InterpType.BILINEAR);
            } else {
                this._logo = full;
            }
        } catch (e) {
            log(`hiro-status: load logo: ${e?.message}`);
        }
    }

    _makeFace() {
        // A Cairo-drawn actor: the whole HIRO logo (glyph, scan brackets and
        // sweep) is repainted on every animation frame, so the motion does
        // not depend on child-actor transforms that may not repaint reliably
        // across shell versions.
        const face = new St.DrawingArea({
            style_class: 'hiro-face',
            width: 96,
            height: 96,
            reactive: false,
        });
        face.set_pivot_point(0.5, 0.5);
        face.connect('repaint', () => {
            const [surfaceW] = face.get_surface_size();
            this._drawFace(face, surfaceW / 64);
        });
        this._sweep = 0;
        this._breathe = 1;
        return face;
    }

    _setFaceState(state) {
        if (!this._face) return;
        this._faceState = state;
        this._face.style_class = 'hiro-face';
        this._face.queue_repaint();
    }

    _startFaceScan(state = 'scanning') {
        this._stopFaceScan();
        this._setFaceState(state);
        const token = ++this._faceAnimationToken;
        const face = this._face;
        if (!face) return;

        // Frame-driven sweep: a repeating timeline advances the sweep and
        // breathing values and repaints the face on every clock tick.
        const timeline = new Clutter.Timeline({
            duration: FACE_SCAN_MS,
            repeat_count: -1,
            actor: face,
        });
        this._faceTimeline = timeline;
        this._faceTimelineId = timeline.connect('new-frame', () => {
            if (token !== this._faceAnimationToken ||
                (this._faceState !== 'scanning' && this._faceState !== 'enrolling') ||
                !this._enabled) {
                timeline.stop();
                return;
            }
            const p = timeline.get_progress();
            this._sweep = Math.sin(p * Math.PI);
            this._breathe = 1 + 0.04 * Math.sin(p * Math.PI * 2);
            face.queue_repaint();
        });
        timeline.start();
    }

    _stopFaceScan() {
        this._faceAnimationToken++;
        if (this._faceTimeline) {
            this._faceTimeline.stop();
            if (this._faceTimelineId)
                this._faceTimeline.disconnect(this._faceTimelineId);
            this._faceTimeline = null;
            this._faceTimelineId = 0;
        }
        this._sweep = 0;
        this._breathe = 1;
        if (this._face) {
            this._face.set_scale(1, 1);
            this._face.queue_repaint();
        }
    }

    _drawFace(face, scale) {
        const cr = face.get_context();
        const state = this._faceState || 'idle';
        const scanning = state === 'scanning' || state === 'enrolling';
        const accent = FACE_ACCENT[state] || FACE_ACCENT.idle;
        const cx = 32 * scale;
        const cy = 32 * scale;

        cr.save();
        if (this._breathe !== 1) {
            cr.translate(cx, cy);
            cr.scale(this._breathe, this._breathe);
            cr.translate(-cx, -cy);
        }

        let frame;
        if (this._logo) {
            // The logo is portrait (smiley over the HIRO wordmark), so fit it
            // to the 60-tall scan zone (2..62 of the 64-grid), centred.
            const pb = this._logo;
            const aspect = pb.get_width() / pb.get_height();
            const th = 60 * scale;
            const tw = th * aspect;
            const dx = cx - tw / 2;
            const dy = cy - th / 2;

            // Only the logo's own strokes are drawn — the background stays
            // transparent so the overlay colour shows through.
            cr.save();
            cr.translate(dx, dy);
            cr.scale(tw / pb.get_width(), th / pb.get_height());
            Gdk.cairo_set_source_pixbuf(cr, pb, 0, 0);
            cr.paint();
            cr.restore();

            // The logo stroke is a neutral slate, so recolour it with the
            // status accent (keeps its alpha via the IN operator).
            cr.save();
            cr.setOperator(Cairo.Operator.IN);
            const [r, g, b, a] = this._hexToRgba(accent, 1);
            cr.setSourceRGBA(r, g, b, a);
            cr.rectangle(dx, dy, tw, th);
            cr.fill();
            cr.restore();

            frame = {
                fx: dx - 1.5 * scale,
                fy: dy - 1.5 * scale,
                fw: tw + 3 * scale,
                fh: th + 3 * scale,
                sweepX: dx + 2 * scale,
                sweepW: tw - 4 * scale,
                sweepA: dy + 2 * scale,
                sweepB: dy + th - 2 * scale,
            };
        } else {
            // Fallback: the legacy hand-drawn smiley glyph.
            this._drawLegacyFace(cr, scale, cx, cy, state, accent);
            frame = {
                fx: 6 * scale,
                fy: 6 * scale,
                fw: 52 * scale,
                fh: 52 * scale,
                sweepX: 13 * scale,
                sweepW: 38 * scale,
                sweepA: 23 * scale,
                sweepB: 41 * scale,
            };
        }

        // Scan brackets and the sweeping line while scanning.
        if (scanning) {
            const arm = 8 * scale;
            cr.setLineWidth(2 * scale);
            this._setRgba(cr, accent, 1);
            cr.newSubPath();
            cr.moveTo(frame.fx, frame.fy + arm);
            cr.lineTo(frame.fx, frame.fy);
            cr.lineTo(frame.fx + arm, frame.fy);
            cr.moveTo(frame.fx + frame.fw - arm, frame.fy);
            cr.lineTo(frame.fx + frame.fw, frame.fy);
            cr.lineTo(frame.fx + frame.fw, frame.fy + arm);
            cr.moveTo(frame.fx, frame.fy + frame.fh - arm);
            cr.lineTo(frame.fx, frame.fy + frame.fh);
            cr.lineTo(frame.fx + arm, frame.fy + frame.fh);
            cr.moveTo(frame.fx + frame.fw - arm, frame.fy + frame.fh);
            cr.lineTo(frame.fx + frame.fw, frame.fy + frame.fh);
            cr.lineTo(frame.fx + frame.fw, frame.fy + frame.fh - arm);
            cr.stroke();

            const sweepY = frame.sweepA + this._sweep * (frame.sweepB - frame.sweepA);
            this._setRgba(cr, accent, 0.16);
            this._roundRect(cr, frame.sweepX, sweepY - 5 * scale, frame.sweepW, 10 * scale, 5 * scale);
            cr.fill();
            this._setRgba(cr, accent, 1);
            this._roundRect(cr, frame.sweepX, sweepY - 1 * scale, frame.sweepW, 2.5 * scale, 1.5 * scale);
            cr.fill();
        }

        cr.restore();
        cr.$dispose();
    }

    // The pre-logo hand-drawn glyph, used only when the shipped smiley PNG
    // cannot be loaded so the indicator never goes blank.
    _drawLegacyFace(cr, scale, cx, cy, state, accent) {
        // Ring and face plate.
        this._setRgba(cr, accent, 0.92);
        cr.setLineWidth(1.6 * scale);
        cr.setLineCap(Cairo.LineCap.ROUND);
        cr.arc(cx, cy, 25 * scale, 0, 2 * Math.PI);
        cr.stroke();

        this._setRgba(cr, accent, 0.08);
        cr.arc(cx, cy, 21.5 * scale, 0, 2 * Math.PI);
        cr.fill();

        // Eyes.
        this._setRgba(cr, accent, 1);
        this._roundRect(cr, 20.5 * scale, 23 * scale, 7 * scale, 9 * scale, 3 * scale);
        cr.fill();
        this._roundRect(cr, 36.5 * scale, 23 * scale, 7 * scale, 9 * scale, 3 * scale);
        cr.fill();

        // Mouth: smile, or frown for failure/warning states.
        cr.setLineWidth(2 * scale);
        if (state === 'fail' || state === 'warn') {
            cr.arc(cx, 41 * scale, 8 * scale, Math.PI * 1.15, Math.PI * 1.85);
        } else {
            cr.arc(cx, 37.5 * scale, 9 * scale, Math.PI * 0.15, Math.PI * 0.85);
        }
        cr.stroke();
    }

    _setRgba(cr, hex, alpha) {
        const [r, g, b, a] = this._hexToRgba(hex, alpha);
        cr.setSourceRGBA(r, g, b, a);
    }

    _hexToRgba(hex, alpha) {
        const h = String(hex || '#ffffff').replace('#', '');
        return [
            parseInt(h.substring(0, 2), 16) / 255,
            parseInt(h.substring(2, 4), 16) / 255,
            parseInt(h.substring(4, 6), 16) / 255,
            alpha,
        ];
    }

    _roundRect(cr, x, y, w, h, r) {
        const rad = Math.min(r, w / 2, h / 2);
        cr.newSubPath();
        cr.arc(x + rad, y + rad, rad, Math.PI, 1.5 * Math.PI);
        cr.arc(x + w - rad, y + rad, rad, 1.5 * Math.PI, 0);
        cr.arc(x + w - rad, y + h - rad, rad, 0, 0.5 * Math.PI);
        cr.arc(x + rad, y + h - rad, rad, 0.5 * Math.PI, Math.PI);
        cr.closePath();
    }

    _makeMeterRow(caption, fill) {
        const cap = new St.Label({text: caption, style_class: 'hiro-meter-caption'});
        cap.set_width(110);
        const track = new St.Bin({
            style_class: 'hiro-meter-track',
            width: METER_WIDTH,
            height: 8,
        });
        track.set_child(fill);
        const row = new St.BoxLayout({style_class: 'hiro-meter-row', vertical: false});
        row.add_child(cap);
        row.add_child(track);
        return row;
    }

    _setConnected(connected) {
        this._connected = connected;
        if (!this._icon) return;
        this._icon.icon_name = connected ? 'face-recognition-symbolic' : 'camera-photo-symbolic';
        this._icon.tooltip_text = connected ? 'HIRO connected' : 'HIRO: daemon not reachable';
    }

    // The top-bar icon only appears while a scan or its result is on
    // screen, so it does not look like the camera is in use at all times.
    _showIndicator() {
        if (this._indicator) this._indicator.visible = true;
    }

    _hideIndicator() {
        if (this._indicator) this._indicator.visible = false;
    }

    _connect() {
        if (!this._enabled || this._connected) return;
        try {
            // Keep the client referenced too; GJS finalizers can otherwise
            // tear down the socket it produced.
            this._client = new Gio.SocketClient({timeout: 2});
            const addr = Gio.UnixSocketAddress.new(SOCKET);
            this._connection = this._client.connect(addr, null);
            // The SocketClient timeout applies to I/O as well as connect.
            // The daemon broadcasts state events only when something
            // changes, so any quiet stretch longer than that timeout kills
            // the watch stream's read; the reconnect then gets the
            // daemon's "idle" replay, which clears a live approval dialog.
            // Disable the timeout on the connected socket so the long-lived
            // watch stream blocks until the next state event.
            this._connection.get_socket().set_timeout(0);
        } catch (e) {
            console.log(`hiro-status: connect error: ${e?.message}`);
            this._setConnected(false);
            return;
        }
        this._setConnected(true);
        if (!this._enabled || !this._icon) return;
        this._icon.style_class = 'system-status-icon';
        try {
            // Keep a reference to the output stream: if it gets garbage
            // collected, finalizing it closes the socket connection.
            this._out = new Gio.DataOutputStream({
                base_stream: this._connection.get_output_stream(),
            });
            this._out.put_string('{"v":1,"id":0,"op":"watch"}\n', null);
        } catch (e) {
            console.log(`hiro-status: write error: ${e?.message}`);
            this._setConnected(false);
            return;
        }
        this._input = new Gio.DataInputStream({
            base_stream: this._connection.get_input_stream(),
        });
        const readAsync = () => {
            if (!this._connection) return;
            try {
                this._input.read_line_async(GLib.PRIORITY_DEFAULT, null, (src, res) => {
                    try {
                        // read_line_finish varies by GJS/GLib: a string, a
                        // Uint8Array, or a [bytes, length] tuple.
                        let result = src.read_line_finish(res);
                        if (Array.isArray(result)) {
                            result = result[0];
                        }
                        if (result === null) {
                            console.log('hiro-status: eof (daemon closed connection)');
                            this._setConnected(false);
                            return;
                        }
                        let text;
                        if (typeof result === 'string') {
                            text = result;
                        } else if (result instanceof Uint8Array) {
                            text = new TextDecoder().decode(result);
                        } else {
                            console.log(`hiro-status: unexpected line type: ${typeof result}`);
                            text = String(result);
                        }
                        try {
                            const ev = JSON.parse(text);
                            if (ev.state)
                                this.setState(
                                    ev.state, ev.score, ev.reason,
                                    ev.variance, ev.motion,
                                    ev.min_variance, ev.min_motion,
                                    ev.op, ev.accepted, ev.target, ev.rejected,
                                    ev.user, ev.service, ev.approval_id,
                                    ev.approval_timeout_ms, ev.secure,
                                    ev.user_present);
                        } catch (e) {
                            console.log(`hiro-status: parse error: ${e?.message}`);
                        }
                        readAsync();
                    } catch (e) {
                        console.log(`hiro-status: read error: ${e?.message}`);
                        this._setConnected(false);
                    }
                });
            } catch (e) {
                console.log(`hiro-status: async error: ${e?.message}`);
                this._setConnected(false);
            }
        };
        readAsync();
    }

    setState(state, score, reason, variance, motion, minVariance, minMotion,
             op, accepted, target, rejected, user, service, approvalId,
             approvalTimeoutMs, secure, userPresent) {
        if (!this._enabled || !this._overlay || !this._icon) return;
        this._op = op === 'enroll' ? 'enroll' : 'verify';
        this._enrolling = this._op === 'enroll';
        console.log(`hiro-status: state=${state} op=${this._op} score=${score} reason=${reason} ` +
            `accepted=${accepted} target=${target} rejected=${rejected}`);
        if (state === 'approval_pending') {
            this._showApproval(score, user, service, approvalId, approvalTimeoutMs,
                secure, userPresent);
        } else if (state === 'scanning') {
            this._clearApproval();
            this._showIndicator();
            this._cancelResultTimer();
            this._pendingResult = null;
            const enteringScanning = this._state !== 'scanning' || !this._overlay.visible;
            if (enteringScanning) {
                this._state = 'scanning';
                this._scanStartedAt = GLib.get_monotonic_time();
                this._cancelOverlayAnimation();
            }
            this._cancelHideTimer();
            this._icon.style_class = this._enrolling
                ? 'system-status-icon hiro-enrolling'
                : 'system-status-icon hiro-scanning';
            this._startPulse();
            this._startDots();
            this._showOverlay(
                this._enrolling ? 'Enrolling your face' : 'Scanning your face',
                this._enrolling ? 'contact-new-symbolic' : 'camera-photo-symbolic',
                this._enrolling ? 'hiro-enrolling' : 'hiro-scanning',
                enteringScanning);
            if (this._enrolling) {
                // Enrollment has no liveness bars; show template progress
                // instead (live "n/target" count from the daemon) plus a
                // live hint whenever a frame is rejected for a fixable
                // reason (too close/far, blurry, duplicate pose, ...).
                this._setMeterVisible(false);
                this._setEnrollProgress(accepted, target);
                this._setEnrollHint(reason);
            } else {
                this._updateLiveness(variance, motion, minVariance, minMotion);
            }
        } else if (state === 'success') {
            this._clearApproval();
            this._queueResult(state, score, reason, accepted, target, rejected);
        } else if (state === 'failure') {
            this._clearApproval();
            this._queueResult(state, score, reason, accepted, target, rejected);
        } else {
            this._clearApproval();
            this._cancelResultTimer();
            this._pendingResult = null;
            this._cancelHideTimer();
            this._state = state;
            this._enrolling = false;
            this._accepted = null;
            this._target = null;
            this._stopAnimations();
            this._cancelOverlayAnimation();
            this._setMeterVisible(false);
            this._animateOverlayOut(() => {
                if (this._state === state) {
                    this._icon.style_class = 'system-status-icon';
                    this._hideIndicator();
                }
            });
        }
    }

    _updateLiveness(variance, motion, minVariance, minMotion) {
        if (!this._meter || !this._hint) return;
        if (minVariance == null || minMotion == null ||
            variance == null || motion == null) {
            this._setMeterVisible(false);
            return;
        }
        this._setMeterVisible(true);
        const vOk = variance >= minVariance;
        const mOk = motion >= minMotion;
        this._varianceFill.set_width(Math.round(this._barFraction(variance, minVariance) * METER_WIDTH));
        this._motionFill.set_width(Math.round(this._barFraction(motion, minMotion) * METER_WIDTH));
        this._varianceFill.style_class =
            `hiro-meter-fill ${vOk ? 'hiro-meter-fill-ok' : 'hiro-meter-fill-var'}`;
        this._motionFill.style_class =
            `hiro-meter-fill ${mOk ? 'hiro-meter-fill-ok' : 'hiro-meter-fill-mot'}`;
        this._hint.text = vOk && mOk
            ? 'Good — hold still'
            : 'Move your head slightly';
    }

    _setEnrollProgress(accepted, target) {
        if (accepted != null) this._accepted = accepted;
        if (target != null) this._target = target;
        this._updateScanLabel();
    }

    // Live coaching during enrollment: when the daemon rejects a frame it
    // sends a reason code ("face_too_small", "blurry", "duplicate_pose",
    // ...); surface the human-readable version so the user knows what to
    // change. Text updates are debounced (HINT_DEBOUNCE_MS) so the hint
    // reads stably instead of flickering through a new reason every frame,
    // and it is left visible once shown: the accepted/target counter is the
    // progress signal, the hint is the (stable) guidance.
    _setEnrollHint(reason) {
        if (!this._hint) return;
        const hint = reason ? this._reasonLabel(reason) : null;
        if (hint) {
            const now = GLib.get_monotonic_time() / 1000;
            if (hint !== this._hintText &&
                (!this._hint.visible || now - this._hintAt >= HINT_DEBOUNCE_MS)) {
                this._hint.text = hint;
                this._hintText = hint;
                this._hintAt = now;
            }
            this._hint.visible = true;
        }
        // reason === null means a frame was accepted: leave the hint as-is
        // rather than hiding/re-showing it, so it doesn't blink between
        // accepted and rejected frames.
    }

    _updateScanLabel() {
        if (!this._label) return;
        if (this._enrolling) {
            const progress = (this._accepted != null && this._target != null)
                ? ` (${this._accepted}/${this._target})`
                : '';
            this._label.text = 'Enrolling your face' + progress + '.'.repeat(this._dots);
        } else {
            this._label.text = 'Scanning your face' + '.'.repeat(this._dots);
        }
    }

    _barFraction(value, max) {
        if (max <= 0 || value == null) return 0;
        return Math.min(1, Math.max(0, value / max));
    }

    _setMeterVisible(visible) {
        if (!this._meter || !this._hint) return;
        if (this._meter.visible === visible) return;
        this._meter.visible = visible;
        this._hint.visible = visible;
        if (visible) this._positionOverlay();
    }

    // --- Approval prompt (action-approval gate) ---
    //
    // After a confident face match for a non-login service, the daemon
    // broadcasts `approval_pending` with an `approval_id`; the prompt below
    // asks for an explicit Allow/Deny. The buttons disappear on their own
    // when the daemon's window expires (`approval_timeout_ms`) — the daemon
    // then broadcasts a failure event which clears this view.

    _showApproval(score, user, service, approvalId, approvalTimeoutMs, secure, userPresent) {
        if (!this._enabled || !this._overlay || !this._icon) return;
        this._showIndicator();
        this._cancelResultTimer();
        this._cancelHideTimer();
        this._pendingResult = null;
        this._state = 'approval_pending';
        this._stopAnimations();
        this._cancelOverlayAnimation();

        const svc = service || 'this application';
        const confidence = score != null ? `Match ${(score * 100).toFixed(0)}%` : 'Face recognized';

        // The daemon re-broadcasts approval_pending when the user steps in
        // or out of the frame (user_present flips). Keep the countdown and
        // the parked request untouched for the same approval id; only
        // update the presence state.
        if (this._approval && this._approval.id === approvalId) {
            this._approval.userPresent = userPresent !== false;
            this._updateApprovalButtons();
            this._positionOverlay();
            return;
        }

        this._icon.style_class = 'system-status-icon hiro-approval';
        // Buttons must be clickable, so the overlay becomes reactive while
        // the prompt is up.
        this._overlay.reactive = true;
        this._setMeterVisible(false);
        if (this._hint) this._hint.visible = false;

        this._showOverlay('Approve this action?', 'security-high-symbolic', 'hiro-approval');
        this._approvalTitle.text = `${svc} wants to authenticate as ${user || 'you'}`;
        this._approvalBox.visible = true;

        this._approval = {
            id: approvalId,
            user: user || '',
            service: svc,
            secure: !!secure,
            confidence,
            userPresent: userPresent !== false,
            timeoutMs: approvalTimeoutMs || 0,
            deadline: GLib.get_monotonic_time() + (approvalTimeoutMs || 0) * 1000,
        };
        this._updateApprovalButtons();
        this._startApprovalTimer();
        this._positionOverlay();
    }

    _updateApprovalButtons() {
        if (!this._approval || !this._approvalSub || !this._approvalButtons) return;
        const a = this._approval;
        if (a.secure) {
            // The decision happens on the secure console (approval.secure_
            // desktop): show a passive notice, not buttons.
            this._approvalButtons.visible = false;
            this._approvalSub.text = `${a.confidence} · decide on the secure console`;
        } else if (a.userPresent === false) {
            // The user stepped away: hide the buttons and invite them back.
            // The daemon keeps the window open and will re-show the prompt
            // when the face returns (or deny at the timeout).
            this._approvalButtons.visible = false;
            this._approvalSub.text = 'Step back in front of the camera to approve';
        } else {
            this._approvalButtons.visible = true;
            this._approvalSub.text = a.countdownText || a.confidence;
        }
    }

    _startApprovalTimer() {
        this._stopApprovalTimer();
        if (!this._approval || !this._approval.timeoutMs) return;
        this._approvalTimer = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 250, () => {
            if (!this._approval) {
                this._approvalTimer = null;
                return false;
            }
            const remaining = this._approval.deadline - GLib.get_monotonic_time();
            if (remaining <= 0) {
                this._approvalTimer = null;
                this._expireApproval();
                return false;
            }
            // get_monotonic_time() is microseconds, not milliseconds.
            const secs = Math.ceil(remaining / 1_000_000);
            if (!this._approval.secure && this._approval.userPresent !== false)
                this._approval.countdownText = `${this._approval.confidence} · ${secs}s to decide`;
            this._updateApprovalButtons();
            return true;
        });
    }

    _stopApprovalTimer() {
        if (this._approvalTimer) {
            GLib.source_remove(this._approvalTimer);
            this._approvalTimer = null;
        }
    }

    _expireApproval() {
        if (!this._approval) return;
        this._approvalButtons.visible = false;
        if (this._approvalSub)
            this._approvalSub.text = 'Decision window closed — request not approved';
        // The daemon broadcasts the terminal failure event shortly after.
    }

    _clearApproval() {
        this._stopApprovalTimer();
        this._approval = null;
        if (this._approvalBox) this._approvalBox.visible = false;
        if (this._overlay) this._overlay.reactive = false;
    }

    _decideApproval(allow) {
        const approval = this._approval;
        if (!approval || approval.id == null) return;
        // The buttons are hidden while the user is away or the decision is
        // on the secure console — nothing to click there.
        if (approval.secure || approval.userPresent === false) return;
        this._stopApprovalTimer();
        this._approvalButtons.visible = false;
        this._approvalSub.text = allow ? 'Allowing…' : 'Denying…';
        this._sendApprove(approval, allow);
    }

    // One-shot request to the daemon over a short-lived connection (the
    // watch stream is dedicated to state events). The daemon resolves the
    // parked request and broadcasts the terminal event.
    _sendApprove(approval, allow) {
        try {
            const client = new Gio.SocketClient({timeout: 2});
            const conn = client.connect(Gio.UnixSocketAddress.new(SOCKET), null);
            const req = JSON.stringify({
                v: 2,
                id: 0,
                op: 'approve',
                approval_id: approval.id,
                user: approval.user,
                allow,
            });
            conn.get_output_stream().write_all(new TextEncoder().encode(req + '\n'), null);
            conn.close(null);
        } catch (e) {
            console.log(`hiro-status: approve send error: ${e?.message}`);
            if (this._approvalSub)
                this._approvalSub.text = 'Could not reach the daemon';
        }
    }

    _isImmediateFailure(state, reason) {
        if (state !== 'failure') return false;
        const r = String(reason || '').toLowerCase();
        // Camera failures happen before/without a real scan (unavailable,
        // mismatched, unreadable frames), so the indicator must say so
        // immediately instead of flashing "Scanning your face" first.
        return r.includes('rate_limited') || r.includes('rate limited') ||
            r.includes('locked_out') || r.includes('locked out') ||
            r.includes('password_required') || r.includes('password required') ||
            r.includes('camera') || r.includes('no_luma');
    }

    _reasonLabel(reason) {
        const r = String(reason || '').toLowerCase();
        if (r.includes('approval_denied') || r.includes('approval denied'))
            return 'Approval denied';
        if (r.includes('approval_timeout') || r.includes('approval timed out'))
            return 'Approval timed out — try again';
        if (r.includes('rate_limited') || r.includes('rate limited'))
            return 'Rate limited — please wait a moment';
        if (r.includes('locked_out') || r.includes('locked out'))
            return 'Too many attempts — try again later';
        if (r.includes('password_required') || r.includes('password required'))
            return 'Enter your password first';
        if (r.includes('liveness_failed') || r.includes('liveness'))
            return 'Not enough movement — try again and move your head slightly';
        if (r.includes('no_face'))
            return 'No face detected';
        if (r.includes('face_too_small'))
            return 'Face too small — move closer to the camera';
        if (r.includes('blurry'))
            return 'Too blurry — hold still and let the camera focus';
        if (r.includes('static_scene'))
            return 'Not enough movement — move your head slightly';
        if (r.includes('duplicate_pose'))
            return 'Duplicate pose — turn your head a little';
        if (r.includes('no_luma'))
            return 'Camera frames unreadable';
        if (r.includes('no_templates') || r.includes('no template'))
            return 'No face enrolled yet';
        if (r.includes('template_limit'))
            return 'Template limit reached — remove some templates first';
        if (r.includes('camera_mismatch'))
            return 'Camera changed since enrollment';
        if (r.includes('camera'))
            return 'Camera unavailable';
        if (r.includes('no_such_user') || r.includes('no such user'))
            return 'User not found';
        if (r.includes('denied'))
            return 'Access denied';
        if (r.includes('no_match'))
            return 'Face not recognized';
        if (r === 'error' || r === '')
            return 'Something went wrong';
        return null;
    }

    _queueResult(state, score, reason, accepted, target, rejected) {
        // Rate-limited / locked-out / password-required / camera-failure
        // requests are rejected before any scan happens, so tell the user
        // immediately instead of faking a scan.
        if (this._isImmediateFailure(state, reason)) {
            this._cancelResultTimer();
            this._cancelHideTimer();
            this._stopAnimations();
            this._cancelOverlayAnimation();
            this._pendingResult = {state, score, reason, accepted, target, rejected};
            this._state = state;
            this._presentResult();
            return;
        }

        // A very fast camera match can otherwise replace the scan message
        // before it has rendered for long enough to be useful. Approval
        // results are exempt: the user just interacted with the prompt, so
        // show the outcome directly instead of flashing "Scanning".
        const wasApproving = this._state === 'approval_pending';
        if ((this._state !== 'scanning' || !this._scanStartedAt) && !wasApproving) {
            this._showIndicator();
            this._state = 'scanning';
            this._scanStartedAt = GLib.get_monotonic_time();
            this._cancelHideTimer();
            this._cancelOverlayAnimation();
            this._icon.style_class = this._enrolling
                ? 'system-status-icon hiro-enrolling'
                : 'system-status-icon hiro-scanning';
            this._startPulse();
            this._startDots();
            this._showOverlay(
                this._enrolling ? 'Enrolling your face' : 'Scanning your face',
                this._enrolling ? 'contact-new-symbolic' : 'camera-photo-symbolic',
                this._enrolling ? 'hiro-enrolling' : 'hiro-scanning',
                true);
        }

        this._pendingResult = {state, score, reason, accepted, target, rejected};
        this._cancelResultTimer();
        const elapsedMs = (GLib.get_monotonic_time() - this._scanStartedAt) / 1000;
        const waitMs = Math.ceil(Math.max(0, MIN_SCAN_MS - elapsedMs));
        if (waitMs === 0) {
            this._presentResult();
            return;
        }

        this._resultTimer = GLib.timeout_add(GLib.PRIORITY_DEFAULT, waitMs, () => {
            this._resultTimer = null;
            if (this._state !== 'scanning' || !this._pendingResult) return false;
            this._presentResult();
            return false;
        });
    }

    _presentResult() {
        const result = this._pendingResult;
        this._pendingResult = null;
        if (!result) return;

        this._showIndicator();
        this._state = result.state;
        this._stopAnimations();
        this._setMeterVisible(false);
        if (this._hint) this._hint.visible = false;
        const warn = this._isImmediateFailure(result.state, result.reason);
        this._icon.style_class =
            `system-status-icon ${result.state === 'success' ? 'hiro-ok' : (warn ? 'hiro-warn' : 'hiro-fail')}`;

        let text;
        let iconName;
        if (result.state === 'success') {
            if (this._enrolling) {
                const n = this._enrollCount(result);
                text = `✓ ${n} face template${n === 1 ? '' : 's'} enrolled`;
            } else {
                text = `✓  Verified${result.score ? ' (' + (result.score * 100).toFixed(0) + '%)' : ''}`;
            }
            iconName = 'object-select-symbolic';
        } else {
            const label = this._reasonLabel(result.reason);
            text = label || (this._enrolling ? 'Face enrollment failed' : 'Not recognized');
            iconName = 'dialog-error-symbolic';
        }
        const extraClass = result.state === 'success' ? 'hiro-ok' : (warn ? 'hiro-warn' : 'hiro-fail');
        this._transitionToResult(text, iconName, extraClass);
        this._hideSoon();
    }

    // Number of templates actually added, taken from the structured field
    // or (for older daemons) the `added=N` reason string.
    _enrollCount(result) {
        if (result.accepted != null) return result.accepted;
        const m = String(result.reason || '').match(/added=(\d+)/);
        if (m) return parseInt(m[1], 10);
        return 0;
    }

    _hideSoon() {
        this._cancelHideTimer();
        this._hideTimer = GLib.timeout_add(GLib.PRIORITY_DEFAULT, RESULT_MS, () => {
            this._hideTimer = null;
            if (this._state !== 'success' && this._state !== 'failure') return false;
            this._animateOverlayOut(() => {
                this._icon.style_class = 'system-status-icon';
                this._hideIndicator();
            });
            return false;
        });
    }

    _showOverlay(text, iconName, extraClass, animate = false) {
        this._label.text = text;
        const classes = String(extraClass || '');
        const isScanning = classes.includes('hiro-enrolling') || classes.includes('hiro-scanning');
        const faceState = isScanning
            ? (classes.includes('hiro-enrolling') ? 'enrolling' : 'scanning')
            : (classes.includes('hiro-ok') ? 'success'
                : (classes.includes('hiro-warn') ? 'warn'
                    : (classes.includes('hiro-fail') ? 'fail'
                        : (classes.includes('hiro-approval') ? 'approval' : 'idle'))));
        if (faceState === 'scanning' || faceState === 'enrolling') {
            if (this._faceState !== faceState) this._startFaceScan(faceState);
        } else {
            this._stopFaceScan();
            this._setFaceState(faceState);
        }
        this._overlay.style_class = 'hiro-status-overlay ' + (extraClass || '');
        this._overlay.visible = true;
        this._positionOverlay();
        if (animate) this._popIn();
    }

    _positionOverlay() {
        // uiGroup's layout does not center children, so place it explicitly
        // relative to the primary monitor, centered both ways.
        const [, natW] = this._overlay.get_preferred_width(-1);
        const [, natH] = this._overlay.get_preferred_height(-1);
        const mon = Main.layoutManager.primaryMonitor;
        const x = Math.round(mon.x + (mon.width - natW) / 2);
        const y = Math.round(mon.y + (mon.height - natH) / 2);
        this._overlay.set_position(x, y);
    }

    _transitionToResult(text, iconName, extraClass) {
        const token = ++this._animationToken;
        this._overlay.remove_all_transitions();
        if (!this._overlay.visible) {
            this._showOverlay(text, iconName, extraClass, false);
            this._popIn(token);
            return;
        }

        // Crossfade only the content row (face + label) instead of flashing
        // the whole card. The brand, meters, and chrome stay put, so a
        // scan -> result change reads as a smooth re-morph of the face
        // rather than a jarring card swap.
        this._box.remove_all_transitions();
        this._box.ease_property('opacity', 0, {
            duration: TRANSITION_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
            onComplete: () => {
                if (token !== this._animationToken) return;
                this._showOverlay(text, iconName, extraClass, false);
                this._box.opacity = 0;
                this._box.ease_property('opacity', 255, {
                    duration: POP_IN_MS,
                    mode: Clutter.AnimationMode.EASE_OUT_QUAD,
                });
                if (this._face) {
                    this._face.set_scale(0.92, 0.92);
                    this._face.ease_property('scale-x', 1, {
                        duration: POP_IN_MS,
                        mode: Clutter.AnimationMode.EASE_OUT_BACK,
                    });
                    this._face.ease_property('scale-y', 1, {
                        duration: POP_IN_MS,
                        mode: Clutter.AnimationMode.EASE_OUT_BACK,
                    });
                }
            },
        });
    }

    _popIn(token = ++this._animationToken) {
        this._overlay.remove_all_transitions();
        this._overlay.opacity = 0;
        this._overlay.set_scale(0.94, 0.94);
        this._overlay.ease_property('opacity', 255, {
            duration: POP_IN_MS,
            mode: Clutter.AnimationMode.EASE_OUT_QUAD,
        });
        this._overlay.ease_property('scale-x', 1.03, {
            duration: POP_IN_MS,
            mode: Clutter.AnimationMode.EASE_OUT_QUAD,
            onComplete: () => {
                if (token !== this._animationToken) return;
                this._overlay.ease_property('scale-x', 1, {
                    duration: POP_SETTLE_MS,
                    mode: Clutter.AnimationMode.EASE_IN_OUT_QUAD,
                });
                this._overlay.ease_property('scale-y', 1, {
                    duration: POP_SETTLE_MS,
                    mode: Clutter.AnimationMode.EASE_IN_OUT_QUAD,
                });
            },
        });
        this._overlay.ease_property('scale-y', 1.03, {
            duration: POP_IN_MS,
            mode: Clutter.AnimationMode.EASE_OUT_QUAD,
        });
    }

    _animateOverlayOut(onComplete = null) {
        if (!this._overlay || !this._overlay.visible) {
            if (onComplete) onComplete();
            return;
        }
        const token = ++this._animationToken;
        this._overlay.remove_all_transitions();
        this._overlay.ease_property('opacity', 0, {
            duration: HIDE_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
            onComplete: () => {
                if (token !== this._animationToken) return;
                this._overlay.hide();
                this._overlay.opacity = 255;
                this._overlay.set_scale(1, 1);
                if (onComplete) onComplete();
            },
        });
        this._overlay.ease_property('scale-x', 0.96, {
            duration: HIDE_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
        });
        this._overlay.ease_property('scale-y', 0.96, {
            duration: HIDE_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
        });
    }

    _cancelOverlayAnimation() {
        this._animationToken++;
        if (this._overlay) this._overlay.remove_all_transitions();
    }

    _startPulse() {
        this._stopPulse();
        const token = ++this._pulseToken;
        const pulse = () => {
            if (token !== this._pulseToken || this._state !== 'scanning' || !this._enabled) return;
            this._icon.ease_property('opacity', 90, {
                duration: 450,
                mode: Clutter.AnimationMode.EASE_OUT_QUAD,
                onComplete: () => {
                    if (token !== this._pulseToken || this._state !== 'scanning' || !this._enabled) return;
                    this._icon.ease_property('opacity', 255, {
                        duration: 450,
                        mode: Clutter.AnimationMode.EASE_IN_QUAD,
                        onComplete: () => {
                            if (token === this._pulseToken) pulse();
                        },
                    });
                },
            });
        };
        this._pulse = pulse;
        pulse();
    }

    _startDots() {
        this._stopDots();
        this._dots = 0;
        this._dotTimer = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 500, () => {
            this._dots = (this._dots + 1) % 4;
            if (this._state !== 'scanning') {
                this._dotTimer = null;
                return false;
            }
            this._updateScanLabel();
            return true;
        });
    }

    _stopAnimations() {
        this._stopPulse();
        this._stopDots();
        this._stopFaceScan();
    }

    _stopPulse() {
        this._pulseToken++;
        this._pulse = null;
        if (!this._icon) return;
        this._icon.remove_all_transitions();
        if (this._enabled) {
            this._icon.ease_property('opacity', 255, {
                duration: TRANSITION_MS,
                mode: Clutter.AnimationMode.EASE_OUT_QUAD,
            });
        } else {
            this._icon.opacity = 255;
        }
    }

    _stopDots() {
        if (this._dotTimer) {
            GLib.source_remove(this._dotTimer);
            this._dotTimer = null;
        }
    }

    _cancelResultTimer() {
        if (this._resultTimer) {
            GLib.source_remove(this._resultTimer);
            this._resultTimer = null;
        }
    }

    _cancelHideTimer() {
        if (this._hideTimer) {
            GLib.source_remove(this._hideTimer);
            this._hideTimer = null;
        }
    }
}
