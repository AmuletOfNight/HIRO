/* HIRO Face Auth Status - animated indicator for face scanning. */
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Clutter from 'gi://Clutter';
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
const METER_WIDTH = 150;

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
        this._lockChangedId = 0;
        this._connection = null;
        this._readLoop = null;

        // Top-bar indicator button.
        this._indicator = new PanelMenu.Button(0.0, 'HIRO face auth', true);
        this._icon = new St.Icon({
            icon_name: 'camera-photo-symbolic',
            style_class: 'system-status-icon',
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._indicator.add_child(this._icon);
        this._indicator.visible = true;
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
        this._overlay.set_translation(0, 18, 0);
        this._overlay.set_pivot_point(0.5, 0.5);
        this._column = new St.BoxLayout({style_class: 'hiro-status-column', vertical: true});
        this._box = new St.BoxLayout({style_class: 'hiro-status-box', vertical: false});
        this._boxIcon = new St.Icon({icon_name: 'camera-photo-symbolic', icon_size: 40});
        this._label = new St.Label({
            text: 'Scanning your face',
            style_class: 'hiro-status-label',
        });
        this._box.add_child(this._boxIcon);
        this._box.add_child(this._label);
        this._column.add_child(this._box);

        // Live liveness progress meter: one bar per anti-spoof signal
        // (temporal frame variance and landmark micro-motion), fed by the
        // daemon's scanning telemetry, plus an actionable hint.
        this._varianceFill = new St.Widget({
            style_class: 'hiro-meter-fill hiro-meter-fill-var',
            height: 6,
            width: 0,
            x_align: Clutter.ActorAlign.START,
        });
        this._motionFill = new St.Widget({
            style_class: 'hiro-meter-fill hiro-meter-fill-mot',
            height: 6,
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
        if (this._dotTimer) GLib.source_remove(this._dotTimer);
        if (this._retry) GLib.source_remove(this._retry);
        this._dotTimer = null;
        this._retry = null;
        this._cancelResultTimer();
        this._cancelHideTimer();
        if (this._connection) this._connection.close(null);
        this._connection = null;
        this._connected = false;
        if (this._overlay) this._overlay.destroy();
        if (this._indicator) this._indicator.destroy();
        this._overlay = null;
        this._indicator = null;
        this._icon = null;
    }

    _makeMeterRow(caption, fill) {
        const cap = new St.Label({text: caption, style_class: 'hiro-meter-caption'});
        cap.set_width(96);
        const track = new St.Bin({
            style_class: 'hiro-meter-track',
            width: METER_WIDTH,
            height: 6,
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

    _connect() {
        if (!this._enabled || this._connected) return;
        try {
            // Keep the client referenced too; GJS finalizers can otherwise
            // tear down the socket it produced.
            this._client = new Gio.SocketClient({timeout: 2});
            const addr = Gio.UnixSocketAddress.new(SOCKET);
            this._connection = this._client.connect(addr, null);
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
                                    ev.op, ev.accepted, ev.target, ev.rejected);
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
             op, accepted, target, rejected) {
        if (!this._enabled || !this._overlay || !this._icon) return;
        this._op = op === 'enroll' ? 'enroll' : 'verify';
        this._enrolling = this._op === 'enroll';
        console.log(`hiro-status: state=${state} op=${this._op} score=${score} reason=${reason} ` +
            `accepted=${accepted} target=${target} rejected=${rejected}`);
        if (state === 'scanning') {
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
                this._enrolling ? 'hiro-enrolling' : null,
                enteringScanning);
            if (this._enrolling) {
                // Enrollment has no liveness bars; show template progress
                // instead (live "n/target" count from the daemon).
                this._setMeterVisible(false);
                this._setEnrollProgress(accepted, target);
            } else {
                this._updateLiveness(variance, motion, minVariance, minMotion);
            }
        } else if (state === 'success') {
            this._queueResult(state, score, reason, accepted, target, rejected);
        } else if (state === 'failure') {
            this._queueResult(state, score, reason, accepted, target, rejected);
        } else {
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
                if (this._state === state) this._icon.style_class = 'system-status-icon';
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

    _isImmediateFailure(state, reason) {
        if (state !== 'failure') return false;
        const r = String(reason || '').toLowerCase();
        return r.includes('rate_limited') || r.includes('rate limited') ||
            r.includes('locked_out') || r.includes('locked out');
    }

    _reasonLabel(reason) {
        const r = String(reason || '').toLowerCase();
        if (r.includes('rate_limited') || r.includes('rate limited'))
            return 'Rate limited — please wait a moment';
        if (r.includes('locked_out') || r.includes('locked out'))
            return 'Too many attempts — try again later';
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
        // Rate-limited / locked-out requests are rejected before any scan
        // happens, so tell the user immediately instead of faking a scan.
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
        // before it has rendered for long enough to be useful.
        if (this._state !== 'scanning' || !this._scanStartedAt) {
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
                this._enrolling ? 'hiro-enrolling' : null,
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

        this._state = result.state;
        this._stopAnimations();
        this._setMeterVisible(false);
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
            });
            return false;
        });
    }

    _showOverlay(text, iconName, extraClass, animate = false) {
        this._label.text = text;
        this._boxIcon.icon_name = iconName;
        this._overlay.style_class = 'hiro-status-overlay ' + (extraClass || '');
        this._overlay.visible = true;
        this._positionOverlay();
        if (animate) this._popIn();
    }

    _positionOverlay() {
        // uiGroup's layout does not center children, so place it explicitly
        // relative to the primary monitor.
        const [, natW] = this._overlay.get_preferred_width(-1);
        const [, natH] = this._overlay.get_preferred_height(-1);
        const mon = Main.layoutManager.primaryMonitor;
        const x = Math.round(mon.x + (mon.width - natW) / 2);
        const y = Math.round(mon.y + 24);
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

        this._overlay.ease_property('opacity', 0, {
            duration: TRANSITION_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
            onComplete: () => {
                if (token !== this._animationToken) return;
                this._showOverlay(text, iconName, extraClass, false);
                this._overlay.opacity = 0;
                this._overlay.set_scale(0.94, 0.94);
                this._popIn(token);
            },
        });
        this._overlay.ease_property('scale-x', 0.96, {
            duration: TRANSITION_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
        });
        this._overlay.ease_property('scale-y', 0.96, {
            duration: TRANSITION_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
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
